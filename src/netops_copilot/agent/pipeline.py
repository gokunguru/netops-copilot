"""Agent pipeline: parse -> generate -> gate -> dry-run -> (retry) -> explain."""

import json
from collections.abc import Callable
from pathlib import Path

import yaml
from pydantic import ValidationError

from netops_copilot import gate
from netops_copilot.agent import prompts
from netops_copilot.audit import acl, remediation
from netops_copilot.lab import simulator
from netops_copilot.llm.client import LLM, extract_json
from netops_copilot.models import (
    AclAuditParams,
    Attempt,
    ChangeType,
    Device,
    Intent,
    ProposedChange,
    RunResult,
    Step,
    VlanParams,
)


def load_inventory(path: str | Path) -> dict[str, Device]:
    path = Path(path)
    data = yaml.safe_load(path.read_text())
    return {
        host: Device(hostname=host, vendor=d["vendor"],
                     config=(path.parent / d["config"]).read_text())
        for host, d in data["devices"].items()
    }


def parse_intent(llm: LLM, request: str, devices: dict[str, Device]) -> Intent:
    inventory = {h: d.vendor.value for h, d in devices.items()}
    reply = llm.chat([
        {"role": "system", "content": prompts.PARSE_SYSTEM},
        {"role": "user", "content": prompts.parse_user(request, inventory)},
    ])
    data = extract_json(reply)
    if "error" in data:
        raise ValueError(f"request not understood: {data['error']}")
    intent = Intent(**data)
    unknown = set(intent.targets) - set(devices)
    if unknown:
        raise ValueError(f"unknown devices in intent: {sorted(unknown)}")
    if intent.change_type == ChangeType.VLAN_PROVISION:
        VlanParams(**intent.params)  # validates id range and name format
    elif intent.change_type in (ChangeType.ACL_AUDIT, ChangeType.ACL_REMEDIATE):
        AclAuditParams(**intent.params)  # validates protocols, ports, expected actions
    else:
        raise ValueError(f"change type '{intent.change_type.value}' not supported yet")
    return intent


def generate_changes(llm: LLM, intent: Intent, devices: dict[str, Device],
                     errors: list[str] | None = None) -> list[ProposedChange]:
    intent_json = intent.model_dump_json()
    changes = []
    for host in intent.targets:
        device = devices[host]
        own_errors = [e for e in (errors or []) if e.startswith(f"{host}:") or ":" not in e]
        reply = llm.chat([
            {"role": "system", "content": prompts.GENERATE_SYSTEM},
            {"role": "user", "content": prompts.generate_user(
                intent_json, host, device.vendor.value, device.config, own_errors)},
        ])
        commands = extract_json(reply)["commands"]
        changes.append(ProposedChange(device=host, vendor=device.vendor, commands=commands))
    return changes


def explain(llm: LLM, intent: Intent, diffs: dict[str, str]) -> str:
    return llm.chat([
        {"role": "system", "content": prompts.EXPLAIN_SYSTEM},
        {"role": "user", "content": prompts.explain_user(intent.model_dump_json(), diffs)},
    ]).strip()


def findings_table(findings) -> str:
    return "\n".join(
        f"{'OK  ' if f.compliant else 'FAIL'} {f.device} {f.interface} acl={f.acl} "
        f"{f.flow.label} ({f.flow.protocol}/{f.flow.dst_port or 'any'}): expected "
        f"{f.flow.expected}, actual {f.actual} <- {f.matched}"
        for f in findings
    )


OnStep = Callable[[Step], None]


def _noop(_: Step) -> None:
    pass


def run_audit(llm: LLM, result: RunResult, devices: dict[str, Device],
              on_step: OnStep = _noop) -> RunResult:
    """Read-only path: deterministic evaluation, then the model explains the findings."""
    flows = AclAuditParams(**result.intent.params).flows
    for host in result.intent.targets:
        result.findings.extend(acl.audit(devices[host], flows))
    failed = sum(not f.compliant for f in result.findings)
    on_step(Step(name="audit", ok=failed == 0,
                 detail=f"{len(result.findings)} checks, {failed} non-compliant"))
    result.explanation = llm.chat([
        {"role": "system", "content": prompts.EXPLAIN_AUDIT_SYSTEM},
        {"role": "user", "content": prompts.explain_audit_user(
            result.intent.model_dump_json(), findings_table(result.findings))},
    ]).strip()
    on_step(Step(name="explain", ok=True))
    return result


def generate_acl_fixes(llm: LLM, intent: Intent, devices: dict[str, Device], targets: list[str],
                       findings, errors: list[str] | None = None) -> list[ProposedChange]:
    intent_json = intent.model_dump_json()
    changes = []
    for host in targets:
        device = devices[host]
        own_errors = [e for e in (errors or []) if e.startswith(f"{host}:") or ":" not in e]
        reply = llm.chat([
            {"role": "system", "content": prompts.GENERATE_ACL_FIX_SYSTEM},
            {"role": "user", "content": prompts.generate_acl_fix_user(
                intent_json, host, device.config, remediation.context(device, findings),
                own_errors)},
        ])
        commands = extract_json(reply)["commands"]
        changes.append(ProposedChange(device=host, vendor=device.vendor, commands=commands))
    return changes


ParseErrors = (ValueError, ValidationError, json.JSONDecodeError, KeyError, TypeError)


def _change_loop(llm: LLM, result: RunResult, gate_intent: Intent, max_retries: int,
                 on_step: OnStep, generate: Callable, dry_run: Callable) -> RunResult:
    """generate -> deterministic gate -> deterministic dry-run, retrying with the errors."""
    errors: list[str] = []
    for n in range(1, max_retries + 1):
        try:
            changes = generate(errors)
        except ParseErrors as exc:
            errors = [f"invalid generation output: {exc}"]
            on_step(Step(name="generate", ok=False, attempt=n, detail=errors[0]))
            continue
        on_step(Step(name="generate", ok=True, attempt=n, detail="; ".join(
            f"{c.device}: " + " | ".join(x.strip() for x in c.commands) for c in changes)))
        verdict = gate.check(gate_intent, changes)
        attempt = Attempt(number=n, changes=changes, gate=verdict)
        on_step(Step(name="gate", ok=not verdict.violations, attempt=n,
                     detail="; ".join(verdict.violations) or "PASS"))
        if verdict.violations:
            errors = verdict.violations  # deterministic gate failed: skip dry-run
        else:
            attempt.dry_run_errors, diffs = dry_run(changes)
            errors = attempt.dry_run_errors
            on_step(Step(name="dry_run", ok=not errors, attempt=n,
                         detail="; ".join(errors) or "all post-checks passed"))
        result.attempts.append(attempt)
        if attempt.ok:
            result.diffs = diffs
            result.explanation = explain(llm, result.intent, diffs)
            on_step(Step(name="explain", ok=True))
            return result

    result.error = f"no valid change after {max_retries} attempts"
    return result


def run_remediation(llm: LLM, result: RunResult, devices: dict[str, Device], max_retries: int,
                    on_step: OnStep) -> RunResult:
    """Audit, then fix only the non-compliant devices, proving each fix by re-auditing it."""
    flows = AclAuditParams(**result.intent.params).flows
    for host in result.intent.targets:
        result.findings.extend(acl.audit(devices[host], flows))
    failing = [h for h in result.intent.targets
               if any(f.device == h and not f.compliant for f in result.findings)]
    on_step(Step(name="audit", ok=not failing, detail=(
        f"{sum(not f.compliant for f in result.findings)} non-compliant, to fix on: "
        f"{', '.join(failing)}" if failing else "already compliant, nothing to fix")))
    if not failing:
        result.explanation = "Every device already complies with the policy: no change needed."
        return result
    # The gate's blast radius is narrowed to the devices that actually need a fix.
    gate_intent = result.intent.model_copy(update={"targets": failing})
    return _change_loop(
        llm, result, gate_intent, max_retries, on_step,
        generate=lambda errors: generate_acl_fixes(
            llm, result.intent, devices, failing, result.findings, errors),
        dry_run=lambda changes: remediation.dry_run(flows, changes, devices),
    )


def run(llm: LLM, request: str, devices: dict[str, Device], max_retries: int = 3,
        on_step: OnStep = _noop) -> RunResult:
    """Full pipeline. Never pushes anything: returns a result for human approval.

    on_step is called after every step, so a UI can show progress live.
    """
    result = RunResult(request=request)
    try:
        result.intent = parse_intent(llm, request, devices)
    except ParseErrors as exc:
        result.error = f"parse step failed: {exc}"
        on_step(Step(name="parse", ok=False, detail=str(exc)))
        return result
    on_step(Step(name="parse", ok=True, detail=result.intent.summary))
    if result.intent.change_type == ChangeType.ACL_AUDIT:
        return run_audit(llm, result, devices, on_step)
    if result.intent.change_type == ChangeType.ACL_REMEDIATE:
        return run_remediation(llm, result, devices, max_retries, on_step)
    return _change_loop(
        llm, result, result.intent, max_retries, on_step,
        generate=lambda errors: generate_changes(llm, result.intent, devices, errors),
        dry_run=lambda changes: simulator.dry_run(result.intent, changes, devices),
    )
