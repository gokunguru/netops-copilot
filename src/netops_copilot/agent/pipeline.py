"""Agent pipeline: parse -> generate -> gate -> dry-run -> (retry) -> explain."""

import json
from pathlib import Path

import yaml
from pydantic import ValidationError

from netops_copilot import gate
from netops_copilot.agent import prompts
from netops_copilot.audit import acl
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
    elif intent.change_type == ChangeType.ACL_AUDIT:
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


def run_audit(llm: LLM, result: RunResult, devices: dict[str, Device]) -> RunResult:
    """Read-only path: deterministic evaluation, then the model explains the findings."""
    flows = AclAuditParams(**result.intent.params).flows
    for host in result.intent.targets:
        result.findings.extend(acl.audit(devices[host], flows))
    result.explanation = llm.chat([
        {"role": "system", "content": prompts.EXPLAIN_AUDIT_SYSTEM},
        {"role": "user", "content": prompts.explain_audit_user(
            result.intent.model_dump_json(), findings_table(result.findings))},
    ]).strip()
    return result


def run(llm: LLM, request: str, devices: dict[str, Device], max_retries: int = 3) -> RunResult:
    """Full pipeline. Never pushes anything: returns a result for human approval."""
    result = RunResult(request=request)
    try:
        result.intent = parse_intent(llm, request, devices)
    except (ValueError, ValidationError, json.JSONDecodeError, KeyError) as exc:
        result.error = f"parse step failed: {exc}"
        return result
    if result.intent.change_type == ChangeType.ACL_AUDIT:
        return run_audit(llm, result, devices)

    errors: list[str] = []
    for n in range(1, max_retries + 1):
        try:
            changes = generate_changes(llm, result.intent, devices, errors)
        except (ValueError, ValidationError, json.JSONDecodeError, KeyError) as exc:
            errors = [f"invalid generation output: {exc}"]
            continue
        verdict = gate.check(result.intent, changes)
        attempt = Attempt(number=n, changes=changes, gate=verdict)
        if verdict.violations:
            errors = verdict.violations  # deterministic gate failed: skip dry-run
        else:
            attempt.dry_run_errors, diffs = simulator.dry_run(result.intent, changes, devices)
            errors = attempt.dry_run_errors
        result.attempts.append(attempt)
        if attempt.ok:
            result.diffs = diffs
            result.explanation = explain(llm, result.intent, diffs)
            return result

    result.error = f"no valid change after {max_retries} attempts"
    return result
