"""Agent pipeline: parse -> generate -> gate -> dry-run -> (retry) -> explain."""

import json
from collections.abc import Callable
from pathlib import Path

import yaml
from pydantic import ValidationError

from netops_copilot import gate, policy, risk, vision
from netops_copilot.agent import prompts
from netops_copilot.agent import review as reviewer
from netops_copilot.agent.investigate import investigate
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
    Reading,
    RunResult,
    Step,
    VlanParams,
)


def load_inventory(path: str | Path, store=None, live: bool = True) -> dict[str, Device]:
    """Devices from the inventory.

    Lab devices: config file, overridden by approved changes kept in the lab state.
    Live devices (with a `driver`): running config fetched over SSH (skipped if live=False).
    """
    from netops_copilot import drivers

    path = Path(path)
    data = yaml.safe_load(path.read_text())
    devices = {}
    for host, d in data["devices"].items():
        device = Device(hostname=host, vendor=d["vendor"], config="", edge=d.get("edge"),
                        protected=d.get("protected", []), driver=d.get("driver"))
        if device.live:
            if not device.edge:
                raise ValueError(f"{host}: a live device must list its edge interfaces "
                                 "(the agent never guesses which interfaces it may filter)")
            config = drivers.fetch_config(device) if live else ""
        else:
            config = (store and store.config(host)) or (path.parent / d["config"]).read_text()
        devices[host] = device.model_copy(update={"config": config})
    return devices


def read_images(llm: LLM, images: list[vision.Image], note: str,
                devices: dict[str, Device]) -> Reading:
    """Muse Spark reads the images and writes a plain-language request (nothing else)."""
    vision.check_count(images)
    inventory = {h: d.vendor.value for h, d in devices.items()}
    reply = llm.chat([
        {"role": "system", "content": prompts.VISION_SYSTEM},
        {"role": "user", "content": vision.content(prompts.vision_user(note, inventory), images)},
    ])
    data = extract_json(reply)
    if "error" in data:
        raise ValueError(f"no change request found in the image: {data['error']}")
    reading = Reading(**data, images=[i.name for i in images])
    if reading.confidence == "low":
        raise ValueError(f"image hard to read, nothing was planned. Read as: \"{reading.request}\". "
                         "Type the request to confirm it, or attach a clearer image")
    return reading


def parse_intent(llm: LLM, request: str, devices: dict[str, Device]) -> Intent:
    inventory = {h: d.vendor.value for h, d in devices.items()}
    reply = llm.chat([
        {"role": "system", "content": prompts.PARSE_SYSTEM},
        {"role": "user", "content": prompts.parse_user(request, inventory)},
    ])
    data = extract_json(reply)
    if "error" in data:
        raise ValueError(f"request not understood: {data['error']}")
    return validate_intent(Intent(**data), devices)


def validate_intent(intent: Intent, devices: dict[str, Device]) -> Intent:
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


def explain(llm: LLM, intent: Intent, diffs: dict[str, str], facts: str = "") -> str:
    return llm.chat([
        {"role": "system", "content": prompts.EXPLAIN_SYSTEM},
        {"role": "user", "content": prompts.explain_user(intent.model_dump_json(), diffs, facts)},
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
                 on_step: OnStep, generate: Callable, dry_run: Callable,
                 devices: dict[str, Device], facts: Callable | None = None,
                 review: "bool | LLM" = True) -> RunResult:
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
            regressions = policy_regressions(changes, devices)
            on_step(Step(name="policy", ok=not regressions,
                         detail="; ".join(regressions) or "no versioned policy regresses"))
            if regressions:
                # Not retried: the request itself contradicts a reviewed policy, so the fix is a
                # policy change (a pull request), not another generation.
                result.error = ("contradicts a versioned policy: " + "; ".join(regressions)
                                + ". Change the policy first (reviewed pull request).")
                return result
            result.risk = risk.assess(changes, devices)
            checked = facts(changes) if facts else VLAN_FACTS
            failing = [f for f in result.findings if not f.compliant]
            if failing:  # why each device is in scope: the audit before the fix
                checked += "\nAudit before the fix, non-compliant: " + "; ".join(
                    f"{f.device} {f.interface} {f.flow.label} expected {f.flow.expected}, "
                    f"actual {f.actual} ({f.matched})" for f in failing)
            if review:
                operator = (result.investigation.goal if result.investigation
                            else result.request)
                review_llm = llm if review is True else review  # another model, if given
                result.review = reviewer.review(review_llm, operator,
                                                result.intent.model_dump_json(),
                                                changes, diffs, devices, on_step,
                                                facts=f"{checked}\n{VENDOR_SEMANTICS}")
                on_step(Step(name="review", ok=not result.review.escalated, detail=(
                    f"{result.review.verdict}: {result.review.summary}"
                    + "".join(f" [{c.severity}] {c.device + ': ' if c.device else ''}{c.text}"
                              for c in result.review.concerns))))
                result.risk = risk.with_review(result.risk, result.review)
            verified = "\n".join(filter(None, [facts(changes) if facts else "",
                                               risk.facts(result.risk),
                                               reviewer_facts(result.review)]))
            result.explanation = risk.enforce(explain(llm, result.intent, diffs, verified),
                                              result.risk)
            on_step(Step(name="explain", ok=True, detail=f"risk floor: {result.risk.level}"))
            return result

    result.error = f"no valid change after {max_retries} attempts"
    return result


def policy_regressions(changes: list[ProposedChange], devices: dict[str, Device]) -> list[str]:
    """Checks that were compliant before the change and would not be after it."""
    try:
        policies = policy.load(policy.DEFAULT_DIR)
    except policy.PolicyError:
        return []  # no policy directory (e.g. an installed package without policies/)
    candidate = reviewer.candidate(changes, devices)
    found = []
    for p in policies:
        try:
            before, after = policy.check(p, devices), policy.check(p, candidate)
        except policy.PolicyError:
            continue  # policy scoped to devices outside this inventory
        compliant = {(r.device, r.subject) for r in before.rows if r.compliant}
        found += [f"{r.device} {r.subject}: {p.name} requires {r.expected}, the change makes it "
                  f"{r.actual}" for r in after.failed if (r.device, r.subject) in compliant]
    return found


VLAN_FACTS = ("Dry-run post-checks passed on the config model: the requested VLANs exist with "
              "the requested names, no existing VLAN was removed or renamed, no other device "
              "or interface changed.")
VENDOR_SEMANTICS = (
    "Vendor semantics (deterministic, already applied by the checks): a Cisco IOS ACL ends with "
    "an implicit deny; a Huawei VRP traffic-filter permits packets that match no rule; a rule "
    "with no source or destination address (Huawei 'rule N deny tcp destination-port eq 23', "
    "Cisco 'any') matches every address; 'permit ip any any' permits every protocol, HTTPS and "
    "OSPF included.")


def reviewer_facts(review) -> str:
    if review is None:
        return ""
    concerns = "; ".join(f"[{c.severity}] {c.text}" for c in review.concerns) or "none"
    return (f"Independent reviewer verdict: {review.verdict.upper()} ({review.summary}). "
            f"Concerns: {concerns}. Mention escalated concerns.")


def run_remediation(llm: LLM, result: RunResult, devices: dict[str, Device], max_retries: int,
                    on_step: OnStep, review: "bool | LLM" = True) -> RunResult:
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
        dry_run=lambda changes: remediation.dry_run(flows, changes, devices, result.findings),
        devices=devices, review=review,
        facts=lambda changes: remediation.verified_facts(flows, changes, devices),
    )


def run(llm: LLM, request: str, devices: dict[str, Device], max_retries: int = 3,
        on_step: OnStep = _noop, images: list[vision.Image] | None = None,
        agent: bool = False, intent: Intent | None = None, policy: str | None = None,
        review: "bool | LLM" = True) -> RunResult:
    """Full pipeline. Never pushes anything: returns a result for human approval.

    on_step is called after every step, so a UI can show progress live.
    With images, the model first reads them into a plain-language request (the `read` step);
    `request` is then an optional operator note. The reading goes through the same checks.
    With agent=True, the model first investigates with read-only tools; it either answers, or
    hands over one change request that then goes through the same checks.
    review: True (same model, separate session), another LLM (independent weights too), or False.
    With intent (from a versioned policy), the parse step is skipped: the intent is already
    structured and reviewed. It is still validated, then goes through the same checks.
    """
    result = RunResult(request=request, policy=policy)
    if intent is not None:
        try:
            result.intent = validate_intent(intent, devices)
        except ParseErrors as exc:
            result.error = f"policy intent invalid: {exc}"
            on_step(Step(name="parse", ok=False, detail=str(exc)))
            return result
        on_step(Step(name="parse", ok=True, detail=f"{intent.summary} (from policy, no model)"))
        return _dispatch(llm, result, devices, max_retries, on_step, review)
    if images:
        try:
            result.reading = read_images(llm, images, request, devices)
        except (*ParseErrors, vision.ImageError) as exc:
            result.error = f"read step failed: {exc}"
            on_step(Step(name="read", ok=False, detail=str(exc)))
            return result
        on_step(Step(name="read", ok=True, detail=result.reading.request))
        result.request = result.reading.request + (f" (operator note: {request})" if request else "")
    if agent:
        try:
            result.investigation = investigate(llm, result.request, devices, on_step)
        except ParseErrors as exc:
            result.error = f"investigation failed: {exc}"
            on_step(Step(name="investigate", ok=False, detail=str(exc)))
            return result
        on_step(Step(name="investigate", ok=True, detail=result.investigation.request
                     or "answered, no change needed"))
        if result.investigation.request is None:
            return result
        result.request = result.investigation.request
    try:
        result.intent = parse_intent(llm, result.request, devices)
    except ParseErrors as exc:
        result.error = f"parse step failed: {exc}"
        on_step(Step(name="parse", ok=False, detail=str(exc)))
        return result
    on_step(Step(name="parse", ok=True, detail=result.intent.summary))
    return _dispatch(llm, result, devices, max_retries, on_step, review)


def _dispatch(llm: LLM, result: RunResult, devices: dict[str, Device], max_retries: int,
              on_step: OnStep, review: "bool | LLM" = True) -> RunResult:
    if result.intent.change_type == ChangeType.ACL_AUDIT:
        return run_audit(llm, result, devices, on_step)
    if result.intent.change_type == ChangeType.ACL_REMEDIATE:
        return run_remediation(llm, result, devices, max_retries, on_step, review)
    return _change_loop(
        llm, result, result.intent, max_retries, on_step,
        generate=lambda errors: generate_changes(llm, result.intent, devices, errors),
        dry_run=lambda changes: simulator.dry_run(result.intent, changes, devices),
        devices=devices, review=review,
    )
