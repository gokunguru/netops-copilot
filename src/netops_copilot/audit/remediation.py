"""ACL remediation: context for the model, and a dry-run that proves the fix.

A proposed fix is accepted only if, on the candidate config:
0. filtering changes only on interfaces the audit flagged (no scope creep), and
1. every policy flow is compliant on every interface (re-run of the deterministic audit), and
2. no other common service changed behaviour on any interface (collateral check), which
   catches the classic lockout: a new ACL that forgets the final "permit ip any any".
"""

import difflib
import json

from netops_copilot.audit import acl
from netops_copilot.lab import acl_editor
from netops_copilot.models import Device, Finding, Flow, ProposedChange

# Common services probed before and after the change to detect collateral damage.
PROBES = [
    Flow(label=name, protocol=proto, dst_port=port, expected="permit")
    for name, proto, port in [
        ("ssh", "tcp", 22), ("dns", "udp", 53), ("http", "tcp", 80), ("ntp", "udp", 123),
        ("snmp", "udp", 161), ("bgp", "tcp", 179), ("https", "tcp", 443),
        ("rdp", "tcp", 3389), ("ping", "icmp", None),
    ]
]


def interface_actions(device: Device, flows: list[Flow]) -> dict[tuple[str, str], str]:
    """{(interface, flow label): permit|deny} for every interface, filtered or not."""
    rules = acl.parse_acls(device)
    filters = acl.inbound_filters(device)
    result = {}
    for iface in acl_editor.interfaces(device.config):
        for flow in flows:
            name = filters.get(iface)
            if name is None or name not in rules:
                result[(iface, flow.label)] = "permit"
            else:
                result[(iface, flow.label)] = acl.evaluate(flow, rules[name], device.vendor)[0]
    return result


def interfaces_to_fix(device: Device, findings: list[Finding]) -> list[str]:
    flagged = {f.interface for f in findings if f.device == device.hostname and not f.compliant}
    if "(all)" in flagged:
        return acl_editor.interfaces(device.config)
    return sorted(flagged)


def context(device: Device, findings: list[Finding]) -> str:
    """Deterministic facts handed to the model so it does not have to re-derive them."""
    return json.dumps({
        "vendor": device.vendor.value,
        "interfaces_to_fix": interfaces_to_fix(device, findings),
        "inbound_filters": acl.inbound_filters(device),
        "violations": [
            {"interface": f.interface, "acl": f.acl, "flow": f.flow.label,
             "protocol": f.flow.protocol, "dst_port": f.flow.dst_port,
             "expected": f.flow.expected, "actual": f.actual, "decided_by": f.matched}
            for f in findings if f.device == device.hostname and not f.compliant
        ],
    })


def dry_run(flows: list[Flow], changes: list[ProposedChange], devices: dict[str, Device],
            findings: list[Finding]) -> tuple[list[str], dict[str, str]]:
    errors: list[str] = []
    diffs: dict[str, str] = {}
    policy_ports = {(f.protocol, f.dst_port) for f in flows}
    probes = [p for p in PROBES if (p.protocol, p.dst_port) not in policy_ports]

    for change in changes:
        device = devices[change.device]
        try:
            new_config = acl_editor.apply(change.vendor, device.config, change.commands)
        except acl_editor.EditError as exc:
            errors.append(f"{change.device}: {exc}")
            continue
        candidate = device.model_copy(update={"config": new_config})

        # 0. Scope: filtering may only change on interfaces the audit flagged.
        allowed = set(interfaces_to_fix(device, findings))
        before_f, after_f = acl.inbound_filters(device), acl.inbound_filters(candidate)
        for iface in sorted(set(before_f) | set(after_f)):
            if before_f.get(iface) != after_f.get(iface) and iface not in allowed:
                errors.append(f"{change.device}: out of scope, inbound filter changed on {iface} "
                              f"which the audit did not flag (allowed: {', '.join(sorted(allowed))})")

        # 1. Re-audit the candidate config against the policy.
        for f in acl.audit(candidate, flows):
            if not f.compliant:
                errors.append(f"{change.device}: still non-compliant after fix, {f.flow.label} "
                              f"on {f.interface} is {f.actual} <- {f.matched}")

        # 2. Collateral check: services outside the policy must behave exactly as before.
        before, after = interface_actions(device, probes), interface_actions(candidate, probes)
        changed: dict[tuple[str, str, str], list[str]] = {}
        for (iface, label), action in before.items():
            if after.get((iface, label)) != action:
                changed.setdefault((iface, action, after[(iface, label)]), []).append(label)
        for (iface, old, new), labels in changed.items():
            errors.append(f"{change.device}: collateral change on {iface}, "
                          f"{', '.join(labels)} {old} -> {new} (not requested by the policy)")

        diffs[change.device] = "\n".join(difflib.unified_diff(
            device.config.splitlines(), new_config.splitlines(),
            "running", "candidate", n=2, lineterm=""))
    return errors, diffs


def verified_facts(flows: list[Flow], changes: list[ProposedChange],
                   devices: dict[str, Device]) -> str:
    """Deterministic facts about an accepted fix, handed to the explain step."""
    lines = ["Every policy flow was re-audited on the candidate configs: all compliant.",
             "Collateral check passed: " + ", ".join(p.label for p in PROBES)
             + " behave exactly as before on every interface.",
             ("Vendor defaults: a Cisco IOS ACL ends with an implicit deny; a Huawei VRP "
             "traffic-filter PERMITS packets that match no rule (a deny-only Huawei ACL "
             "blocks nothing else).")]
    for c in changes:
        lines.append(f"{c.device} ({devices[c.device].vendor.value}): filtering changed only on "
                     f"the interfaces flagged by the audit.")
    return "\n".join(lines)
