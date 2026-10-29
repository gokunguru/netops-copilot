"""Deterministic safety gate. No LLM involved: same input, same verdict."""

import re

from netops_copilot.models import ChangeType, GateResult, Intent, ProposedChange, Verdict

# Commands that must never come out of the agent, whatever the request.
FORBIDDEN_PATTERNS = [
    r"^\s*(no|undo)\s+(router|interface|vlan\s+batch|ip\s+route)\b",
    r"^\s*(reload|reboot|erase|format|write\s+erase|reset\s+saved-configuration)\b",
    r"^\s*(no|undo)\s+(username|aaa|local-user)\b",
    r"^\s*shutdown\s*$",
]

# An ACL remediation may only add rules or bind an ACL: removing protection is never automatic.
REMEDIATION_FORBIDDEN = [
    r"^\s*no\s+\d+\s*$",
    r"^\s*undo\s+rule\b",
    r"^\s*(no|undo)\s+(ip\s+access-group|traffic-filter|ip\s+access-list|acl)\b",
]

MAX_COMMANDS_PER_DEVICE = 50

# VLAN 1 (default) and Cisco reserved range must never be touched by the agent.
PROTECTED_VLANS = {1, 1002, 1003, 1004, 1005}
VLAN_REF = re.compile(r"\bvlan\s+(?:batch\s+)?(\d+)", re.IGNORECASE)


def check(intent: Intent, changes: list[ProposedChange]) -> GateResult:
    violations: list[str] = []

    # 1. Blast radius: every touched device must be in the requested scope.
    out_of_scope = {c.device for c in changes} - set(intent.targets)
    if out_of_scope:
        violations.append(f"devices outside requested scope: {sorted(out_of_scope)}")

    forbidden = FORBIDDEN_PATTERNS
    if intent.change_type == ChangeType.ACL_REMEDIATE:
        forbidden = FORBIDDEN_PATTERNS + REMEDIATION_FORBIDDEN

    for change in changes:
        # 2. Size limit.
        if len(change.commands) > MAX_COMMANDS_PER_DEVICE:
            violations.append(
                f"{change.device}: {len(change.commands)} commands (max {MAX_COMMANDS_PER_DEVICE})"
            )
        # 3. Forbidden commands.
        for cmd in change.commands:
            for pattern in forbidden:
                if re.search(pattern, cmd, re.IGNORECASE):
                    violations.append(f"{change.device}: forbidden command '{cmd.strip()}'")
                    break
            # 4. VLAN ID sanity.
            for vid in (int(v) for v in VLAN_REF.findall(cmd)):
                if vid in PROTECTED_VLANS or not 2 <= vid <= 4094:
                    violations.append(f"{change.device}: protected or invalid VLAN {vid} in '{cmd.strip()}'")

    verdict = Verdict.REJECT if violations else Verdict.PASS
    return GateResult(verdict=verdict, violations=violations)
