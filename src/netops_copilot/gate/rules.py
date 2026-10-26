"""Deterministic safety gate. No LLM involved: same input, same verdict."""

import re

from netops_copilot.models import GateResult, Intent, ProposedChange, Verdict

# Commands that must never come out of the agent, whatever the request.
FORBIDDEN_PATTERNS = [
    r"^\s*(no|undo)\s+(router|interface|vlan\s+batch|ip\s+route)\b",
    r"^\s*(reload|reboot|erase|format|write\s+erase|reset\s+saved-configuration)\b",
    r"^\s*(no|undo)\s+(username|aaa|local-user)\b",
    r"^\s*shutdown\s*$",
]

MAX_COMMANDS_PER_DEVICE = 50


def check(intent: Intent, changes: list[ProposedChange]) -> GateResult:
    violations: list[str] = []

    # 1. Blast radius: every touched device must be in the requested scope.
    out_of_scope = {c.device for c in changes} - set(intent.targets)
    if out_of_scope:
        violations.append(f"devices outside requested scope: {sorted(out_of_scope)}")

    for change in changes:
        # 2. Size limit.
        if len(change.commands) > MAX_COMMANDS_PER_DEVICE:
            violations.append(
                f"{change.device}: {len(change.commands)} commands (max {MAX_COMMANDS_PER_DEVICE})"
            )
        # 3. Forbidden commands.
        for cmd in change.commands:
            for pattern in FORBIDDEN_PATTERNS:
                if re.search(pattern, cmd, re.IGNORECASE):
                    violations.append(f"{change.device}: forbidden command '{cmd.strip()}'")
                    break

    verdict = Verdict.REJECT if violations else Verdict.PASS
    return GateResult(verdict=verdict, violations=violations)
