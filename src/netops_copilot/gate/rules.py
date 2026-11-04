"""Safety gate: plain rules over the proposed commands, evaluated without any model.

The same intent and the same commands always get the same verdict. Each rule returns the
violations it finds; the gate passes only when none of them finds anything.
"""

import re
from collections.abc import Callable, Iterator

from netops_copilot.models import ChangeType, GateResult, Intent, ProposedChange, Verdict

Rule = Callable[[Intent, list[ProposedChange]], Iterator[str]]


def _patterns(*regexes: str) -> list[re.Pattern[str]]:
    return [re.compile(r, re.IGNORECASE) for r in regexes]


# Never acceptable from the agent, whatever was asked: removing routing, interfaces, VLAN batches
# or static routes, rebooting or wiping a device, deleting accounts, shutting a port down.
ALWAYS_FORBIDDEN = _patterns(
    r"^\s*(?:no|undo)\s+(?:router|interface|ip\s+route|vlan\s+batch)\b",  # topology
    r"^\s*(?:reload|reboot)\b",  # restart
    r"^\s*(?:erase|format|write\s+erase|reset\s+saved-configuration)\b",  # wipe
    r"^\s*(?:no|undo)\s+(?:aaa|username|local-user)\b",  # accounts
    r"^\s*shutdown\s*$",  # port down
)

# During an ACL fix the agent may only add rules or bind a filter. Taking protection away
# (deleting a rule, an ACL or a binding) is always left to a human.
FORBIDDEN_WHILE_FIXING_ACLS = _patterns(
    r"^\s*no\s+\d+\s*$",
    r"^\s*undo\s+rule\b",
    r"^\s*(no|undo)\s+(ip\s+access-group|traffic-filter|ip\s+access-list|acl)\b",
)

COMMAND_BUDGET = 50  # per device: a larger change is not a ticket-sized change

# Default VLAN and the Cisco reserved range are off limits; valid VLAN ids are 2..4094.
RESERVED_VLANS = frozenset({1, 1002, 1003, 1004, 1005})
VLAN_ID = re.compile(r"\bvlan\s+(?:batch\s+)?(\d+)", re.IGNORECASE)


def scope(intent: Intent, changes: list[ProposedChange]) -> Iterator[str]:
    """Blast radius: nothing may touch a device the request did not name."""
    extra = sorted({c.device for c in changes} - set(intent.targets))
    if extra:
        yield f"devices outside requested scope: {extra}"


def budget(intent: Intent, changes: list[ProposedChange]) -> Iterator[str]:
    for c in changes:
        if len(c.commands) > COMMAND_BUDGET:
            yield f"{c.device}: {len(c.commands)} commands (max {COMMAND_BUDGET})"


def forbidden(intent: Intent, changes: list[ProposedChange]) -> Iterator[str]:
    banned = ALWAYS_FORBIDDEN
    if intent.change_type == ChangeType.ACL_REMEDIATE:
        banned = ALWAYS_FORBIDDEN + FORBIDDEN_WHILE_FIXING_ACLS
    for c in changes:
        for line in c.commands:
            if any(p.search(line) for p in banned):
                yield f"{c.device}: forbidden command '{line.strip()}'"


def vlans(intent: Intent, changes: list[ProposedChange]) -> Iterator[str]:
    for c in changes:
        for line in c.commands:
            for vid in map(int, VLAN_ID.findall(line)):
                if vid in RESERVED_VLANS or not 2 <= vid <= 4094:
                    yield f"{c.device}: protected or invalid VLAN {vid} in '{line.strip()}'"


RULES: tuple[Rule, ...] = (scope, budget, forbidden, vlans)


def check(intent: Intent, proposed: list[ProposedChange]) -> GateResult:
    found = [v for rule in RULES for v in rule(intent, proposed)]
    return GateResult(verdict=Verdict.REJECT if found else Verdict.PASS, violations=found)
