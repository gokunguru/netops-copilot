"""Deterministic risk floor. The model explains the change, but it cannot rate it below this.

Seen on Muse Spark: a new inbound ACL bound to a core uplink described as "Risk: low". The
re-audit was green, but any new filter on an interface can cut traffic the probes do not cover,
so it is at least medium. On a live device, a filtering change is high.
"""

import re

from netops_copilot.audit import acl
from netops_copilot.lab import config_editor
from netops_copilot.models import Device, ProposedChange, Review, Risk

LEVELS = ("low", "medium", "high")
# Routing and redundancy protocols. Denying them can tear down adjacencies (the classic outage):
# whatever the checks say, such a change goes to a human. Seen in the benchmark: "block BGP on
# core" was proposed, re-audited, and approved by the reviewer because no BGP session existed yet.
CONTROL_PLANE = re.compile(
    r"\bdeny\s+(?:.*\beq\s+(179|bgp|520|rip|646|639|3784|3785)\b"
    r"|(ospf|eigrp|pim|vrrp|igmp|gre|89|88|103|112)\b)", re.IGNORECASE)
PROTOCOLS = {"179": "BGP", "bgp": "BGP", "520": "RIP", "rip": "RIP", "646": "LDP", "639": "MSDP",
             "3784": "BFD", "3785": "BFD", "ospf": "OSPF", "89": "OSPF", "eigrp": "EIGRP",
             "88": "EIGRP", "pim": "PIM", "103": "PIM", "vrrp": "VRRP", "112": "VRRP",
             "igmp": "IGMP", "gre": "GRE"}
ACL_HEADER = re.compile(r"^(ip access-list extended|acl (number|name))\b")
RISK_LINE = re.compile(r"^.*\brisk\b\s*(?:level)?\s*[:=-]\s*\**\s*(low|medium|high)\b.*$",
                       re.IGNORECASE | re.MULTILINE)
PROSE_RISK = re.compile(r"\b(low|medium|high)([- ]risk)\b", re.IGNORECASE)


def assess(changes: list[ProposedChange], devices: dict[str, Device]) -> Risk:
    found: list[tuple[int, str]] = []
    human = False

    def raise_to(n: int, reason: str) -> None:
        found.append((n, reason))

    for change in changes:
        device = devices[change.device]
        filtering = False
        try:
            candidate = config_editor.apply(change.vendor, device.config, change.commands)
        except config_editor.EditError:
            candidate = device.config  # not reached: the dry-run already validated the change
        before = acl.inbound_filters(device)
        after = acl.inbound_filters(device.model_copy(update={"config": candidate}))
        for iface in sorted(set(before) | set(after)):
            if before.get(iface) != after.get(iface):
                filtering = True
                verb = "bound to" if iface not in before else "changed on"
                raise_to(1, f"{change.device}: new inbound filter {verb} {iface}")
        if any(ACL_HEADER.match(c.strip()) for c in change.commands):
            filtering = True
            raise_to(1, f"{change.device}: filtering rules added")
        for command in change.commands:
            if m := CONTROL_PLANE.search(command.strip()):
                token = (m.group(1) or m.group(2) or "").lower()
                human = True
                raise_to(2, f"{change.device}: denies control-plane traffic "
                            f"({PROTOCOLS.get(token, token)}): '{command.strip()}', "
                            "a human must decide")
        if device.live:
            raise_to(2 if filtering else 1, f"{change.device}: live device"
                     + (", filtering change on the running config" if filtering else ""))
    if not found:
        return Risk(level="low", reasons=["additive change on lab devices"])
    found.sort(key=lambda f: (-f[0], "control-plane" not in f[1], "bound to" not in f[1]))
    return Risk(level=LEVELS[found[0][0]], reasons=[r for _, r in found], human=human)



def facts(risk: Risk) -> str:
    return (f"Deterministic risk floor: {risk.level.upper()} ({'; '.join(risk.reasons)}). "
            "State a risk level at least this high.")


def enforce(explanation: str, risk: Risk) -> str:
    """Raise the model's stated risk to the floor; add a risk line if it gave none."""
    floor = LEVELS.index(risk.level)
    note = f"Risk: {risk.level} (deterministic floor: {risk.reasons[0]})"
    match = RISK_LINE.search(explanation)
    if match is None:
        # Level written in prose ("a low-risk change"): raise it too, so the text never shows
        # two contradicting levels.
        lower = {m.group(1).lower() for m in PROSE_RISK.finditer(explanation)
                 if LEVELS.index(m.group(1).lower()) < floor}
        def raise_level(m: re.Match) -> str:
            if LEVELS.index(m.group(1).lower()) >= floor:
                return m.group(0)
            level = risk.level.capitalize() if m.group(1)[0].isupper() else risk.level
            return level + m.group(2)

        text = PROSE_RISK.sub(raise_level, explanation)
        if PROSE_RISK.search(explanation) and not lower:
            return explanation  # stated in prose, at or above the floor
        if lower:
            note = (f"Risk: {risk.level} (raised from {'/'.join(sorted(lower))} by the "
                    f"deterministic floor: {risk.reasons[0]})")
        return f"{text.rstrip()}\n{note}"
    stated = match.group(1).lower()
    if LEVELS.index(stated) >= floor:
        return explanation
    return (explanation[:match.start()]
            + f"Risk: {risk.level} (raised from {stated} by the deterministic floor: "
              f"{risk.reasons[0]})" + explanation[match.end():])


def with_review(risk: Risk, review: Review) -> Risk:
    """The reviewer can only raise the floor: its most severe concern becomes a reason."""
    worst = max((c for c in review.concerns), key=lambda c: LEVELS.index(c.severity),
                default=None)
    if worst is None or LEVELS.index(worst.severity) <= LEVELS.index(risk.level):
        return risk
    reason = f"independent reviewer: {(worst.device + ': ') if worst.device else ''}{worst.text}"
    return Risk(level=worst.severity, reasons=[reason, *risk.reasons], human=risk.human)
