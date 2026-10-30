"""Deterministic ACL compliance engine for Cisco IOS and Huawei VRP.

The LLM only translates the policy into test flows. Whether a flow is permitted or denied
is decided here, by first-match evaluation, with each vendor's default action:
- Cisco IOS: implicit "deny any" at the end of every ACL.
- Huawei VRP traffic-filter: packets matching no rule are PERMITTED by default.

Flows are evaluated as "from any source to any destination". A rule restricted to specific
addresses, source ports or extra conditions only covers part of that traffic, so it is not
treated as a match. This is conservative: a deny limited to one host does not make
"telnet is blocked" compliant.
"""

import re
from dataclasses import dataclass

from netops_copilot.models import Device, Finding, Flow, Vendor

SERVICES = {
    "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53, "dns": 53, "www": 80,
    "http": 80, "pop3": 110, "ntp": 123, "snmp": 161, "bgp": 179, "https": 443,
}
DEFAULT_ACTION = {Vendor.CISCO_IOS: "deny", Vendor.HUAWEI_VRP: "permit"}
DEFAULT_LABEL = {Vendor.CISCO_IOS: "implicit deny (end of Cisco ACL)",
                 Vendor.HUAWEI_VRP: "no rule matched: Huawei traffic-filter default permit"}


@dataclass
class Rule:
    text: str
    action: str
    protocol: str
    dst_ports: tuple[int, int] | None = None  # inclusive range, None = any port
    covers_any: bool = True                   # False if restricted to part of the traffic

    def matches(self, flow: Flow) -> bool:
        if not self.covers_any:
            return False
        if self.protocol != "ip" and self.protocol != flow.protocol:
            return False
        if self.dst_ports is None:
            return True
        return flow.dst_port is not None and self.dst_ports[0] <= flow.dst_port <= self.dst_ports[1]


def _port(token: str) -> int:
    return int(token) if token.isdigit() else SERVICES[token.lower()]


def _port_range(op: str, args: list[str]) -> tuple[int, int]:
    if op == "eq":
        p = _port(args[0])
        return (p, p)
    if op == "range":
        return (_port(args[0]), _port(args[1]))
    if op == "gt":
        return (_port(args[0]) + 1, 65535)
    if op == "lt":
        return (1, _port(args[0]) - 1)
    raise ValueError(op)  # "neq" and others: handled as partial coverage


def _parse_cisco_ace(text: str) -> Rule | None:
    tokens = re.sub(r"^\d+\s+", "", text.strip()).split()
    if not tokens or tokens[0] not in ("permit", "deny"):
        return None
    action, protocol, rest = tokens[0], tokens[1], tokens[2:]
    rule = Rule(text=text.strip(), action=action, protocol=protocol)
    i = 0
    for endpoint in ("src", "dst"):
        if i >= len(rest):
            rule.covers_any = False
            return rule
        if rest[i] == "any":
            i += 1
        else:  # "host x" or "addr wildcard": restricted
            rule.covers_any = False
            i += 2
        if i < len(rest) and rest[i] in ("eq", "range", "gt", "lt", "neq"):
            op = rest[i]
            n = 2 if op == "range" else 1
            args = rest[i + 1 : i + 1 + n]
            i += 1 + n
            if endpoint == "src":
                rule.covers_any = False
            else:
                try:
                    rule.dst_ports = _port_range(op, args)
                except (ValueError, KeyError):
                    rule.covers_any = False
    if any(t in ("established", "fragments") for t in rest[i:]):
        rule.covers_any = False
    return rule


def _parse_huawei_rule(text: str) -> Rule | None:
    m = re.match(r"^\s*rule(?:\s+\d+)?\s+(permit|deny)\s+(\S+)(.*)$", text)
    if not m:
        return None
    action, protocol, rest = m.group(1), m.group(2), m.group(3)
    rule = Rule(text=text.strip(), action=action, protocol=protocol)
    if re.search(r"\b(source|destination)\s+(?!any\b)\d", rest) or "source-port" in rest:
        rule.covers_any = False
    if pm := re.search(r"destination-port\s+(eq|range|gt|lt|neq)\s+(\S+)(?:\s+(\S+))?", rest):
        try:
            rule.dst_ports = _port_range(pm.group(1), [pm.group(2), pm.group(3) or ""])
        except (ValueError, KeyError):
            rule.covers_any = False
    return rule


def parse_acls(device: Device) -> dict[str, list[Rule]]:
    acls: dict[str, list[Rule]] = {}
    current: str | None = None
    for line in device.config.splitlines():
        if device.vendor == Vendor.CISCO_IOS:
            if m := re.match(r"^ip access-list (?:extended|standard) (\S+)", line):
                current = m.group(1)
                acls.setdefault(current, [])
                continue
            if m := re.match(r"^access-list (\S+) (.*)$", line):  # numbered ACL
                if rule := _parse_cisco_ace(m.group(2)):
                    acls.setdefault(m.group(1), []).append(rule)
                continue
            if current and line.startswith(" ") and (rule := _parse_cisco_ace(line)):
                acls[current].append(rule)
                continue
        else:
            if m := re.match(r"^acl (?:number (\d+)|name (\S+)(?: \d+)?)", line):
                current = m.group(1) or m.group(2)
                acls.setdefault(current, [])
                continue
            if current and line.startswith(" ") and (rule := _parse_huawei_rule(line)):
                acls[current].append(rule)
                continue
        if not line.startswith(" "):
            current = None
    return acls


def inbound_filters(device: Device) -> dict[str, str]:
    """{interface: acl applied inbound}."""
    result: dict[str, str] = {}
    interface: str | None = None
    pattern = (r"^\s+ip access-group (\S+) in\b" if device.vendor == Vendor.CISCO_IOS
               else r"^\s+traffic-filter inbound acl (?:name )?(\S+)")
    for line in device.config.splitlines():
        if m := re.match(r"^interface (\S+)", line):
            interface = m.group(1)
        elif interface and (m := re.match(pattern, line)):
            result[interface] = m.group(1)
        elif not line.startswith(" "):
            interface = None
    return result


def evaluate(flow: Flow, rules: list[Rule], vendor: Vendor) -> tuple[str, str]:
    for rule in rules:
        if rule.matches(flow):
            return rule.action, rule.text
    return DEFAULT_ACTION[vendor], DEFAULT_LABEL[vendor]


def audit(device: Device, flows: list[Flow]) -> list[Finding]:
    acls = parse_acls(device)
    filters = inbound_filters(device)
    findings: list[Finding] = []
    if device.edge is not None:
        # Explicit edge interfaces: each one is audited, filtered or not.
        for interface in device.edge:
            name = filters.get(interface)
            for flow in flows:
                if name is None:
                    actual, matched = "permit", "no inbound ACL on this interface"
                elif name not in acls:
                    actual, matched = "permit", f"ACL {name} applied but not defined: permits all"
                else:
                    actual, matched = evaluate(flow, acls[name], device.vendor)
                findings.append(Finding(device=device.hostname, interface=interface,
                                        acl=name or "(none)", flow=flow, actual=actual,
                                        matched=matched))
        return findings
    if not filters:
        return [Finding(device=device.hostname, interface="(all)", acl="(none)", flow=f,
                        actual="permit", matched="no inbound ACL applied on any interface")
                for f in flows]
    for interface, acl in filters.items():
        for flow in flows:
            if acl not in acls:
                actual, matched = "permit", f"ACL {acl} applied but not defined: permits all"
            else:
                actual, matched = evaluate(flow, acls[acl], device.vendor)
            findings.append(Finding(device=device.hostname, interface=interface, acl=acl,
                                    flow=flow, actual=actual, matched=matched))
    return findings
