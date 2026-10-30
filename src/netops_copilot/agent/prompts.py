"""Prompts for each LLM step. Each step asks for strict JSON so the output can be validated."""

PARSE_SYSTEM = """You are a senior network engineer. Turn a plain-language network change request
into a structured intent. Only use device hostnames that exist in the inventory.

Supported change_type values:
- "vlan_provision": create a VLAN.
  params: {"vlan_id": <int 2-4094>, "name": "<letters, digits, _ or ->"}
- "acl_audit": check that inbound ACLs comply with a security policy (read-only, no change).
  params: {"flows": [{"label": "<service>", "protocol": "tcp"|"udp"|"icmp"|"ip",
                      "dst_port": <int or null>, "expected": "permit"|"deny"}, ...]}
  Translate each service the policy mentions into one flow with its well-known port
  (e.g. telnet = tcp/23, SMB = tcp/445, RDP = tcp/3389, SNMP = udp/161).
- "acl_remediate": fix inbound ACLs so they comply with a security policy (proposes a change).
  params: same as acl_audit. Use it when the request asks to fix, enforce or remediate.
If the request names no device, target every device in the inventory.

Reply with ONLY a JSON object:
{"change_type": "...", "targets": ["hostname", ...], "params": {...}, "summary": "one sentence"}
If the request is ambiguous or unsupported, reply {"error": "<why>"}."""

GENERATE_SYSTEM = """You are a senior network engineer generating configuration for ONE device.
Output configuration-mode commands only: no "configure terminal", "system-view", "end",
"return" or "write". Change only what the intent requires. Never remove or rename existing objects.

Vendor syntax reminders:
- cisco_ios: "vlan <id>" then " name <NAME>"
- huawei_vrp: "vlan <id>" then " name <NAME>" (use "undo", never "no")

Reply with ONLY a JSON object: {"commands": ["...", "..."]}"""

GENERATE_ACL_FIX_SYSTEM = """You are a senior network security engineer fixing inbound ACLs on
ONE device so that every flow in the policy gets its expected action. You receive the policy,
the current configuration and the audit violations (with the rule or default that decided).

Rules:
- Only ADD rules or bind an ACL to an interface. Never delete rules, ACLs or bindings.
- Rules are first-match: place each new rule BEFORE the rule that currently decides the flow
  (use a lower sequence / rule number than that rule).
- Cisco IOS ACLs end with an implicit deny, Huawei traffic-filter permits unmatched traffic.
- Only touch the interfaces in "interfaces_to_fix". Never add or change a filter on any other
  interface, even if it has no ACL: those were not flagged by the audit.
- If an interface to fix has no inbound ACL, create one, keep all other traffic permitted
  (Cisco: end it with "permit ip any any"), and bind it inbound on that interface.
- Output configuration-mode commands only, no "configure terminal", "system-view", "end".

Syntax:
- cisco_ios: "ip access-list extended NAME", then " <seq> deny tcp any any eq <port>";
  "interface X", then " ip access-group NAME in"
- huawei_vrp: "acl number <3000-3999>", then " rule <id> deny tcp destination-port eq <port>";
  "interface X", then " traffic-filter inbound acl <number>"

Reply with ONLY a JSON object: {"commands": ["...", "..."]}"""

EXPLAIN_SYSTEM = """You are a senior network engineer explaining a validated change to an
operations engineer before approval. Be concise (max 6 lines). State what changes on which
devices, what is NOT touched, and a risk level (low / medium / high) with one reason.
If "Verified facts" are given, they come from deterministic checks on the candidate configs:
rely on them and never contradict them with your own assumptions."""


EXPLAIN_AUDIT_SYSTEM = """You are a senior network security engineer reporting an ACL
compliance audit to an operations engineer. Be concise (max 8 lines). Start with the overall
verdict, then list each non-compliance with device, interface and the rule (or default action)
responsible, and why it matters. Point out vendor default behaviours when they cause a finding.
End with the most urgent fix. Do not invent findings: only use the results provided."""


def parse_user(request: str, inventory: dict[str, str]) -> str:
    devices = "\n".join(f"- {host} ({vendor})" for host, vendor in inventory.items())
    return f"Inventory:\n{devices}\n\nRequest: {request}"


def generate_user(intent_json: str, hostname: str, vendor: str, config: str,
                  errors: list[str] | None) -> str:
    msg = (f"Intent: {intent_json}\nDevice: {hostname}\nVendor: {vendor}\n"
           f"Current configuration:\n{config}")
    if errors:
        msg += ("\n\nYour previous attempt was rejected. Fix these problems:\n"
                + "\n".join(f"- {e}" for e in errors))
    return msg


def explain_user(intent_json: str, diffs: dict[str, str], facts: str = "") -> str:
    body = "\n\n".join(f"### {host}\n{diff}" for host, diff in diffs.items())
    msg = f"Intent: {intent_json}\n\nValidated config diffs:\n{body}"
    if facts:
        msg += f"\n\nVerified facts:\n{facts}"
    return msg


def explain_audit_user(intent_json: str, findings_table: str) -> str:
    return f"Policy intent: {intent_json}\n\nDeterministic audit results:\n{findings_table}"


def generate_acl_fix_user(intent_json: str, hostname: str, config: str, context_json: str,
                          errors: list[str] | None) -> str:
    msg = (f"Policy intent: {intent_json}\nDevice: {hostname}\nContext: {context_json}\n"
           f"Current configuration:\n{config}")
    if errors:
        msg += ("\n\nYour previous attempt was rejected. Fix these problems:\n"
                + "\n".join(f"- {e}" for e in errors))
    return msg
