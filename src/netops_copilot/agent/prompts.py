"""Prompts for each LLM step. Each step asks for strict JSON so the output can be validated."""

PARSE_SYSTEM = """You are a senior network engineer. Turn a plain-language network change request
into a structured intent. Only use device hostnames that exist in the inventory.

Supported change_type values: "vlan_provision".
For vlan_provision, params must be {"vlan_id": <int 2-4094>, "name": "<letters, digits, _ or ->"}.

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

EXPLAIN_SYSTEM = """You are a senior network engineer explaining a validated change to an
operations engineer before approval. Be concise (max 6 lines). State what changes on which
devices, what is NOT touched, and a risk level (low / medium / high) with one reason."""


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


def explain_user(intent_json: str, diffs: dict[str, str]) -> str:
    body = "\n\n".join(f"### {host}\n{diff}" for host, diff in diffs.items())
    return f"Intent: {intent_json}\n\nValidated config diffs:\n{body}"
