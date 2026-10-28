"""Deterministic stand-in for Muse Spark, for offline demos and tests (--mock).
It only understands simple VLAN and ACL audit requests. The real agent runs on Meta Model API.
"""

import json
import re

from netops_copilot.agent import prompts

# service keyword -> (protocol, port)
SERVICES = {
    "telnet": ("tcp", 23), "ssh": ("tcp", 22), "ftp": ("tcp", 21), "http": ("tcp", 80),
    "https": ("tcp", 443), "smb": ("tcp", 445), "rdp": ("tcp", 3389), "snmp": ("udp", 161),
    "dns": ("udp", 53), "icmp": ("icmp", None), "ping": ("icmp", None),
}


class MockLLM:
    def __init__(self, faulty_first_generation: bool = False) -> None:
        # When True, the first generation includes a forbidden command, to exercise the retry loop.
        self.faulty = faulty_first_generation
        self.calls: list[str] = []

    def chat(self, messages: list[dict], **kwargs) -> str:
        system, user = messages[0]["content"], messages[-1]["content"]
        if system == prompts.PARSE_SYSTEM:
            self.calls.append("parse")
            return self._parse(user)
        if system == prompts.GENERATE_SYSTEM:
            self.calls.append("generate")
            return self._generate(user)
        if system == prompts.EXPLAIN_AUDIT_SYSTEM:
            self.calls.append("explain")
            fails = [line for line in user.splitlines() if line.startswith("FAIL")]
            if not fails:
                return "Compliant: every flow matches the policy on every audited interface."
            return (f"Non-compliant: {len(fails)} finding(s).\n" + "\n".join(
                "- " + line[5:] for line in fails))
        self.calls.append("explain")
        return ("Creates VLAN on the target devices only. Existing VLANs, interfaces and "
                "routing are untouched.\nRisk: low (additive change, no port reassignment).")

    @staticmethod
    def _parse(user: str) -> str:
        inventory = re.findall(r"^- (\S+) \(", user, re.MULTILINE)
        request = user.split("Request:", 1)[1]
        if re.search(r"\b(audit|compliance|compliant|acls?)\b", request, re.IGNORECASE):
            return MockLLM._parse_audit(request, inventory)
        vid = re.search(r"vlan\s+(\d+)", request, re.IGNORECASE)
        name = re.search(r"(?:named|name|called)\s+([A-Za-z0-9_-]+)", request, re.IGNORECASE)
        targets = [h for h in inventory if re.search(rf"\b{re.escape(h)}\b", request)]
        if not (vid and name and targets):
            return json.dumps({"error": "need a VLAN id, a name and at least one known device"})
        return json.dumps({
            "change_type": "vlan_provision",
            "targets": targets,
            "params": {"vlan_id": int(vid.group(1)), "name": name.group(1).upper()},
            "summary": f"Create VLAN {vid.group(1)} on {', '.join(targets)}",
        })

    @staticmethod
    def _parse_audit(request: str, inventory: list[str]) -> str:
        targets = [h for h in inventory if re.search(rf"\b{re.escape(h)}\b", request)] or inventory
        verbs = {"block": "deny", "blocked": "deny", "deny": "deny", "denied": "deny",
                 "forbid": "deny", "forbidden": "deny",
                 "allow": "permit", "allowed": "permit", "permit": "permit", "permitted": "permit"}
        flows, last = [], None
        # Per clause: a service takes the first verb after it ("telnet must be blocked"),
        # otherwise the last verb before it ("block telnet").
        for clause in re.split(r"[,;.:()]", request.lower()):
            words = re.findall(r"[a-z]+", clause)
            for i, word in enumerate(words):
                if word in verbs:
                    last = verbs[word]
                elif word in SERVICES:
                    after = next((verbs[w] for w in words[i + 1:] if w in verbs), None)
                    expected = after or last
                    if expected:
                        proto, port = SERVICES[word]
                        flows.append({"label": word, "protocol": proto, "dst_port": port,
                                      "expected": expected})
        if not flows:
            return json.dumps({"error": "no service with a permit/deny expectation found"})
        return json.dumps({"change_type": "acl_audit", "targets": targets,
                           "params": {"flows": flows},
                           "summary": f"Audit inbound ACLs on {', '.join(targets)}"})

    def _generate(self, user: str) -> str:
        intent = json.loads(re.search(r"Intent: (\{.*\})", user).group(1))
        vid, name = intent["params"]["vlan_id"], intent["params"]["name"]
        commands = [f"vlan {vid}", f" name {name}"]
        if self.faulty and "previous attempt was rejected" not in user:
            vendor = re.search(r"Vendor: (\S+)", user).group(1)
            commands.append("no vlan 20" if vendor == "cisco_ios" else "undo vlan 20")
        return json.dumps({"commands": commands})
