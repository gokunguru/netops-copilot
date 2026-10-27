"""Deterministic stand-in for Muse Spark, for offline demos and tests (--mock).
It only understands simple VLAN requests. The real agent runs on Meta Model API.
"""

import json
import re

from netops_copilot.agent import prompts


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
        self.calls.append("explain")
        return ("Creates VLAN on the target devices only. Existing VLANs, interfaces and "
                "routing are untouched.\nRisk: low (additive change, no port reassignment).")

    @staticmethod
    def _parse(user: str) -> str:
        inventory = re.findall(r"^- (\S+) \(", user, re.MULTILINE)
        request = user.split("Request:", 1)[1]
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

    def _generate(self, user: str) -> str:
        intent = json.loads(re.search(r"Intent: (\{.*\})", user).group(1))
        vid, name = intent["params"]["vlan_id"], intent["params"]["name"]
        commands = [f"vlan {vid}", f" name {name}"]
        if self.faulty and "previous attempt was rejected" not in user:
            vendor = re.search(r"Vendor: (\S+)", user).group(1)
            commands.append("no vlan 20" if vendor == "cisco_ios" else "undo vlan 20")
        return json.dumps({"commands": commands})
