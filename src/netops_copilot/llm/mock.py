"""Deterministic stand-in for Muse Spark, for offline demos and tests (--mock).
It only understands simple VLAN, ACL audit and ACL fix requests. The real agent runs on Meta Model API.
It cannot see pixels: for images it reads the expected reading stored in the PNG metadata of the
sample images (docs/examples). Muse Spark reads the image itself.
"""

import base64
import json
import re

from netops_copilot import vision
from netops_copilot.agent import prompts

# service keyword -> (protocol, port)
SERVICES = {
    "telnet": ("tcp", 23), "ssh": ("tcp", 22), "ftp": ("tcp", 21), "http": ("tcp", 80),
    "https": ("tcp", 443), "smb": ("tcp", 445), "rdp": ("tcp", 3389), "snmp": ("udp", 161),
    "dns": ("udp", 53), "icmp": ("icmp", None), "ping": ("icmp", None),
    "bgp": ("tcp", 179),
}


class MockLLM:
    def __init__(self, faulty_first_generation: bool = False) -> None:
        # When True, the first generation includes a forbidden command, to exercise the retry loop.
        self.faulty = faulty_first_generation
        self.calls: list[str] = []

    def chat(self, messages: list[dict], **kwargs) -> str:
        system, user = messages[0]["content"], messages[-1]["content"]
        if system == prompts.REVIEW_SYSTEM:  # tool budget spent: JSON verdict, no tools
            self.calls.append("review")
            return json.dumps({"verdict": "escalate", "summary": "Budget spent before a clear "
                               "conclusion.", "concerns": [{"severity": "medium", "text":
                               "not every changed interface could be checked"}]})
        if system == prompts.VISION_SYSTEM:
            self.calls.append("read")
            return self._read(user)
        if system == prompts.PARSE_SYSTEM:
            self.calls.append("parse")
            return self._parse(user)
        if system == prompts.GENERATE_ACL_FIX_SYSTEM:
            self.calls.append("generate")
            return self._generate_acl_fix(user)
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
        if '"acl_remediate"' in user:
            return ("Adds deny rules ahead of the rules that let the traffic through, and binds a "
                    "new inbound ACL where none existed. No rule or binding is removed; other "
                    "services keep their current behaviour (verified by the collateral check).\n"
                    "Risk: medium (filtering change on edge interfaces, validated by re-audit).")
        return ("Creates VLAN on the target devices only. Existing VLANs, interfaces and "
                "routing are untouched.\nRisk: low (additive change, no port reassignment).")

    # ---------- agent with tools: a short scripted investigation driven by the tool results ----------

    def complete(self, messages: list[dict], tools: list[dict], force: str | None = None) -> dict:
        if messages[0]["content"] == prompts.REVIEW_SYSTEM:
            self.calls.append("review")
            return self._review(messages)
        self.calls.append("agent")
        goal = messages[1]["content"].split("Operator: ", 1)[1]
        seen = [json.loads(m["content"]) for m in messages if m["role"] == "tool"
                and not m["content"].startswith("error")]
        change = re.search(r"\b(fix|add|create|make sure|ensure|remediate|enforce)\b", goal, re.IGNORECASE)
        if vlan := re.search(r"vlan\s+(\d+)", goal, re.IGNORECASE):
            return self._agent_vlan(goal, vlan.group(1), seen, bool(change))
        if services := [w for w in SERVICES if re.search(rf"\b{w}\b", goal, re.IGNORECASE)]:
            return self._agent_acl(goal, services, seen, bool(change))
        if re.search(r"interfaces?", goal, re.IGNORECASE):
            return self._agent_interfaces(seen)
        return _finish("The offline model can only investigate VLAN presence, ACL exposure of a "
                       "service and unfiltered interfaces. Run without --mock for Muse Spark.")

    @staticmethod
    def _review(messages: list[dict]) -> dict:
        """Escalates a new or changed inbound filter on an uplink, core or management link."""
        change = json.loads(re.search(r"^Change: (\[.*\])$", messages[1]["content"],
                                      re.MULTILINE).group(1))
        hosts = list(dict.fromkeys(c["device"] for c in change))
        seen = [json.loads(m["content"]) for m in messages if m["role"] == "tool"]
        if not seen:
            return _call(*[("list_interfaces", {"device": h, "state": state})
                           for h in hosts for state in ("running", "candidate")])
        concerns = []
        for i, host in enumerate(hosts):
            before = {x["interface"]: x for x in seen[2 * i]}
            for x in seen[2 * i + 1]:
                changed = before.get(x["interface"], {}).get("inbound_filter") != x["inbound_filter"]
                if changed and re.search(r"uplink|core|transit|mgmt|management",
                                         x["description"], re.IGNORECASE):
                    concerns.append({"severity": "medium", "device": host, "text": (
                        f"new inbound filter on {x['interface']} ({x['description']}): an uplink "
                        "carries routing adjacencies and management traffic; the final permit "
                        "keeps them, but confirm with the link owner before the window")})
        if concerns:
            return _call(("verdict", {"verdict": "escalate", "concerns": concerns,
                                      "summary": "Scope matches the request, but a critical "
                                                 "link is filtered for the first time."}))
        return _call(("verdict", {"verdict": "approve", "concerns": [],
                                  "summary": f"Scope matches the request ({', '.join(hosts)}); "
                                             "no uplink or management interface touched."}))

    @staticmethod
    def _agent_vlan(goal: str, vid: str, seen: list, change: bool) -> dict:
        if not seen:
            return _call(("list_vlans", {}))
        vlans = seen[-1]
        have = [h for h, v in vlans.items() if vid in v]
        missing = [h for h in vlans if h not in have]
        named = re.search(r"(?:named|name|called)\s+([A-Za-z0-9_-]+)", goal, re.IGNORECASE)
        name = named.group(1).upper() if named else next(
            (vlans[h][vid] for h in have if vlans[h][vid]), None)
        answer = (f"VLAN {vid}{f' ({name})' if name else ''} is configured on "
                  f"{', '.join(have) or 'no device'}; missing on {', '.join(missing) or 'none'}.")
        request = (f"Create VLAN {vid} named {name} on {', '.join(missing)}"
                   if change and missing and name else None)
        return _finish(answer, request)

    @staticmethod
    def _agent_acl(goal: str, services: list[str], seen: list, change: bool) -> dict:
        parsed = json.loads(MockLLM._parse_audit(goal, []))
        flows = parsed.get("params", {}).get("flows") or [
            {"label": s, "protocol": SERVICES[s][0], "dst_port": SERVICES[s][1],
             "expected": "permit" if s in ("https", "ssh", "dns") else "deny"} for s in services]
        if not seen:
            return _call(("list_devices", {}))
        if len(seen) == 1:
            return _call(("audit_acls", {"flows": flows}))
        bad = seen[-1]["non_compliant"]
        if not bad:
            return _finish(f"All {seen[-1]['checks']} checks pass: {', '.join(services)} already "
                           "handled as expected on every edge interface.")
        devices = sorted({f["device"] for f in bad}, key=[d["hostname"] for d in seen[0]].index)
        answer = "; ".join(f"{f['flow']} {f['actual']} on {f['device']} {f['interface']} "
                           f"({f['decided_by']})" for f in bad)
        policy = ", ".join(f"{f['label']} must be {'blocked' if f['expected'] == 'deny' else 'allowed'}"
                           for f in flows)
        return _finish(f"Exposed: {answer}.",
                       f"Fix the edge ACLs on {', '.join(devices)}: {policy}" if change else None)

    @staticmethod
    def _agent_interfaces(seen: list) -> dict:
        if not seen:
            return _call(("list_devices", {}))
        if len(seen) == 1:  # one call per device, in parallel
            return _call(*[("list_interfaces", {"device": d["hostname"]}) for d in seen[0]])
        hosts = [d["hostname"] for d in seen[0]]
        open_ = [f"{h} {i['interface']}" for h, ifaces in zip(hosts, seen[1:], strict=False)
                 for i in ifaces if i["edge"] is not False and not i["inbound_filter"]]
        return _finish("Interfaces with no inbound ACL: " + (", ".join(open_) or "none") + ".")

    @staticmethod
    def _read(content: list[dict]) -> str:
        for part in content:
            if part["type"] != "image_url":
                continue
            data = base64.b64decode(part["image_url"]["url"].split(",", 1)[1])
            meta = vision.png_text(data) if data.startswith(b"\x89PNG") else {}
            if vision.DEMO_KEY in meta:
                return json.dumps({"request": meta[vision.DEMO_KEY],
                                   "seen": meta.get("netops:seen", "A sample image."),
                                   "confidence": meta.get("netops:confidence", "high")})
        return json.dumps({"error": "the offline model only reads the sample images in "
                                    "docs/examples (run without --mock to let Muse Spark read it)"})

    @staticmethod
    def _parse(user: str) -> str:
        inventory = re.findall(r"^- (\S+) \(", user, re.MULTILINE)
        request = user.split("Request:", 1)[1]
        if re.search(r"\b(audit|compliance|compliant|acls?)\b", request, re.IGNORECASE):
            parsed = json.loads(MockLLM._parse_audit(request, inventory))
            if "error" not in parsed and re.search(
                    r"\b(fix|remediate|enforce|correct)\b", request, re.IGNORECASE):
                parsed["change_type"] = "acl_remediate"
                parsed["summary"] = parsed["summary"].replace("Audit", "Fix")
            return json.dumps(parsed)
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

    def _generate_acl_fix(self, user: str) -> str:
        ctx = json.loads(re.search(r"^Context: (\{.*\})$", user, re.MULTILINE).group(1))
        config = user.split("Current configuration:\n", 1)[1]
        cisco = ctx["vendor"] == "cisco_ios"
        retry = "previous attempt was rejected" in user

        def rule(v):
            proto, port, action = v["protocol"], v["dst_port"], v["expected"]
            if cisco:
                return f"{action} {proto} any any" + (f" eq {port}" if port else "")
            return f"{action} {proto}" + (f" destination-port eq {port}" if port else "")

        used = {int(n) for n in re.findall(r"^\s+(?:rule\s+)?(\d+)\s", config, re.MULTILINE)}
        free = (n for n in range(1, 10000) if n not in used)
        commands, done = [], set()
        for v in ctx["violations"]:
            if v["acl"] == "(none)":
                continue
            if v["acl"] not in done:
                done.add(v["acl"])
                commands.append(f"ip access-list extended {v['acl']}" if cisco
                                else f"acl number {v['acl']}")
                for same in (x for x in ctx["violations"] if x["acl"] == v["acl"]):
                    entry = rule(same)
                    line = f" {next(free)} {entry}" if cisco else f" rule {next(free)} {entry}"
                    if line not in commands:
                        commands.append(line)
        unfiltered = [v for v in ctx["violations"] if v["acl"] == "(none)"]
        if unfiltered:
            name = "NETOPS-EDGE-IN" if cisco else "3990"
            commands.append(f"ip access-list extended {name}" if cisco else f"acl number {name}")
            seen = []
            for v in unfiltered:
                if rule(v) not in seen:
                    seen.append(rule(v))
            for i, entry in enumerate(seen, start=1):
                commands.append(f" {i * 10} {entry}" if cisco else f" rule {i * 5} {entry}")
            # Faulty model: forgets that a Cisco ACL ends with an implicit deny.
            if cisco and not (self.faulty and not retry):
                commands.append(" 1000 permit ip any any")
            for iface in ctx["interfaces_to_fix"]:
                commands += [f"interface {iface}", f" ip access-group {name} in" if cisco
                             else f" traffic-filter inbound acl {name}"]
        return json.dumps({"commands": commands})


def _call(*calls: tuple[str, dict]) -> dict:
    return {"role": "assistant", "content": None, "tool_calls": [
        {"id": f"call_{name}_{i}", "type": "function",
         "function": {"name": name, "arguments": json.dumps(args)}}
        for i, (name, args) in enumerate(calls)]}


def _finish(answer: str, request: str | None = None) -> dict:
    return _call(("finish", {"answer": answer, "request": request}))
