"""Agent with tools: read-only investigation, then the usual checks on whatever it asks for."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netops_copilot import cli, drivers
from netops_copilot.agent import tools
from netops_copilot.agent.investigate import investigate
from netops_copilot.agent.pipeline import load_inventory, run
from netops_copilot.llm import client as client_mod
from netops_copilot.llm.client import MetaClient
from netops_copilot.llm.mock import MockLLM, _call, _finish
from netops_copilot.web.app import create_app

INVENTORY = Path(__file__).resolve().parents[1] / "lab" / "inventory.yml"
TELNET = "Is telnet reachable from outside anywhere? Fix it where it is."


@pytest.fixture
def devices():
    return load_inventory(INVENTORY)


class Scripted:
    """Replays assistant messages in order and records what the agent sent back."""

    def __init__(self, *replies):
        self.replies, self.seen = list(replies), []

    def complete(self, messages, tools, force=None):
        self.seen.append(messages[-1])
        return self.replies.pop(0)

    def chat(self, messages, **kwargs):
        return MockLLM().chat(messages, **kwargs)


# ---------- tools ----------

def test_tool_specs_are_openai_functions():
    specs = tools.specs()
    names = [s["function"]["name"] for s in specs]
    assert names == [*tools.TOOLS, "finish"]
    assert all(s["type"] == "function" and s["function"]["parameters"]["type"] == "object"
               for s in specs)
    assert not any(n.startswith(("apply", "push", "set", "write")) for n in names)  # read-only


def test_tools_read_the_snapshot(devices):
    assert "acl number 3000" in tools.call("show_config", {"device": "site-b", "section": "acl"},
                                           devices)
    assert "interface" not in tools.call("show_config", {"device": "site-b", "section": "acl"},
                                         devices)
    assert tools.call("show_config", {"device": "core"}, devices) == devices["core"].config
    vlans = json.loads(tools.call("list_vlans", {}, devices))
    assert vlans["core"] == {"10": "MGMT"} and vlans["site-b"]["20"] == "VOICE"
    ifaces = json.loads(tools.call("list_interfaces", {"device": "site-a"}, devices))
    assert ifaces[0] == {"interface": "GigabitEthernet0/0", "description": "WAN",
                         "inbound_filter": "EDGE-IN", "edge": None, "protected": False}
    audit = json.loads(tools.call("audit_acls", {"flows": [
        {"label": "telnet", "protocol": "tcp", "dst_port": 23, "expected": "deny"}],
        "devices": ["site-a"]}, devices))
    assert audit["non_compliant"] == []


@pytest.mark.parametrize(("name", "args", "error"), [
    ("show_config", {"device": "site-z"}, "unknown device 'site-z'"),
    ("show_config", {"device": "core", "section": "router bgp"}, "no top-level block"),
    ("list_interfaces", {}, "invalid arguments for list_interfaces"),
    ("audit_acls", {"flows": []}, "invalid arguments for audit_acls"),
    ("push_config", {}, "unknown tool 'push_config'"),
])
def test_tool_errors_are_messages_for_the_model(devices, name, args, error):
    with pytest.raises(tools.ToolError, match=error):
        tools.call(name, args, devices)


def test_long_output_is_truncated(devices, monkeypatch):
    monkeypatch.setattr(tools, "MAX_OUTPUT", 50)
    assert tools.call("show_config", {"device": "site-a"}, devices).endswith("... (truncated)")


def test_tools_never_open_an_ssh_session(devices, monkeypatch):
    def no_ssh(device):
        raise AssertionError("tools must read the snapshot")
    monkeypatch.setattr(drivers, "connect", no_ssh)
    for name, args in [("list_devices", {}), ("list_vlans", {}),
                       ("list_interfaces", {"device": "core"})]:
        tools.call(name, args, devices)


# ---------- loop ----------

def test_errors_go_back_to_the_model_which_recovers(devices):
    llm = Scripted(
        _call(("show_config", {"device": "site-z"})),
        {"tool_calls": [{"id": "x", "function": {"name": "list_vlans", "arguments": "{oops"}}]},
        _call(("finish", {"request": "no answer"})),
        _finish("core lacks VLAN 20", "Create VLAN 20 named VOICE on core"))
    steps = []
    result = investigate(llm, "goal", devices, steps.append)
    assert [c.ok for c in result.calls] == [False, False, False]
    assert llm.seen[1]["content"].startswith("error: unknown device 'site-z'")
    assert llm.seen[2]["role"] == "tool" and llm.seen[3]["content"].startswith("error: invalid finish")
    assert result.request == "Create VLAN 20 named VOICE on core"
    assert steps[0].name == "tool" and not steps[0].ok


def test_tool_budget_is_enforced(devices):
    llm = Scripted(*[_call(("list_vlans", {}))] * 20)
    with pytest.raises(ValueError, match="did not conclude within 2 tool calls"):
        investigate(llm, "goal", devices, lambda s: None, max_calls=2)
    assert "tool budget exhausted" in llm.seen[-1]["content"]


def test_plain_text_reply_is_an_answer(devices):
    llm = Scripted({"content": "All good."}, {"content": "All good, really."})
    result = investigate(llm, "g", devices, lambda s: None)
    assert result.answer == "All good, really." and result.request is None
    assert "Call the `finish` tool now" in llm.seen[1]["content"]  # asked once, then accepted
    with pytest.raises(ValueError, match="neither a tool call nor an answer"):
        investigate(Scripted({"content": None}, {"content": ""}), "g", devices, lambda s: None)


def test_prose_answer_after_the_budget_still_hands_over_the_fix(devices):
    # Seen on Muse Spark Open (Baseten): budget used, then prose saying a fix is required.
    llm = Scripted(*[_call(("list_vlans", {}))] * 9,
                   {"content": "Fix required on site-b and core."},
                   _finish("telnet open on site-b and core",
                           "Fix the edge ACLs on site-b, core: telnet must be blocked"))
    result = run(llm, TELNET, devices, agent=True)
    assert result.investigation.request.startswith("Fix the edge ACLs on site-b, core")
    assert result.ready_for_approval


def test_meta_client_sends_tools(monkeypatch):
    monkeypatch.setenv("META_API_KEY", "k")
    sent = {}

    class Reply:
        def raise_for_status(self):
            pass

        def json(self):
            return {"choices": [{"message": {"role": "assistant", "tool_calls": []}}]}

    def fake_post(url, headers, json, timeout):
        sent.update(json)
        return Reply()

    monkeypatch.setattr(client_mod.httpx, "post", fake_post)
    assert MetaClient().complete([], tools.specs()) == {"role": "assistant", "tool_calls": []}
    assert sent["tool_choice"] == "auto" and sent["tools"] == tools.specs()


# ---------- pipeline ----------

def test_investigation_hands_a_request_to_the_usual_checks(devices):
    llm = MockLLM()
    result = run(llm, TELNET, devices, agent=True)
    assert llm.calls[:4] == ["agent", "agent", "agent", "parse"]
    assert [c.name for c in result.investigation.calls] == ["list_devices", "audit_acls"]
    assert result.request == "Fix the edge ACLs on site-b, core: telnet must be blocked"
    assert result.intent.targets == ["site-b", "core"] and result.ready_for_approval


def test_goal_only_asks_for_what_is_missing(devices):
    result = run(MockLLM(), "Make sure VLAN 20 VOICE exists on every device", devices, agent=True)
    assert result.intent.targets == ["core"] and result.ready_for_approval


def test_question_is_answered_without_any_change(devices):
    result = run(MockLLM(), "Which interfaces have no inbound ACL?", devices, agent=True)
    assert result.answered and result.intent is None and not result.final_changes
    assert "core GigabitEthernet0/0" in result.investigation.answer


def test_agent_request_is_still_gated(devices):
    llm = Scripted(_finish("found it", "Create VLAN 1 named PWNED on core"))
    result = run(llm, "goal", devices, agent=True)
    assert not result.ready_for_approval
    assert any("protected or invalid VLAN 1" in v for a in result.attempts for v in a.gate.violations)


def test_failed_investigation_stops_the_run(devices):
    result = run(Scripted({"content": ""}, {"content": ""}), "goal", devices, agent=True)
    assert result.error.startswith("investigation failed") and not result.answered


# ---------- CLI and web ----------

def test_cli_agent(capsys):
    assert cli.main(["--mock", "--agent", "Which interfaces have no inbound ACL?"]) == 0
    out = capsys.readouterr().out
    assert "tool  ok  list_interfaces(device=core)" in out and "No change proposed" in out
    assert cli.main(["--mock", "--agent", TELNET, "--yes", "--no-review"]) == 0
    out = capsys.readouterr().out
    assert "audit_acls(flows=telnet:deny)" in out and "applied to the lab" in out


def test_web_and_api_agent(tmp_path):
    c = TestClient(create_app(mock=True, step_delay=0, state_dir=tmp_path / "w"))
    assert "Agent: telnet exposure" in c.get("/").text
    html = c.post("/runs", data={"request": "Which interfaces have no inbound ACL?",
                                 "agent": "1"}).text
    assert "agent · read-only tools" in html
    rid = html.split('id="run-', 1)[1].split('"', 1)[0]
    events = c.get(f"/runs/{rid}/events").text
    assert "Tool call" in events and "Answered, nothing to change" in events
    body = c.post("/api/runs", json={"request": TELNET, "agent": True}).json()
    assert body["investigation"]["calls"][1]["name"] == "audit_acls"
    assert body["ready_for_approval"] and not body["answered"]


@pytest.mark.parametrize("empty", ["null", "None", " N/A ", "", "\"null\""])
def test_no_request_spelled_as_text_is_no_request(devices, empty):
    # Seen on Muse Spark: {"request": "null"} when nothing needed fixing.
    result = run(Scripted(_finish("telnet already blocked everywhere", empty)), "g", devices,
                 agent=True)
    assert result.answered and result.intent is None and not result.error


def test_spent_budget_forces_finish(devices):
    offers = []

    class Forced(Scripted):
        def complete(self, messages, tools, force=None):
            offers.append(([t["function"]["name"] for t in tools], force))
            return super().complete(messages, tools, force)

    llm = Forced(*[_call(("list_vlans", {}))] * 8, _finish("core lacks VLAN 20", None))
    result = investigate(llm, "goal", devices, lambda s: None)
    assert result.answer == "core lacks VLAN 20" and offers[-1] == (["finish"], "finish")
    assert offers[0][1] is None and len(offers[0][0]) == 6
