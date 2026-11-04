"""Independent reviewer: separate session, read-only tools on running and candidate states,
can only escalate, fails closed."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netops_copilot import cli, risk
from netops_copilot.agent import prompts
from netops_copilot.agent import review as reviewer
from netops_copilot.agent.pipeline import load_inventory, run
from netops_copilot.llm import client as client_mod
from netops_copilot.llm.mock import MockLLM, _call
from netops_copilot.web.app import create_app

INVENTORY = Path(__file__).resolve().parents[1] / "lab" / "inventory.yml"
FIX = "Fix the edge ACLs: telnet and SMB must be blocked and HTTPS allowed"
VLAN = "Create VLAN 30 named users on site-a"


@pytest.fixture
def devices():
    return load_inventory(INVENTORY)


class Reviewer(MockLLM):
    """MockLLM for every step, scripted replies for the review session only."""

    def __init__(self, *replies, fail: Exception | None = None, fallback: str = "no json here"):
        super().__init__()
        self.replies, self.fail, self.review_messages = list(replies), fail, []
        self.fallback, self.fallback_prompts = fallback, []

    def chat(self, messages, **kwargs):
        if messages[0]["content"] != prompts.REVIEW_SYSTEM:
            return super().chat(messages, **kwargs)
        self.fallback_prompts.append(messages[-1]["content"])
        return self.fallback

    def complete(self, messages, tools, force=None):
        if messages[0]["content"] != prompts.REVIEW_SYSTEM:
            return super().complete(messages, tools, force)
        self.review_messages.append(messages)
        if self.fail:
            raise self.fail
        return self.replies.pop(0)


def verdict(v="approve", concerns=(), summary="ok"):
    return _call(("verdict", {"verdict": v, "summary": summary, "concerns": list(concerns)}))


# ---------- tools and independence ----------

def test_reviewer_tools_are_read_only_on_two_states():
    names = [s["function"]["name"] for s in reviewer.specs()]
    assert names == ["list_devices", "show_config", "list_interfaces", "list_vlans", "audit_acls",
                     "verdict"]
    for s in reviewer.specs()[:-1]:
        assert s["function"]["parameters"]["properties"]["state"]["enum"] == ["running",
                                                                              "candidate"]


def test_reviewer_sees_the_change_not_the_generator(devices):
    llm = Reviewer(_call(("list_interfaces", {"device": "core", "state": "candidate"}),
                         ("list_interfaces", {"device": "core"})), verdict())
    run(MockLLM(faulty_first_generation=True), "x", devices)  # warm-up: nothing shared
    result = run(llm, FIX, devices)
    system, user = llm.review_messages[0][0]["content"], llm.review_messages[0][1]["content"]
    assert system == prompts.REVIEW_SYSTEM
    assert user.startswith(f"Operator request: {FIX}")
    assert prompts.GENERATE_ACL_FIX_SYSTEM not in user and "previous attempt" not in user
    assert "Verified by the deterministic checks" in user and "re-audited" in user
    assert "Huawei VRP traffic-filter permits packets that match no rule" in user
    # Seen on Muse Spark Open: "core was not in need of remediation". It now sees why it is.
    assert "Audit before the fix, non-compliant: " in user
    assert "core (all) telnet expected deny, actual permit (no inbound ACL" in user
    candidate, running = (json.loads(c.output) for c in result.review.calls)
    assert candidate[0]["inbound_filter"] == "NETOPS-EDGE-IN" and running[0]["inbound_filter"] is None


# ---------- verdicts: only escalation ----------

def test_mock_reviewer_approves_a_vlan_and_escalates_a_filtered_uplink(devices):
    assert run(MockLLM(), VLAN, devices).review.verdict == "approve"
    result = run(MockLLM(), FIX, devices)
    assert result.escalated and result.ready_for_approval
    assert "GigabitEthernet0/0 (UPLINK)" in result.review.concerns[0].text


def test_a_serious_concern_always_escalates(devices):
    medium = {"severity": "medium", "device": "site-a", "text": "naming"}
    assert run(Reviewer(verdict("approve", [medium])), VLAN, devices).escalated
    low = {"severity": "low", "text": "cosmetic"}
    assert not run(Reviewer(verdict("approve", [low])), VLAN, devices).escalated


def test_reviewer_can_raise_the_risk_never_lower_it(devices):
    high = {"severity": "high", "device": "site-a", "text": "VLAN 30 is the customer VLAN"}
    result = run(Reviewer(verdict("escalate", [high])), VLAN, devices)
    assert result.risk.level == "high"
    assert result.risk.reasons[0] == "independent reviewer: site-a: VLAN 30 is the customer VLAN"
    assert "Risk: high (raised from low" in result.explanation
    floor = risk.Risk(level="medium", reasons=["x"])
    assert risk.with_review(floor, result.review.model_copy(update={"concerns": []})) == floor


# ---------- fails closed ----------

@pytest.mark.parametrize("llm", [
    Reviewer(fail=RuntimeError("API down")),
    Reviewer({"content": "Looks fine to me."}),
    Reviewer(*[_call(("list_vlans", {}))] * 12),
])
def test_no_verdict_means_escalation(devices, llm):
    result = run(llm, VLAN, devices)
    assert result.escalated and "reviewer unavailable" in result.review.concerns[0].text


def test_bad_calls_go_back_to_the_reviewer(devices):
    llm = Reviewer(_call(("list_vlans", {"state": "tomorrow"})),
                   _call(("verdict", {"verdict": "maybe"})), verdict())
    result = run(llm, VLAN, devices)
    assert [c.ok for c in result.review.calls] == [False, False]
    assert "state must be one of running, candidate" in result.review.calls[0].output
    assert result.review.verdict == "approve"


def test_review_can_be_skipped_or_run_on_another_model(devices):
    assert run(MockLLM(), VLAN, devices, review=False).review is None
    other = Reviewer(verdict(summary="from the other model"))
    result = run(MockLLM(), VLAN, devices, review=other)
    assert result.review.summary == "from the other model" and other.review_messages


def test_reviewer_defaults_to_the_other_provider(monkeypatch):
    monkeypatch.setenv("META_API_KEY", "m")
    monkeypatch.delenv("BASETEN_API_KEY", raising=False)
    monkeypatch.delenv("REVIEW_PROVIDER", raising=False)
    main = client_mod.MetaClient(provider="meta")
    assert client_mod.reviewer(main) is main  # one key: same model, separate session
    monkeypatch.setenv("BASETEN_API_KEY", "b")
    assert client_mod.reviewer(main).provider == "baseten"  # independent weights too
    monkeypatch.setenv("REVIEW_PROVIDER", "meta")
    assert client_mod.reviewer(main).provider == "meta"


# ---------- CLI and web ----------

def test_yes_never_approves_an_escalated_change(capsys):
    assert cli.main([FIX, "--mock", "--yes"]) == 2
    out = capsys.readouterr().out
    assert "Review  : ESCALATE" in out and "never approves an escalated change" in out


def test_operator_can_override_explicitly(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda prompt: "override")
    assert cli.main([FIX, "--mock"]) == 0
    assert "applied to the lab" in capsys.readouterr().out


def test_web_shows_the_review_and_requires_acknowledgement(tmp_path):
    c = TestClient(create_app(mock=True, step_delay=0, state_dir=tmp_path))
    html = c.post("/runs", data={"request": FIX}).text
    rid = html.split('id="run-', 1)[1].split('"', 1)[0]
    events = c.get(f"/runs/{rid}/events").text
    assert "Reviewer looks" in events and "ESCALATED to you" in events
    assert "Approve despite concerns" in events and 'hx-vals=\'{"ack": "1"}\'' in events
    assert c.post(f"/runs/{rid}/approve").status_code == 409
    assert c.post(f"/runs/{rid}/reject").status_code == 200
    assert c.post("/api/runs", json={"request": FIX}).json()["escalated"] is True


class Recording(Reviewer):
    """Keeps which tools were offered and which one was forced, for the review session."""

    def __init__(self, *replies):
        super().__init__(*replies)
        self.offers = []

    def complete(self, messages, tools, force=None):
        if messages[0]["content"] == prompts.REVIEW_SYSTEM:
            self.offers.append(([t["function"]["name"] for t in tools], force))
        return super().complete(messages, tools, force)


def test_spent_budget_forces_the_verdict(devices):
    # Seen on Muse Spark Open: tool calls kept coming after "budget exhausted", no verdict.
    llm = Recording(*[_call(("list_vlans", {}))] * reviewer.MAX_CALLS, verdict(summary="done"))
    result = run(llm, VLAN, devices)
    assert result.review.verdict == "approve" and result.review.summary == "done"
    assert llm.offers[-1] == (["verdict"], "verdict") and llm.offers[0][1] is None


def test_prose_instead_of_a_verdict_is_asked_once(devices):
    llm = Recording({"content": "Looks fine."}, verdict(summary="ok after nudge"))
    result = run(llm, VLAN, devices)
    assert result.review.summary == "ok after nudge" and llm.offers[1] == (["verdict"], "verdict")
    assert reviewer.VERDICT_NUDGE in llm.review_messages[1][-2]["content"]


def test_client_sends_the_forced_tool_choice(monkeypatch):
    monkeypatch.setenv("META_API_KEY", "k")
    sent = {}

    class Reply:
        def raise_for_status(self):
            pass

        def json(self):
            return {"choices": [{"message": {"tool_calls": []}}]}

    def fake_post(url, headers, json, timeout):
        sent.update(json)
        return Reply()

    monkeypatch.setattr(client_mod.httpx, "post", fake_post)
    client_mod.MetaClient(provider="meta").complete([], reviewer.specs()[-1:], force="verdict")
    assert sent["tool_choice"] == {"type": "function", "function": {"name": "verdict"}}


def test_vlan_review_gets_the_dry_run_facts(devices):
    llm = Reviewer(verdict())
    run(llm, VLAN, devices)
    assert "no existing VLAN was removed or renamed" in llm.review_messages[0][1]["content"]


def test_provider_ignoring_the_forced_verdict_gets_a_json_fallback(devices):
    # Seen on Muse Spark Open (Baseten): even with tool_choice forcing `verdict`, more tool calls.
    reply = json.dumps({"verdict": "escalate", "summary": "uplink filtered", "concerns": [
        {"severity": "high", "device": "core", "text": "core Gi0/0 is an uplink, not an edge"}]})
    llm = Reviewer(*[_call(("list_interfaces", {"device": "core", "state": "candidate"}))] * 11,
                   fallback=reply)
    result = run(llm, FIX, devices)
    assert result.review.summary == "uplink filtered" and result.risk.level == "high"
    assert "Tool results you gathered" in llm.fallback_prompts[0]
    assert "NETOPS-EDGE-IN" in llm.fallback_prompts[0]  # the evidence is passed along
    assert len(result.review.calls) == 11


def test_invalid_json_fallback_still_escalates(devices):
    llm = Reviewer(*[_call(("list_vlans", {}))] * 11, fallback='{"verdict": "ship it"}')
    result = run(llm, VLAN, devices)
    assert result.escalated and "reviewer unavailable" in result.review.concerns[0].text


def test_offline_model_json_fallback(devices):
    llm = Reviewer(*[_call(("list_vlans", {}))] * 11)
    llm.chat = MockLLM().chat  # the offline model's own fallback answer
    assert run(llm, VLAN, devices).review.summary.startswith("Budget spent")
