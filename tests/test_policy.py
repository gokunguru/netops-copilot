"""Policy as code, drift report and issue sync, and the deterministic risk floor."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netops_copilot import cli, policy, risk
from netops_copilot.agent.pipeline import load_inventory, run
from netops_copilot.llm.mock import MockLLM
from netops_copilot.models import ProposedChange, Vendor
from netops_copilot.web.app import create_app

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "lab" / "inventory.yml"
SCRIPT = ROOT / ".github" / "scripts" / "drift-issue.sh"


@pytest.fixture
def devices():
    return load_inventory(INVENTORY)


@pytest.fixture
def policies():
    return policy.load(ROOT / "policies")


def write(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    return tmp_path


# ---------- loading ----------

def test_repo_policies_load(policies):
    assert [(p.name, p.kind) for p in policies] == [("edge-acl-baseline", "acl"),
                                                     ("standard-vlans", "vlan")]


@pytest.mark.parametrize(("text", "error"), [
    (("name: x1\nflows: [{label: t, protocol: tcp, dst_port: 23, expected: deny}]\n"
      "vlans: [{vlan_id: 10, name: A}]\n"), "either `flows`"),
    ("name: x1\n", "either `flows`"),
    ("name: Bad Name\nvlans: [{vlan_id: 10, name: A}]\n", "pattern"),
    ("name: x1\nvlans: [{vlan_id: 99999, name: A}]\n", "4094"),
    ("- not a mapping\n", "p.yml"),
])
def test_invalid_policies_are_refused(tmp_path, text, error):
    with pytest.raises(policy.PolicyError, match=error):
        policy.load(write(tmp_path, "p.yml", text))


def test_duplicate_and_missing_policies(tmp_path):
    with pytest.raises(policy.PolicyError, match="no policy file"):
        policy.load(tmp_path)
    write(tmp_path, "a.yml", "name: same\nvlans: [{vlan_id: 10, name: A}]\n")
    write(tmp_path, "b.yml", "name: same\nvlans: [{vlan_id: 11, name: B}]\n")
    with pytest.raises(policy.PolicyError, match="duplicate policy name 'same'"):
        policy.load(tmp_path)


def test_unknown_device_in_scope(tmp_path, devices):
    [p] = policy.load(write(tmp_path, "p.yml", "name: x1\ndevices: [site-z]\n"
                                               "vlans: [{vlan_id: 10, name: MGMT}]\n"))
    with pytest.raises(policy.PolicyError, match="unknown devices"):
        policy.check(p, devices)


# ---------- checking and enforcing ----------

def test_lab_drift(policies, devices):
    acl_result, vlan_result = policy.check_all(policies, devices)
    assert len(acl_result.failed) == 4 and len(acl_result.rows) == 9
    assert [(r.device, r.subject, r.actual) for r in vlan_result.failed] == [
        ("core", "vlan 20", "missing")]


def test_policy_becomes_an_intent_without_any_model(policies, devices):
    acl_result, vlan_result = policy.check_all(policies, devices)
    acl_intent = policy.intent(acl_result)
    assert acl_intent.change_type.value == "acl_remediate"
    assert acl_intent.targets == ["site-a", "site-b", "core"]
    vlan_intent = policy.intent(vlan_result)
    assert vlan_intent.targets == ["core"] and vlan_intent.params == {"vlan_id": 20, "name": "VOICE"}


def test_renames_and_compliance_are_not_enforced(tmp_path, devices):
    [p] = policy.load(write(tmp_path, "p.yml", "name: renamed\nvlans: [{vlan_id: 20, name: PHONES}]\n"
                                               "devices: [site-a]\n"))
    result = policy.check(p, devices)
    assert result.failed[0].actual == "VOICE" and policy.intent(result) is None
    [ok] = policy.load(write(tmp_path, "p.yml", "name: mgmt\nvlans: [{vlan_id: 10, name: MGMT}]\n"))
    assert policy.check(ok, devices).compliant and policy.intent(policy.check(ok, devices)) is None


def test_enforce_closes_the_loop(policies, devices, tmp_path):
    from netops_copilot import changes

    store = changes.Store(tmp_path / "s")
    llm = MockLLM()
    result = run(llm, "Enforce policy edge-acl-baseline", devices,
                 intent=policy.intent(policy.check(policies[0], devices)),
                 policy="edge-acl-baseline")
    assert "parse" not in llm.calls and result.ready_for_approval  # no model for the intent
    changes.commit(result, devices, INVENTORY, store)
    assert policy.check(policies[0], load_inventory(INVENTORY, store)).compliant


def test_report_and_fingerprint(policies, devices):
    results = policy.check_all(policies, devices)
    text = policy.report(results, "lab/inventory.yml")
    assert text.startswith("## Policy drift detected")
    assert "netops-copilot --enforce edge-acl-baseline" in text
    assert f"<!-- fingerprint: {policy.fingerprint(results)} -->" in text
    assert policy.fingerprint(results) == policy.fingerprint(policy.check_all(policies, devices))
    fixed = [results[0], results[1].model_copy(update={"rows": []})]
    assert policy.fingerprint(fixed) != policy.fingerprint(results)
    assert policy._cell("a|b") == "a\\|b"
    assert policy.report(fixed[1:], "x").startswith("## All policies compliant")


# ---------- risk floor ----------

def test_risk_floor_levels(devices):
    vlan = [ProposedChange(device="site-a", vendor=Vendor.CISCO_IOS,
                           commands=["vlan 30", " name USERS"])]
    assert risk.assess(vlan, devices).level == "low"
    binding = [ProposedChange(device="core", vendor=Vendor.CISCO_IOS, commands=[
        "ip access-list extended X", " 10 permit ip any any",
        "interface GigabitEthernet0/0", " ip access-group X in"])]
    r = risk.assess(binding, devices)
    assert r.level == "medium" and r.reasons[0] == "core: new inbound filter bound to GigabitEthernet0/0"
    live = {**devices, "core": devices["core"].model_copy(update={"driver": {"host": "x"}})}
    assert risk.assess(binding, live).level == "high"
    assert risk.assess(vlan, {**devices, "site-a": devices["site-a"].model_copy(
        update={"driver": {"host": "x"}})}).level == "medium"


@pytest.mark.parametrize(("text", "expected"), [
    ("Adds rules.\nRisk: Low – additive.", "Risk: medium (raised from low by the deterministic floor"),
    ("**Risk level:** low", "Risk: medium (raised from low"),
    ("No risk line.", "No risk line.\nRisk: medium (deterministic floor"),
    ("Risk: high, core uplink.", "Risk: high, core uplink."),
    ("A low-risk change.", "A medium-risk change.\nRisk: medium (raised from low by the"),
    ("Low risk overall.", "Medium risk overall.\nRisk: medium (raised from low"),
    ("A high-risk change.", "A high-risk change."),
])
def test_model_cannot_rate_below_the_floor(text, expected):
    floor = risk.Risk(level="medium", reasons=["core: new inbound filter bound to Gi0/0"])
    enforced = risk.enforce(text, floor)
    assert expected in enforced
    assert not risk.PROSE_RISK.search(enforced.replace("medium-risk", "").replace(
        "Medium risk", "").replace("high-risk", "")), "two contradicting levels"


def test_floor_is_applied_to_the_explanation(devices):
    class Optimist(MockLLM):
        def chat(self, messages, **kwargs):
            reply = super().chat(messages, **kwargs)
            return reply.replace("Risk: medium", "Risk: low") if "Risk:" in reply else reply

    result = run(Optimist(), "Fix the edge ACLs: telnet and SMB must be blocked and HTTPS allowed",
                 devices)
    assert "raised from low by the deterministic floor: core: new inbound filter" in result.explanation
    assert result.risk.level == "medium"


# ---------- CLI ----------

def test_cli_check_policies(tmp_path, capsys):
    report = tmp_path / "drift.md"
    assert cli.main(["--check-policies", "--report", str(report)]) == 3
    out = capsys.readouterr().out
    assert "edge-acl-baseline        acl   high    DRIFT (4 of 9 failed)" in out
    assert "fingerprint" in report.read_text()
    assert cli.main(["--check-policies", "--policies", str(tmp_path)]) == 1


def test_cli_enforce(capsys):
    assert cli.main(["--mock", "--enforce", "standard-vlans", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "Policy  : standard-vlans" in out and "Risk floor (deterministic): LOW" in out
    assert cli.main(["--mock", "--enforce", "standard-vlans"]) == 0
    assert "nothing to enforce" in capsys.readouterr().out
    assert cli.main(["--check-policies"]) == 3  # the ACL policy still drifts
    assert cli.main(["--mock", "--enforce", "nope"]) == 1


# ---------- web ----------

def test_web_policies_panel_enforce_and_api(tmp_path):
    c = TestClient(create_app(mock=True, step_delay=0, state_dir=tmp_path / "w"))
    panel = c.get("/policies").text
    assert "DRIFT" in panel and '"enforce": "standard-vlans"' in panel
    html = c.post("/runs", data={"enforce": "standard-vlans"}).text
    rid = html.split('id="run-', 1)[1].split('"', 1)[0]
    assert "from policy, no model" in c.get(f"/runs/{rid}/events").text
    decision = c.post(f"/runs/{rid}/approve")
    assert decision.headers["hx-trigger"] == "refresh-policies"
    assert "nothing to" in c.post("/runs", data={"enforce": "standard-vlans"}).text
    assert "unknown policy" in c.post("/runs", data={"enforce": "nope"}).text
    api = c.get("/api/policies").json()
    assert not api["compliant"] and api["policies"][1]["compliant"]


# ---------- drift issue sync (the CI script, with a fake gh) ----------

FAKE_GH = """#!/usr/bin/env bash
echo "$*" >> "$GH_LOG"
case "$1 $2" in
  "issue list") cat "$GH_STATE/open" 2>/dev/null || true ;;
  "issue view") cat "$GH_STATE/body" ;;
esac
"""


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize(("drift", "open_issue", "old_body", "expected"), [
    ("true", False, "", ["issue create --label policy-drift"]),
    ("true", True, "<!-- fingerprint: abc -->", []),
    ("true", True, "<!-- fingerprint: old -->", ["issue edit 7", "issue comment 7"]),
    ("false", True, "", ["issue comment 7", "issue close 7"]),
    ("false", False, "", []),
])
def test_drift_issue_sync(tmp_path, drift, open_issue, old_body, expected):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "gh").write_text(FAKE_GH)
    (bin_dir / "gh").chmod(0o755)
    if open_issue:
        (tmp_path / "open").write_text("7")
    (tmp_path / "body").write_text(old_body)
    (tmp_path / "drift.md").write_text("report\n<!-- fingerprint: abc -->\n")
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "GH_LOG": str(tmp_path / "log"),
           "GH_STATE": str(tmp_path), "DRIFT": drift, "INVENTORY": "lab/inventory.yml",
           "REPORT": str(tmp_path / "drift.md"), "GITHUB_SERVER_URL": "https://github.com",
           "GITHUB_REPOSITORY": "o/r", "GITHUB_RUN_ID": "1"}
    subprocess.run(["bash", str(SCRIPT)], env=env, check=True, capture_output=True)
    calls = [line for line in (tmp_path / "log").read_text().splitlines()
             if not line.startswith(("label create", "issue list", "issue view"))]
    assert [c for c in calls if any(c.startswith(e) for e in expected)] == calls
    assert len(calls) == len(expected)


def test_report_never_exposes_an_absolute_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # inventory outside the current directory: file name only
    report = tmp_path / "drift.md"
    cli.main(["--check-policies", "--inventory", str(INVENTORY), "--report", str(report)])
    text = report.read_text()
    assert "Inventory `inventory.yml`" in text and str(ROOT) not in text
    monkeypatch.chdir(ROOT)  # inside the current directory: relative path
    cli.main(["--check-policies", "--inventory", str(INVENTORY), "--report", str(report)])
    assert "Inventory `lab/inventory.yml`" in report.read_text()
