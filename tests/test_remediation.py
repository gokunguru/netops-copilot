import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netops_copilot import gate
from netops_copilot.agent.pipeline import load_inventory, run
from netops_copilot.audit import acl, remediation
from netops_copilot.lab import acl_editor
from netops_copilot.llm.mock import MockLLM
from netops_copilot.models import ChangeType, Device, Flow, Intent, ProposedChange, Vendor
from netops_copilot.web.app import create_app

INVENTORY = Path(__file__).resolve().parents[1] / "lab" / "inventory.yml"
FIX = "Fix the edge ACLs: telnet and SMB must be blocked and HTTPS allowed"
TELNET_DENY = Flow(label="telnet", protocol="tcp", dst_port=23, expected="deny")

CISCO = """hostname r1
!
ip access-list extended EDGE-IN
 10 permit tcp any any eq 443
 20 permit ip any any
!
interface Gi0/0
 ip access-group EDGE-IN in
!
interface Gi0/1
!
end
"""


def devices():
    return load_inventory(INVENTORY)


# ---------- editor ----------

def test_editor_inserts_by_sequence_number():
    out = acl_editor.apply(Vendor.CISCO_IOS, CISCO,
                           ["ip access-list extended EDGE-IN", " 15 deny tcp any any eq 23"])
    lines = out.splitlines()
    assert lines.index(" 15 deny tcp any any eq 23") == lines.index(" 10 permit tcp any any eq 443") + 1


def test_editor_creates_acl_before_end_and_binds_interface():
    out = acl_editor.apply(Vendor.CISCO_IOS, CISCO, [
        "ip access-list extended NEW", " deny tcp any any eq 23", " permit ip any any",
        "interface Gi0/1", " ip access-group NEW in"])
    assert out.rstrip().endswith("end")
    assert " 10 deny tcp any any eq 23" in out and " 20 permit ip any any" in out
    assert acl.inbound_filters(Device(hostname="r1", vendor=Vendor.CISCO_IOS, config=out)) == {
        "Gi0/0": "EDGE-IN", "Gi0/1": "NEW"}


@pytest.mark.parametrize("commands, message", [
    (["interface Gi9/9", " ip access-group X in"], "does not exist"),
    (["ip access-list extended EDGE-IN", " 10 deny tcp any any eq 23"], "already exists"),
    (["ip access-list extended EDGE-IN", " rule 5 deny tcp destination-port eq 23"], "unrecognized"),
    (["acl number 3000"], "unrecognized"),  # Huawei syntax on a Cisco device
])
def test_editor_rejects_invalid_commands(commands, message):
    with pytest.raises(acl_editor.EditError, match=message):
        acl_editor.apply(Vendor.CISCO_IOS, CISCO, commands)


# ---------- dry-run ----------

def dry(commands):
    dev = {"r1": Device(hostname="r1", vendor=Vendor.CISCO_IOS, config=CISCO)}
    return remediation.dry_run([TELNET_DENY],
                               [ProposedChange(device="r1", vendor=Vendor.CISCO_IOS,
                                               commands=commands)], dev)[0]


def test_dry_run_accepts_a_correct_fix():
    assert dry(["ip access-list extended EDGE-IN", " 5 deny tcp any any eq 23"]) == []


def test_dry_run_rejects_a_rule_placed_after_the_permit():
    errors = dry(["ip access-list extended EDGE-IN", " 30 deny tcp any any eq 23"])
    assert any("still non-compliant" in e and "20 permit ip any any" in e for e in errors)


def test_dry_run_catches_collateral_damage():
    errors = dry(["ip access-list extended EDGE-IN", " 5 deny ip any any"])
    assert any("collateral change on Gi0/0" in e and "ssh" in e for e in errors)


def test_gate_forbids_removing_protection_during_remediation():
    intent = Intent(change_type=ChangeType.ACL_REMEDIATE, targets=["r1"], summary="fix",
                    params={"flows": [TELNET_DENY.model_dump()]})
    for cmd in ["no 20", "undo rule 5", "no ip access-group EDGE-IN in", "no ip access-list extended EDGE-IN"]:
        change = ProposedChange(device="r1", vendor=Vendor.CISCO_IOS, commands=[cmd])
        assert gate.check(intent, [change]).violations, cmd


# ---------- pipeline ----------

def test_remediation_end_to_end_fixes_only_failing_devices_and_proves_it():
    result = run(MockLLM(), FIX, devices())
    assert result.intent.change_type == ChangeType.ACL_REMEDIATE
    assert result.ready_for_approval and len(result.attempts) == 1
    assert {c.device for c in result.final_changes} == {"site-a", "site-b", "core"}
    # Re-audit the candidate configs independently of the pipeline.
    flows = [f.flow for f in result.findings if f.device == "site-a"]
    for change in result.final_changes:
        dev = devices()[change.device]
        fixed = dev.model_copy(update={"config": acl_editor.apply(dev.vendor, dev.config, change.commands)})
        assert all(f.compliant for f in acl.audit(fixed, flows))


def test_remediation_lockout_is_caught_then_corrected():
    result = run(MockLLM(faulty_first_generation=True), FIX, devices())
    first, second = result.attempts
    assert any("collateral change" in e and "bgp" in e for e in first.dry_run_errors)
    assert second.ok and result.ready_for_approval
    assert " 1000 permit ip any any" in [c for ch in second.changes for c in ch.commands]


def test_remediation_on_compliant_device_is_a_no_op():
    llm = MockLLM()
    result = run(llm, "Fix the ACL on site-a: telnet must be blocked", devices())
    assert not result.attempts and not result.error and not result.ready_for_approval
    assert llm.calls == ["parse"]


def test_remediation_in_web_ui():
    c = TestClient(create_app(mock=True, step_delay=0))
    page = c.post("/runs", data={"request": FIX, "faulty": "1"})
    run_id = re.search(r'sse-connect="/runs/(\w+)/events"', page.text).group(1)
    stream = c.get(f"/runs/{run_id}/events").text
    assert "Audit before fix" in stream and "collateral change" in stream and "Approve" in stream
    assert c.post(f"/runs/{run_id}/approve").status_code == 200
