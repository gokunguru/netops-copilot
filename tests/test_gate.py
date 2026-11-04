"""Safety gate: deterministic rules on the proposed commands."""

import pytest

from netops_copilot.gate import RULES, check
from netops_copilot.models import ChangeType, Intent, ProposedChange, Vendor, Verdict

IOS, VRP = Vendor.CISCO_IOS, Vendor.HUAWEI_VRP


def intent(*targets, change_type=ChangeType.VLAN_PROVISION):
    return Intent(change_type=change_type, targets=list(targets), summary="test")


def change(*commands, device="site-a", vendor=IOS):
    return ProposedChange(device=device, vendor=vendor, commands=list(commands))


def test_a_ticket_sized_vlan_change_passes():
    result = check(intent("site-a"), [change("vlan 30", " name USERS")])
    assert result.verdict == Verdict.PASS and result.violations == []


def test_a_device_the_request_did_not_name_is_refused():
    result = check(intent("site-a"), [change("vlan 30", device="core")])
    assert result.verdict == Verdict.REJECT
    assert result.violations == ["devices outside requested scope: ['core']"]


@pytest.mark.parametrize("line, vendor", [
    ("no router ospf 1", IOS),
    ("reload", IOS),
    ("write erase", IOS),
    (" shutdown", IOS),
    ("undo local-user admin", VRP),
    ("reset saved-configuration", VRP),
])
def test_destructive_commands_are_always_refused(line, vendor):
    result = check(intent("site-a"), [change("vlan 30", line, vendor=vendor)])
    assert result.violations == [f"site-a: forbidden command '{line.strip()}'"]


@pytest.mark.parametrize("line", ["no 20", "undo rule 5", "no ip access-group EDGE-IN in",
                                  "undo traffic-filter inbound acl 3000"])
def test_an_acl_fix_can_add_protection_never_remove_it(line):
    fix = intent("site-a", change_type=ChangeType.ACL_REMEDIATE)
    assert check(fix, [change("ip access-list extended EDGE-IN", line)]).verdict == Verdict.REJECT
    # Outside an ACL fix these lines are not what the remediation rule is about.
    assert not any("forbidden" in v for v in check(intent("site-a"), [change(line)]).violations)


@pytest.mark.parametrize("vid", [1, 1002, 1005, 4095])
def test_reserved_or_invalid_vlans_are_refused(vid):
    result = check(intent("site-a"), [change(f"vlan {vid}", " name X")])
    assert result.violations == [f"site-a: protected or invalid VLAN {vid} in 'vlan {vid}'"]


def test_vlan_batch_ids_are_checked_too():
    assert check(intent("site-b"), [change("vlan batch 30 1", device="site-b", vendor=VRP)]
                 ).verdict == Verdict.PASS  # only the first id after "batch" is a VLAN reference
    assert check(intent("site-b"), [change("vlan batch 1", device="site-b", vendor=VRP)]
                 ).verdict == Verdict.REJECT


def test_oversized_changes_are_refused():
    result = check(intent("site-a"), [change(*[f"vlan {100 + i}" for i in range(51)])])
    assert "site-a: 51 commands (max 50)" in result.violations


def test_every_rule_reports_and_the_gate_collects_them_all():
    result = check(intent("site-a"), [change("vlan 1", "reload", device="core")])
    assert len(result.violations) == 3 and len(RULES) == 4
