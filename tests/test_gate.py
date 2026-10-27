from netops_copilot.gate import check
from netops_copilot.models import ChangeType, Intent, ProposedChange, Vendor, Verdict


def make_intent(targets):
    return Intent(change_type=ChangeType.VLAN_PROVISION, targets=targets, summary="add VLAN 30")


def test_clean_change_passes():
    changes = [ProposedChange(device="site-a", vendor=Vendor.CISCO_IOS,
                              commands=["vlan 30", " name USERS"])]
    assert check(make_intent(["site-a"]), changes).verdict == Verdict.PASS


def test_out_of_scope_device_rejected():
    changes = [ProposedChange(device="core", vendor=Vendor.CISCO_IOS, commands=["vlan 30"])]
    result = check(make_intent(["site-a"]), changes)
    assert result.verdict == Verdict.REJECT
    assert "outside requested scope" in result.violations[0]


def test_forbidden_command_rejected_cisco():
    changes = [ProposedChange(device="site-a", vendor=Vendor.CISCO_IOS,
                              commands=["vlan 30", "no router ospf 1"])]
    assert check(make_intent(["site-a"]), changes).verdict == Verdict.REJECT


def test_forbidden_command_rejected_huawei():
    changes = [ProposedChange(device="site-a", vendor=Vendor.HUAWEI_VRP,
                              commands=["vlan batch 30", "undo local-user admin"])]
    assert check(make_intent(["site-a"]), changes).verdict == Verdict.REJECT


def test_protected_vlan_rejected():
    changes = [ProposedChange(device="site-a", vendor=Vendor.CISCO_IOS,
                              commands=["vlan 1", " name HACKED"])]
    result = check(make_intent(["site-a"]), changes)
    assert result.verdict == Verdict.REJECT
    assert "protected or invalid VLAN 1" in result.violations[0]
