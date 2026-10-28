from pathlib import Path

import pytest

from netops_copilot.agent.pipeline import load_inventory, run
from netops_copilot.audit import acl
from netops_copilot.llm.mock import MockLLM
from netops_copilot.models import Device, Flow, Vendor

INVENTORY = Path(__file__).resolve().parents[1] / "lab" / "inventory.yml"

TELNET_DENY = Flow(label="telnet", protocol="tcp", dst_port=23, expected="deny")
HTTPS_PERMIT = Flow(label="https", protocol="tcp", dst_port=443, expected="permit")


def cisco(body: str) -> Device:
    cfg = (f"ip access-list extended T\n{body}\n!\n"
           "interface Gi0/0\n ip access-group T in\n!")
    return Device(hostname="r1", vendor=Vendor.CISCO_IOS, config=cfg)


def huawei(body: str) -> Device:
    cfg = (f"acl number 3000\n{body}\n#\n"
           "interface GigabitEthernet0/0/0\n traffic-filter inbound acl 3000\n#")
    return Device(hostname="r2", vendor=Vendor.HUAWEI_VRP, config=cfg)


def actual(device: Device, flow: Flow) -> str:
    [finding] = acl.audit(device, [flow])
    return finding.actual


def test_first_match_wins():
    dev = cisco(" 10 permit tcp any any eq 23\n 20 deny tcp any any eq 23")
    assert actual(dev, TELNET_DENY) == "permit"


def test_cisco_implicit_deny_vs_huawei_default_permit():
    assert actual(cisco(" 10 permit tcp any any eq 443"), TELNET_DENY) == "deny"
    assert actual(huawei(" rule 5 permit tcp destination-port eq 443"), TELNET_DENY) == "permit"


def test_service_names_and_ranges():
    assert actual(cisco(" 10 deny tcp any any eq telnet\n 20 permit ip any any"), TELNET_DENY) == "deny"
    assert actual(cisco(" 10 deny tcp any any range 20 25\n 20 permit ip any any"),
                  TELNET_DENY) == "deny"
    assert actual(huawei(" rule 5 deny tcp destination-port range 20 25"), TELNET_DENY) == "deny"


def test_host_restricted_rule_does_not_count_as_blocking():
    # A deny limited to one source does not block telnet from everywhere.
    dev = cisco(" 10 deny tcp host 192.0.2.1 any eq 23\n 20 permit ip any any")
    assert actual(dev, TELNET_DENY) == "permit"
    dev = huawei(" rule 5 deny tcp source 10.0.0.0 0.0.0.255 destination-port eq 23")
    assert actual(dev, TELNET_DENY) == "permit"


def test_wrong_protocol_does_not_match():
    dev = cisco(" 10 deny udp any any eq 23\n 20 permit ip any any")
    assert actual(dev, TELNET_DENY) == "permit"


def test_applied_but_undefined_acl_permits_all():
    dev = Device(hostname="r1", vendor=Vendor.CISCO_IOS,
                 config="interface Gi0/0\n ip access-group MISSING in\n!")
    [finding] = acl.audit(dev, [TELNET_DENY])
    assert finding.actual == "permit" and "not defined" in finding.matched


def test_no_inbound_acl():
    dev = Device(hostname="r1", vendor=Vendor.CISCO_IOS, config="interface Gi0/0\n!")
    [finding] = acl.audit(dev, [TELNET_DENY])
    assert not finding.compliant and finding.interface == "(all)"


@pytest.mark.parametrize("request_text", [
    "Audit edge ACLs: block telnet and smb, allow https",
    "Telnet and SMB must be blocked and HTTPS allowed (compliance audit)",
])
def test_end_to_end_audit_on_lab(request_text):
    llm = MockLLM()
    result = run(llm, request_text, load_inventory(INVENTORY))
    assert result.is_audit and not result.error
    assert not result.compliant
    failed = {(f.device, f.flow.label) for f in result.findings if not f.compliant}
    assert failed == {("site-a", "smb"), ("site-b", "telnet"), ("core", "telnet"), ("core", "smb")}
    assert llm.calls == ["parse", "explain"]  # read-only: no generation step
    assert not result.ready_for_approval


def test_audit_scoped_to_named_device():
    result = run(MockLLM(), "ACL audit on site-b: block telnet", load_inventory(INVENTORY))
    assert result.intent.targets == ["site-b"]
    assert [f.actual for f in result.findings] == ["permit"]
