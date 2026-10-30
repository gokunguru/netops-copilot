"""Live-device path against a fake IOS XE box that behaves like one seen through Netmiko."""

import re
from pathlib import Path

import pytest

from netops_copilot import changes, cli, drivers
from netops_copilot.agent.pipeline import load_inventory, run
from netops_copilot.audit import acl, remediation
from netops_copilot.lab import config_editor
from netops_copilot.llm.mock import MockLLM
from netops_copilot.models import ProposedChange, Vendor

AUDIT = "Telnet and SMB must be blocked and HTTPS allowed on all edge ACLs"
FIX = "Fix the edge ACLs: telnet and SMB must be blocked and HTTPS allowed"

ROUTER = """hostname cat8k
!
interface GigabitEthernet1
 description MGMT
 ip address 10.10.20.48 255.255.255.0
!
interface GigabitEthernet2
 description EDGE
 ip address 192.0.2.1 255.255.255.0
!
interface Loopback0
 ip address 198.51.100.1 255.255.255.255
!
end
"""
NAMES = {"23": "telnet", "80": "www"}  # IOS shows these ports by name in the running config


class FakeRouter:
    def __init__(self, config: str = ROUTER, reject: str | None = None, tamper: bool = False):
        self.config, self.reject, self.tamper = config, reject, tamper
        self.pushes: list[list[str]] = []
        self.connected = False

    def running(self) -> str:
        shown = re.sub(r"eq (\d+)\b", lambda m: f"eq {NAMES.get(m.group(1), m.group(1))}", self.config)
        return ("Building configuration...\n\nCurrent configuration : 1873 bytes\n!\n"
                "! Last configuration change at 15:02:11 UTC Fri Oct 30 2026 by admin\n!\n" + shown)


class FakeConn:
    def __init__(self, router: FakeRouter):
        self.router = router
        router.connected = True

    def send_command(self, command_string, **kwargs):
        if command_string == "show running-config":
            return self.router.running()
        if "interface brief" in command_string:
            return "Interface  IP-Address  OK? Method Status Protocol\nGigabitEthernet2 192.0.2.1 YES manual up up"
        return "Cisco IOS XE Software, Version 17.12.04"

    def send_config_set(self, config_commands, **kwargs):
        assert kwargs["error_pattern"] and kwargs["cmd_verify"]
        self.router.pushes.append(list(config_commands))
        original = self.router.config
        for i, cmd in enumerate(config_commands):  # command by command, like the device
            if self.router.reject and self.router.reject in cmd:
                raise RuntimeError(f"Invalid input detected at '^' marker: {cmd}")
            self.router.config = config_editor.apply(Vendor.CISCO_IOS, original,
                                                      config_commands[: i + 1])
        if self.router.tamper:  # the device silently drops the last ACE we added
            self.router.config = re.sub(r"\n 20 deny tcp any any eq 445", "", self.router.config)
        return "configure terminal\n...\nend"

    def disconnect(self):
        pass


@pytest.fixture
def inventory(tmp_path):
    path = tmp_path / "live.yml"
    path.write_text("""devices:
  cat8k:
    vendor: cisco_ios
    driver: {host: sandbox.example, credentials_env: DEVNET}
    edge: [GigabitEthernet2]
    protected: [GigabitEthernet1]
""")
    return path


@pytest.fixture
def router(monkeypatch):
    box = FakeRouter()
    monkeypatch.setattr(drivers, "connect", lambda device: FakeConn(box))
    return box


@pytest.fixture
def store(tmp_path):
    return changes.Store(tmp_path / "state")


def approve(inventory, store, request=FIX):
    devices = load_inventory(inventory, store)
    result = run(MockLLM(), request, devices)
    assert result.ready_for_approval, result.error
    return result, devices


# ---------- reading the device ----------

def test_running_config_is_cleaned_and_audited_on_edge_only(inventory, store, router):
    devices = load_inventory(inventory, store)
    assert "Building configuration" not in devices["cat8k"].config
    findings = run(MockLLM(), AUDIT, devices).findings
    assert {f.interface for f in findings} == {"GigabitEthernet2"}  # Gi1 protected, Lo0 not edge


def test_live_device_must_declare_edge_interfaces(tmp_path):
    path = tmp_path / "bad.yml"
    path.write_text("devices:\n  r1:\n    vendor: cisco_ios\n    driver: {host: x}\n")
    with pytest.raises(ValueError, match="must list its edge interfaces"):
        load_inventory(path, live=False)


def test_ios_port_names_are_equivalent_to_numbers():
    assert changes._canon(" 10 deny tcp any any eq telnet") == changes._canon("10 deny tcp any any eq 23")


# ---------- full cycle on the device ----------

def test_fix_pushed_verified_then_rolled_back_on_the_device(inventory, store, router):
    result, devices = approve(inventory, store)
    entry = changes.commit(result, devices, inventory, store, "alice")
    assert entry["live"] == ["cat8k"] and len(router.pushes) == 1
    assert "ip access-group NETOPS-EDGE-IN in" in router.config

    record = store.record(entry["change"])["devices"]["cat8k"]
    assert record["target"] == "live" and "interface GigabitEthernet2" in record["headers"]
    folder = store.changes / entry["change"]
    assert (folder / "cat8k.before.cfg").exists() and (folder / "cat8k.after.cfg").exists()

    assert run(MockLLM(), AUDIT, load_inventory(inventory, store)).compliant
    changes.rollback(entry["change"], inventory, store, "bob")
    assert router.config.strip() == ROUTER.strip()
    assert not run(MockLLM(), AUDIT, load_inventory(inventory, store)).compliant


def test_device_rejecting_a_command_is_rolled_back_automatically(inventory, store, router):
    result, devices = approve(inventory, store)
    router.reject = "ip access-group"  # ACL created, binding rejected: half-applied
    with pytest.raises(changes.ChangeError, match="device rejected.*Rolled back automatically"):
        changes.commit(result, devices, inventory, store)
    assert router.config.strip() == ROUTER.strip()  # the orphan ACL was removed too
    assert store.journal() == []


def test_running_config_not_matching_the_candidate_is_rolled_back(inventory, store, router):
    result, devices = approve(inventory, store)
    router.tamper = True
    with pytest.raises(changes.ChangeError, match="differs from the validated candidate"):
        changes.commit(result, devices, inventory, store)
    router.tamper = False
    assert "NETOPS-EDGE-IN" not in router.config and store.journal() == []


def test_drift_on_a_touched_block_refuses_the_push(inventory, store, router):
    result, devices = approve(inventory, store)
    router.config = router.config.replace(" description EDGE", " description EDGE\n shutdown")
    with pytest.raises(changes.ChangeError, match="changed on the device since this run"):
        changes.commit(result, devices, inventory, store)
    assert router.pushes == []


def test_unrelated_drift_on_a_shared_device_does_not_block(inventory, store, router):
    result, devices = approve(inventory, store)
    router.config = router.config.replace("end\n", "ip access-list extended SOMEONE-ELSE\n 10 permit ip any any\n!\nend\n")
    changes.commit(result, devices, inventory, store)
    assert "SOMEONE-ELSE" in router.config


def test_rollback_refused_if_the_device_moved_after_the_change(inventory, store, router):
    result, devices = approve(inventory, store)
    entry = changes.commit(result, devices, inventory, store)
    router.config = router.config.replace(" 10 deny tcp any any eq 23", " 10 deny tcp any any eq 22")
    with pytest.raises(changes.ChangeError, match="changed after"):
        changes.rollback(entry["change"], inventory, store)


def test_protected_interface_can_never_be_filtered(inventory, store, router):
    devices = load_inventory(inventory, store)
    findings = acl.audit(devices["cat8k"], [remediation.PROBES[0].model_copy(update={"expected": "deny"})])
    change = ProposedChange(device="cat8k", vendor=Vendor.CISCO_IOS, commands=[
        "ip access-list extended X", " 10 deny tcp any any eq 22", " 20 permit ip any any",
        "interface GigabitEthernet1", " ip access-group X in"])
    errors, _ = remediation.dry_run([findings[0].flow], [change], devices, findings)
    assert any("GigabitEthernet1 is a protected interface" in e for e in errors)


# ---------- CLI ----------

def test_cli_probe_and_live_apply(inventory, router, capsys):
    assert cli.main(["--inventory", str(inventory), "--probe"]) == 0
    out = capsys.readouterr().out
    assert "cat8k (sandbox.example)" in out and "GigabitEthernet2" in out and "protected: GigabitEthernet1" in out
    assert cli.main([FIX, "--inventory", str(inventory), "--mock", "--yes"]) == 0
    assert "pushed to cat8k and verified on the running config" in capsys.readouterr().out


def test_probe_reports_missing_credentials(inventory, monkeypatch, capsys):
    monkeypatch.delenv("DEVNET_USERNAME", raising=False)
    assert cli.main(["--inventory", str(inventory), "--probe"]) == 4
    assert "set DEVNET_USERNAME and DEVNET_PASSWORD" in capsys.readouterr().out


def test_probe_on_lab_inventory():
    lab = Path(__file__).resolve().parents[1] / "lab" / "inventory.yml"
    assert cli.main(["--inventory", str(lab), "--probe"]) == 0


def test_unreachable_device_is_reported_not_crashed(inventory, monkeypatch, capsys, tmp_path):
    def down(device):
        raise drivers.DriverError("cat8k: cannot connect (timeout)")

    monkeypatch.setattr(drivers, "connect", down)
    assert cli.main([AUDIT, "--inventory", str(inventory), "--mock"]) == 4
    assert "Cannot read the devices: cat8k: cannot connect" in capsys.readouterr().out

    from fastapi.testclient import TestClient

    from netops_copilot.web.app import create_app
    c = TestClient(create_app(mock=True, inventory=inventory, step_delay=0, state_dir=tmp_path / "w"))
    assert c.get("/").status_code == 200  # the home page never opens an SSH session
    assert "Cannot read the devices" in c.post("/runs", data={"request": AUDIT}).text
    assert c.get("/api/inventory").json() == [{"hostname": "cat8k", "vendor": "cisco_ios", "live": True}]
