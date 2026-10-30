import re
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from netops_copilot import changes, cli
from netops_copilot.agent.pipeline import load_inventory, run
from netops_copilot.lab import config_editor
from netops_copilot.llm.mock import MockLLM
from netops_copilot.models import Vendor
from netops_copilot.web.app import create_app

INVENTORY = Path(__file__).resolve().parents[1] / "lab" / "inventory.yml"
AUDIT = "Telnet and SMB must be blocked and HTTPS allowed on all edge ACLs"
FIX = "Fix the edge ACLs: telnet and SMB must be blocked and HTTPS allowed"
VLAN = "Create VLAN 30 named users on site-a and site-b"


@pytest.fixture
def store(tmp_path):
    return changes.Store(tmp_path / "lab")


def approve(request, store, **llm):
    devices = load_inventory(INVENTORY, store)
    result = run(MockLLM(**llm), request, devices)
    return result, devices, changes.commit(result, devices, INVENTORY, store, "alice")


# ---------- rollback derivation ----------

def test_rollback_of_a_new_vlan_removes_it_on_each_vendor():
    for vendor, neg, cfg in [(Vendor.CISCO_IOS, "no", "vlan 10\n name A\n!\nend\n"),
                             (Vendor.HUAWEI_VRP, "undo", "vlan 10\n name A\n#\nreturn\n")]:
        after = config_editor.apply(vendor, cfg, ["vlan 30", " name USERS"])
        assert changes.derive_rollback(vendor, cfg, after) == [f"{neg} vlan 30"]


def test_rollback_unbinds_before_deleting_the_acl():
    before = "interface Gi0/0\n!\nend\n"
    after = config_editor.apply(Vendor.CISCO_IOS, before, [
        "ip access-list extended NEW", " 10 deny tcp any any eq 23", " 20 permit ip any any",
        "interface Gi0/0", " ip access-group NEW in"])
    assert changes.derive_rollback(Vendor.CISCO_IOS, before, after) == [
        "interface Gi0/0", " no ip access-group NEW in", "no ip access-list extended NEW"]


def test_no_rollback_means_no_change():
    before = "vlan 10\n name A\n!\nend\n"
    renamed = "vlan 10\n name B\n!\nend\n"
    with pytest.raises(changes.ChangeError, match="no automatic rollback"):
        changes.derive_rollback(Vendor.CISCO_IOS, before, renamed)


def test_huawei_vlan_batch_creates_vlans_and_rolls_back():
    cfg = "vlan batch 10\n#\nvlan 10\n#\nreturn\n"
    after = config_editor.apply(Vendor.HUAWEI_VRP, cfg, ["vlan batch 40 41"])
    assert "vlan 40" in after and "vlan 41" in after
    rollback = changes.derive_rollback(Vendor.HUAWEI_VRP, cfg, after)
    assert config_editor.apply(Vendor.HUAWEI_VRP, after, rollback) == cfg


# ---------- apply, re-audit, rollback ----------

def test_fix_then_audit_is_compliant_then_rollback_restores_everything(store):
    original = {h: d.config for h, d in load_inventory(INVENTORY).items()}
    _, _, entry = approve(FIX, store)
    assert entry["type"] == "apply" and entry["operator"] == "alice"

    after_fix = run(MockLLM(), AUDIT, load_inventory(INVENTORY, store))
    assert after_fix.compliant

    changes.rollback(entry["change"], INVENTORY, store, "bob")
    restored = load_inventory(INVENTORY, store)
    assert {h: d.config for h, d in restored.items()} == original
    assert not run(MockLLM(), AUDIT, restored).compliant
    with pytest.raises(changes.ChangeError, match="already rolled back"):
        changes.rollback(entry["change"], INVENTORY, store)


def test_stale_approval_is_refused(store):
    devices = load_inventory(INVENTORY, store)
    stale = run(MockLLM(), VLAN, devices)
    approve("Create VLAN 40 named cameras on site-a", store)  # the lab moves meanwhile
    with pytest.raises(changes.ChangeError, match="changed since this run was validated"):
        changes.commit(stale, devices, INVENTORY, store)


def test_rollback_refused_after_a_later_change(store):
    _, _, first = approve(VLAN, store)
    approve("Create VLAN 40 named cameras on site-a", store)
    with pytest.raises(changes.ChangeError, match="changed after"):
        changes.rollback(first["change"], INVENTORY, store)


def test_nothing_to_apply_for_an_audit(store):
    result = run(MockLLM(), AUDIT, load_inventory(INVENTORY, store))
    with pytest.raises(changes.ChangeError, match="nothing validated"):
        changes.commit(result, load_inventory(INVENTORY, store), INVENTORY, store)


# ---------- artefacts and journal ----------

def test_ansible_artefacts(store):
    _, _, entry = approve(FIX, store)
    plays = yaml.safe_load(store.artefact(entry["change"], "playbook.yml"))
    assert [p["hosts"] for p in plays] == ["site-a", "site-b", "core"]
    task = plays[0]["tasks"][0]["ansible.netcommon.cli_config"]
    assert task["backup"] is True and "deny tcp any any eq 445" in task["config"]
    inventory = yaml.safe_load(store.artefact(entry["change"], "inventory.yml"))
    assert inventory["all"]["hosts"]["site-b"]["ansible_network_os"] == "community.network.ce"
    rollback = yaml.safe_load(store.artefact(entry["change"], "rollback.yml"))
    assert "no ip access-list extended NETOPS-EDGE-IN" in rollback[2]["tasks"][0][
        "ansible.netcommon.cli_config"]["config"]


@pytest.mark.parametrize("change_id, name", [("../../etc", "playbook.yml"),
                                             ("0123456789", "playbook.yml")])
def test_artefact_access_is_validated(store, change_id, name):
    with pytest.raises(changes.ChangeError):
        store.artefact(change_id, name)


def test_artefact_name_is_whitelisted(store):
    _, _, entry = approve(VLAN, store)
    with pytest.raises(changes.ChangeError, match="unknown artefact"):
        store.artefact(entry["change"], "change.json")


def test_journal_is_hash_chained_and_tamper_evident(store):
    _, _, entry = approve(FIX, store)
    changes.rollback(entry["change"], INVENTORY, store)
    journal = store.journal()
    assert [e["type"] for e in journal] == ["apply", "rollback"]
    assert journal[1]["prev"] == journal[0]["hash"] and store.verify_journal()
    store.journal_path.write_text(store.journal_path.read_text().replace("alice", "mallory"))
    assert not store.verify_journal()


# ---------- CLI ----------

def test_cli_apply_history_rollback_reset(capsys):
    assert cli.main([FIX, "--mock", "--yes"]) == 0
    change_id = re.search(r"Change (\w{10}) applied", capsys.readouterr().out).group(1)
    assert cli.main([AUDIT, "--mock"]) == 0  # compliant now
    assert cli.main(["--history"]) == 0
    assert f"apply     {change_id}" in capsys.readouterr().out
    assert cli.main(["--rollback", change_id]) == 0
    assert cli.main(["--rollback", change_id]) == 4
    assert cli.main([AUDIT, "--mock"]) == 3
    assert cli.main(["--reset-lab"]) == 0
    capsys.readouterr()
    assert cli.main(["--history"]) == 0
    assert "No change applied" in capsys.readouterr().out


def test_cli_requires_a_request():
    with pytest.raises(SystemExit):
        cli.main([])


# ---------- web ----------

def test_web_apply_artefacts_rollback_and_journal(tmp_path):
    c = TestClient(create_app(mock=True, step_delay=0, state_dir=tmp_path / "web"))
    page = c.post("/runs", data={"request": FIX})
    run_id = re.search(r'sse-connect="/runs/(\w+)/events"', page.text).group(1)
    c.get(f"/runs/{run_id}/events")
    decision = c.post(f"/runs/{run_id}/approve").text
    change_id = re.search(r"change <span class=\"mono\">(\w{10})", decision).group(1)
    assert "rollback.yml" in decision

    assert c.get(f"/changes/{change_id}/playbook.yml").text.startswith("# Generated by")
    assert c.get(f"/changes/{change_id}/secrets.txt").status_code == 404
    assert "Change log" in c.get("/").text and change_id in c.get("/").text
    assert c.get("/api/changes").json()["integrity_ok"] is True

    # The next run sees the applied change.
    body = c.post("/api/runs", json={"request": AUDIT}).json()
    assert body["compliant"] is True

    assert "Rolled back" in c.post(f"/changes/{change_id}/rollback").text
    assert "Rollback refused" in c.post(f"/changes/{change_id}/rollback").text
    assert "Lab reset" in c.post("/lab/reset").text
    assert c.get("/api/changes").json()["entries"] == []


def test_web_stale_approval_is_refused(tmp_path):
    c = TestClient(create_app(mock=True, step_delay=0, state_dir=tmp_path / "web"))
    ids = []
    for request in (VLAN, "Create VLAN 40 named cameras on site-a"):
        page = c.post("/runs", data={"request": request})
        ids.append(re.search(r'sse-connect="/runs/(\w+)/events"', page.text).group(1))
        c.get(f"/runs/{ids[-1]}/events")
    assert "Applied to the lab" in c.post(f"/runs/{ids[1]}/approve").text
    assert "changed since this run was validated" in c.post(f"/runs/{ids[0]}/approve").text
