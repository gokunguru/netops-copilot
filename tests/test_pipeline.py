from pathlib import Path

from netops_copilot.agent.pipeline import load_inventory, run
from netops_copilot.lab import simulator
from netops_copilot.llm.mock import MockLLM
from netops_copilot.models import Vendor

INVENTORY = Path(__file__).resolve().parents[1] / "lab" / "inventory.yml"


def devices():
    return load_inventory(INVENTORY)


def test_end_to_end_multivendor_vlan():
    llm = MockLLM()
    result = run(llm, "Create VLAN 30 named users on site-a and site-b", devices())
    assert result.ready_for_approval, result.error
    assert result.intent.targets == ["site-a", "site-b"]
    assert len(result.attempts) == 1
    assert "+vlan 30" in result.diffs["site-a"] and "+ name USERS" in result.diffs["site-b"]
    assert result.explanation
    assert llm.calls == ["parse", "generate", "generate", "explain"]


def test_dry_run_catches_destructive_change_and_agent_retries():
    llm = MockLLM(faulty_first_generation=True)
    result = run(llm, "Create VLAN 30 named users on site-a", devices())
    first, second = result.attempts
    assert not first.ok and any("existing VLAN 20 removed" in e for e in first.dry_run_errors)
    assert second.ok and result.ready_for_approval


def test_unsupported_request_is_refused():
    result = run(MockLLM(), "make the network faster", devices())
    assert not result.ready_for_approval and "parse step failed" in result.error


def test_retry_budget_exhausted():
    class AlwaysBad(MockLLM):
        def _generate(self, user):
            return '{"commands": ["vlan 30", " name USERS", "reload"]}'

    result = run(AlwaysBad(), "Create VLAN 30 named users on site-a", devices(), max_retries=2)
    assert len(result.attempts) == 2 and "no valid change" in result.error
    assert not result.final_changes


def test_parse_vlans_huawei_batch():
    cfg = "vlan batch 10 20 to 22\n#\nvlan 10\n name MGMT\n#"
    assert simulator.parse_vlans(cfg) == {10: "MGMT", 20: "", 21: "", 22: ""}


def test_wrong_vendor_syntax_rejected():
    import pytest
    with pytest.raises(simulator.SimulationError):
        simulator.apply(Vendor.HUAWEI_VRP, {}, ["no vlan 10"])
