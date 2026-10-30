import pytest

from netops_copilot import cli

VLAN = "Create VLAN 30 named users on site-a and site-b"
AUDIT = "Telnet and SMB must be blocked and HTTPS allowed on all edge ACLs"
FIX = "Fix the edge ACLs: telnet and SMB must be blocked and HTTPS allowed"


def test_vlan_approved_with_yes(capsys):
    assert cli.main([VLAN, "--mock", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "+vlan 30" in out and "Approved" in out


def test_operator_rejects(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _: "n")
    assert cli.main([VLAN, "--mock"]) == 2
    assert "Nothing was pushed" in capsys.readouterr().out


def test_operator_approves_interactively(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "y")
    assert cli.main([VLAN, "--mock"]) == 0


def test_retry_loop_output(capsys):
    assert cli.main(["Create VLAN 30 named users on site-a", "--mock-faulty", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "Attempt 1: gate PASS, dry-run FAILED" in out and "existing VLAN 20 removed" in out


def test_audit_exit_code_is_3_when_non_compliant(capsys):
    assert cli.main([AUDIT, "--mock"]) == 3
    assert "NON-COMPLIANT (4 of 9 checks failed)" in capsys.readouterr().out


def test_audit_exit_code_is_0_when_compliant(capsys):
    assert cli.main(["ACL audit on site-a: telnet must be blocked", "--mock"]) == 0
    assert "COMPLIANT" in capsys.readouterr().out


def test_remediation_shows_audit_before_fix(capsys):
    assert cli.main([FIX, "--mock", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "Audit before fix: 4 of 9 checks failed" in out and "Validated diff" in out


def test_unparseable_request_exits_1(capsys):
    assert cli.main(["make the network faster", "--mock"]) == 1
    assert "ERROR: parse step failed" in capsys.readouterr().out


def test_retry_budget_exhausted_exits_1(capsys):
    assert cli.main(["Create VLAN 30 named users on site-a", "--mock-faulty", "--retries", "1"]) == 1
    assert "no valid change after 1 attempts" in capsys.readouterr().out


def test_missing_api_key_fails_fast(monkeypatch):
    monkeypatch.delenv("META_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="META_API_KEY is not set"):
        cli.main([VLAN])
