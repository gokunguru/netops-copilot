import pytest


@pytest.fixture(autouse=True)
def isolated_lab_state(tmp_path, monkeypatch):
    """Every test gets its own lab state and journal: nothing leaks between tests."""
    monkeypatch.setenv("NETOPS_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("NETOPS_OPERATOR", "tester")
