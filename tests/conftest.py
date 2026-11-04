import pytest


@pytest.fixture(autouse=True)
def isolated_lab_state(tmp_path, monkeypatch):
    """Every test gets its own lab state and journal: nothing leaks between tests."""
    monkeypatch.setenv("NETOPS_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("NETOPS_OPERATOR", "tester")
    # A developer .env (loaded by dotenv) must not change what the tests check, nor let a test
    # reach a real, paid API: model settings and keys start empty, tests set what they need.
    for var in ("LLM_PROVIDER", "REVIEW_PROVIDER", "META_API_KEY", "META_API_BASE_URL",
                "META_MODEL", "MAX_TOKENS", "BASETEN_API_KEY", "BASETEN_BASE_URL",
                "BASETEN_MODEL", "BASETEN_MAX_TOKENS", "BASETEN_REASONING_EFFORT"):
        monkeypatch.delenv(var, raising=False)
