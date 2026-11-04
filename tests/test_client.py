import httpx
import pytest

from netops_copilot.llm import client as client_mod
from netops_copilot.llm.client import MetaClient, extract_json


class FakeResponse:
    def __init__(self, status: int, body: dict):
        self.status_code, self._body = status, body

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("POST", "https://api.example/v1/chat/completions")
            raise httpx.HTTPStatusError("error", request=request,
                                        response=httpx.Response(self.status_code, request=request))


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("META_API_KEY", "test-key")
    monkeypatch.setenv("META_API_BASE_URL", "https://api.example/v1/")
    monkeypatch.setenv("META_MODEL", "muse-spark-1.3")
    monkeypatch.setenv("MAX_TOKENS", "1234")


def test_request_shape_and_token_cap(env, monkeypatch):
    sent = {}

    def fake_post(url, headers, json, timeout):
        sent.update(url=url, headers=headers, json=json, timeout=timeout)
        return FakeResponse(200, {"choices": [{"message": {"content": "hello"}}]})

    monkeypatch.setattr(client_mod.httpx, "post", fake_post)
    assert MetaClient().chat([{"role": "user", "content": "hi"}]) == "hello"
    assert sent["url"] == "https://api.example/v1/chat/completions"
    assert sent["headers"] == {"Authorization": "Bearer test-key"}
    assert sent["json"]["model"] == "muse-spark-1.3"
    assert sent["json"]["max_tokens"] == 1234 and sent["json"]["temperature"] == 0


def test_http_errors_are_raised(env, monkeypatch):
    monkeypatch.setattr(client_mod.httpx, "post", lambda *a, **k: FakeResponse(401, {}))
    with pytest.raises(httpx.HTTPStatusError):
        MetaClient().chat([{"role": "user", "content": "hi"}])


def test_defaults_point_to_meta_model_api(monkeypatch):
    for var in ("META_API_BASE_URL", "META_MODEL", "MAX_TOKENS"):
        monkeypatch.delenv(var, raising=False)
    c = MetaClient(api_key="k")
    assert (c.base_url, c.model) == ("https://api.meta.ai/v1", "muse-spark-1.3")


@pytest.mark.parametrize("reply", [
    '{"commands": ["vlan 30"]}',
    'Sure!\n```json\n{"commands": ["vlan 30"]}\n```',
    'Here you go: {"commands": ["vlan 30"]} hope it helps',
])
def test_extract_json_tolerates_wrapping(reply):
    assert extract_json(reply) == {"commands": ["vlan 30"]}


def test_extract_json_rejects_prose():
    with pytest.raises(ValueError, match="no JSON object"):
        extract_json("I cannot help with that.")


def test_baseten_serves_the_open_weights_model(monkeypatch):
    monkeypatch.setenv("BASETEN_API_KEY", "bt-key")
    monkeypatch.delenv("BASETEN_MODEL", raising=False)
    monkeypatch.delenv("BASETEN_BASE_URL", raising=False)
    monkeypatch.delenv("BASETEN_MAX_TOKENS", raising=False)
    monkeypatch.delenv("BASETEN_REASONING_EFFORT", raising=False)
    sent = {}

    def fake_post(url, headers, json, timeout):
        sent.update(url=url, headers=headers, json=json)
        return FakeResponse(200, {"choices": [{"message": {"content": "ok"}}]})

    monkeypatch.setattr(client_mod.httpx, "post", fake_post)
    c = MetaClient(provider="baseten")
    assert c.chat([{"role": "user", "content": "hi"}]) == "ok"
    assert sent["url"] == "https://inference.baseten.co/v1/chat/completions"
    assert sent["headers"] == {"Authorization": "Bearer bt-key"}
    assert sent["json"]["model"] == "meta-models/muse-spark-open"
    # Always-on reasoning (xhigh by default on Baseten) must leave room for the answer.
    assert sent["json"]["max_tokens"] == 16384 and sent["json"]["reasoning_effort"] == "medium"
    assert c.label == "Baseten · open weights"


def test_provider_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "baseten")
    monkeypatch.setenv("BASETEN_API_KEY", "k")
    monkeypatch.setenv("BASETEN_MODEL", "meta-models/muse-spark-open-v2")
    assert MetaClient().model == "meta-models/muse-spark-open-v2"
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    with pytest.raises(RuntimeError, match="unknown LLM provider 'openai'"):
        MetaClient()


def test_web_badge_names_the_provider(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from netops_copilot.web.app import create_app
    monkeypatch.setenv("LLM_PROVIDER", "baseten")
    monkeypatch.delenv("BASETEN_MODEL", raising=False)  # a developer .env may set it
    page = TestClient(create_app(mock=False, state_dir=tmp_path)).get("/").text
    assert "meta-models/muse-spark-open · Baseten · open weights" in page


def test_reasoning_settings_are_per_provider(env, monkeypatch):
    monkeypatch.setenv("BASETEN_API_KEY", "b")
    monkeypatch.setenv("BASETEN_MAX_TOKENS", "32768")
    monkeypatch.setenv("BASETEN_REASONING_EFFORT", "low")
    open_weights = MetaClient(provider="baseten")
    assert (open_weights.max_tokens, open_weights.reasoning_effort) == (32768, "low")
    hosted = MetaClient(provider="meta")
    assert (hosted.max_tokens, hosted.reasoning_effort) == (1234, None)  # MAX_TOKENS, no effort


def test_empty_content_does_not_crash(env, monkeypatch):
    monkeypatch.setattr(client_mod.httpx, "post", lambda *a, **k: FakeResponse(
        200, {"choices": [{"message": {"content": None, "reasoning_content": "..."}}]}))
    assert MetaClient().chat([{"role": "user", "content": "hi"}]) == ""


def test_token_usage_is_counted(env, monkeypatch):
    monkeypatch.setattr(client_mod.httpx, "post", lambda *a, **k: FakeResponse(200, {
        "choices": [{"message": {"content": "x"}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 40}}))
    c = MetaClient()
    c.chat([{"role": "user", "content": "a"}])
    c.chat([{"role": "user", "content": "b"}])
    assert c.usage == {"calls": 2, "prompt_tokens": 200, "completion_tokens": 80}
