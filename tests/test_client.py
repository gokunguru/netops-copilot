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
