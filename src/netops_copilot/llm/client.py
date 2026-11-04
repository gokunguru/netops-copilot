"""Client for Muse Spark: Meta Model API or Baseten (OpenAI-compatible Chat Completions)."""

import json
import os
import re
from typing import Protocol

import dotenv
import httpx

dotenv.load_dotenv()  # API keys and overrides from .env, never committed

DEFAULT_BASE_URL = "https://api.meta.ai/v1"
DEFAULT_MODEL = "muse-spark-1.3"

# Same OpenAI-compatible API, two ways to reach a Meta model: the hosted Muse Spark on the Meta
# Model API, or the open-weights Muse Spark Open served by Baseten.
PROVIDERS = {
    "meta": {"label": "Meta Model API", "env": "META", "base_url": DEFAULT_BASE_URL,
             "model": DEFAULT_MODEL},
    # Muse Spark Open always reasons, at reasoning_effort "xhigh" by default on Baseten, and the
    # reasoning tokens count toward max_tokens: with 8k and xhigh it can run out before the
    # answer (empty content, finish_reason "length"). Defaults that leave room for the answer.
    "baseten": {"label": "Baseten · open weights", "env": "BASETEN",
                "base_url": "https://inference.baseten.co/v1",
                "model": "meta-models/muse-spark-open",
                "max_tokens": 16384, "reasoning_effort": "medium"},
}


def provider_name(provider: str | None = None) -> str:
    name = (provider or os.getenv("LLM_PROVIDER") or "meta").lower()
    if name not in PROVIDERS:
        raise RuntimeError(f"unknown LLM provider '{name}', use one of: {', '.join(PROVIDERS)}")
    return name


def settings(provider: str | None = None) -> dict:
    """Base URL, model and API key variable of a provider, with <ENV>_BASE_URL and <ENV>_MODEL
    overrides (META_API_BASE_URL is kept for compatibility)."""
    name = provider_name(provider)
    p = PROVIDERS[name]
    env = p["env"]
    base_url = (os.getenv(f"{env}_BASE_URL") or (os.getenv("META_API_BASE_URL") if name == "meta"
                                                  else None) or p["base_url"])
    model = os.getenv(f"{env}_MODEL") or p["model"]
    max_tokens = int(os.getenv(f"{env}_MAX_TOKENS") or p.get("max_tokens")
                     or os.getenv("MAX_TOKENS") or 2048)
    effort = os.getenv(f"{env}_REASONING_EFFORT") or p.get("reasoning_effort")
    return {"name": name, "label": p["label"], "base_url": base_url, "model": model,
            "key_var": f"{env}_API_KEY", "max_tokens": max_tokens, "reasoning_effort": effort}


class LLM(Protocol):
    def chat(self, messages: list[dict], **kwargs) -> str: ...

    def complete(self, messages: list[dict], tools: list[dict], force: str | None = None) -> dict:
        """One assistant message, possibly with tool_calls (OpenAI format). `force` names the
        tool the model must call (used to make it conclude once its tool budget is spent)."""
        ...


class MetaClient(LLM):
    """Muse Spark over an OpenAI-compatible Chat Completions API (Meta Model API or Baseten)."""

    def __init__(self, api_key: str | None = None, model: str | None = None,
                 provider: str | None = None) -> None:
        conf = settings(provider)
        self.provider, self.label = conf["name"], conf["label"]
        self.api_key = api_key or os.environ.get(conf["key_var"], "")
        if not self.api_key:
            raise RuntimeError(f"{conf['key_var']} is not set (see .env.example), "
                               "or run with --mock")
        self.base_url = conf["base_url"]
        self.model = model or conf["model"]
        self.max_tokens = conf["max_tokens"]
        self.reasoning_effort = conf["reasoning_effort"]
        self.usage = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0}

    def chat(self, messages: list[dict], **options) -> str:
        return self._post(messages, **options).get("content") or ""

    def complete(self, messages: list[dict], tools: list[dict], force: str | None = None) -> dict:
        choice = {"type": "function", "function": {"name": force}} if force else "auto"
        return self._post(messages, tools=tools, tool_choice=choice)

    def _post(self, messages: list[dict], **kwargs) -> dict:
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0,
            "max_tokens": self.max_tokens,  # hard cap per call, protects the credits
            **({"reasoning_effort": self.reasoning_effort} if self.reasoning_effort else {}),
            **kwargs,
        }
        endpoint = self.base_url.rstrip("/") + "/chat/completions"
        auth = {"Authorization": "Bearer " + self.api_key}
        reply = httpx.post(endpoint, headers=auth, json=payload, timeout=120)
        reply.raise_for_status()
        data = reply.json()
        usage = data.get("usage") or {}
        self.usage["calls"] += 1
        for key in ("prompt_tokens", "completion_tokens"):
            self.usage[key] += int(usage.get(key) or 0)
        return data["choices"][0]["message"]


def extract_json(text: str) -> dict:
    """Parse a JSON object from a model reply, tolerating code fences or surrounding prose."""
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidate = fenced.group(1) if fenced else text[text.find("{") : text.rfind("}") + 1]
    if not candidate:
        raise ValueError(f"no JSON object in model reply: {text[:200]!r}")
    return json.loads(candidate)


def reviewer(llm: "MetaClient", provider: str | None = None) -> "MetaClient":
    """Model for the independent reviewer: REVIEW_PROVIDER (or `provider`) if set, otherwise the
    other provider when its key is present (independent weights), otherwise the same client."""
    wanted = provider or os.getenv("REVIEW_PROVIDER")
    if wanted:
        return MetaClient(provider=wanted)
    other = "baseten" if llm.provider == "meta" else "meta"
    if os.getenv(settings(other)["key_var"]):
        return MetaClient(provider=other)
    return llm
