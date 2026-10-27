"""Client for Meta Model API (OpenAI-compatible Chat Completions endpoint)."""

import json
import os
import re
from typing import Protocol

import httpx
from dotenv import load_dotenv

load_dotenv()

DEFAULT_BASE_URL = "https://api.meta.ai/v1"
DEFAULT_MODEL = "muse-spark-1.3"


class LLM(Protocol):
    def chat(self, messages: list[dict], **kwargs) -> str: ...


class MetaClient:
    def __init__(self, api_key: str | None = None, model: str | None = None) -> None:
        self.api_key = api_key or os.environ.get("META_API_KEY", "")
        if not self.api_key:
            raise RuntimeError("META_API_KEY is not set (see .env.example), or run with --mock")
        self.base_url = os.getenv("META_API_BASE_URL") or DEFAULT_BASE_URL
        self.model = model or os.getenv("META_MODEL") or DEFAULT_MODEL
        self.max_tokens = int(os.getenv("MAX_TOKENS", "2048"))

    def chat(self, messages: list[dict], **kwargs) -> str:
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0,
            "max_tokens": self.max_tokens,  # hard cap per call, protects the credits
            **kwargs,
        }
        resp = httpx.post(
            f"{self.base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


def extract_json(text: str) -> dict:
    """Parse a JSON object from a model reply, tolerating code fences or surrounding prose."""
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidate = fenced.group(1) if fenced else text[text.find("{") : text.rfind("}") + 1]
    if not candidate:
        raise ValueError(f"no JSON object in model reply: {text[:200]!r}")
    return json.loads(candidate)
