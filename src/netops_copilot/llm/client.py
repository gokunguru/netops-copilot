"""Thin client for Meta Model API. Endpoint and payload to confirm against the official docs."""

import os

import httpx
from dotenv import load_dotenv

load_dotenv()


class MetaClient:
    def __init__(self) -> None:
        self.api_key = os.environ["META_API_KEY"]
        self.base_url = os.environ["META_API_BASE_URL"].rstrip("/")
        self.model = os.getenv("META_MODEL", "muse-spark")

    def chat(self, messages: list[dict], **kwargs) -> str:
        # TODO: align path, payload and response parsing with the Meta Model API quickstart.
        resp = httpx.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={"model": self.model, "messages": messages, **kwargs},
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
