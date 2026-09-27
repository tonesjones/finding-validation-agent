"""Swappable model clients. The assessor only depends on the ModelClient protocol, so a
local/self-hosted model can replace the hosted API without touching reasoning code."""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Protocol


class ModelClient(Protocol):
    model_id: str

    def complete(self, system: str, user: str, *, max_tokens: int = 2000) -> str: ...


class AnthropicClient:
    """Claude via the Messages API. Key from ANTHROPIC_API_KEY. Temperature 0 for reproducibility."""

    def __init__(self, model_id: str = "claude-sonnet-5", api_key: str | None = None,
                 base_url: str = "https://api.anthropic.com"):
        self.model_id = model_id
        self._key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self._key:
            raise SystemExit("Set ANTHROPIC_API_KEY to use AnthropicClient")
        self._url = base_url.rstrip("/") + "/v1/messages"

    def complete(self, system: str, user: str, *, max_tokens: int = 2000) -> str:
        body = {"model": self.model_id, "max_tokens": max_tokens, "temperature": 0, "system": system,
                "messages": [{"role": "user", "content": user}]}
        req = urllib.request.Request(self._url, json.dumps(body).encode(), {
            "x-api-key": self._key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            msg = json.loads(r.read())
        return "".join(b.get("text", "") for b in msg.get("content", []) if b.get("type") == "text")


class OpenAICompatibleClient:
    """Any OpenAI-compatible chat endpoint (vLLM, Ollama, LM Studio...) for local/self-hosted models."""

    def __init__(self, model_id: str, base_url: str, api_key: str | None = None):
        self.model_id = model_id
        self._url = base_url.rstrip("/") + "/v1/chat/completions"
        self._key = api_key or os.environ.get("FVA_LOCAL_MODEL_KEY", "")

    def complete(self, system: str, user: str, *, max_tokens: int = 2000) -> str:
        body = {"model": self.model_id, "max_tokens": max_tokens, "temperature": 0,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        h = {"content-type": "application/json", **({"authorization": f"Bearer {self._key}"} if self._key else {})}
        with urllib.request.urlopen(urllib.request.Request(self._url, json.dumps(body).encode(), h), timeout=300) as r:
            return json.loads(r.read())["choices"][0]["message"]["content"]


class ScriptedClient:
    """Deterministic client for tests: returns queued responses in order."""

    def __init__(self, responses: list[str], model_id: str = "scripted"):
        self.model_id, self._responses, self.prompts = model_id, list(responses), []

    def complete(self, system: str, user: str, *, max_tokens: int = 2000) -> str:
        self.prompts.append((system, user))
        return self._responses.pop(0)
