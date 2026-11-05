"""LLM provider abstraction. Only reachable through privacy.gateway.complete().

LLM_PROVIDER=local (default) uses deterministic reasoning templates and needs no API key.
anthropic / openai send the already-validated metadata payload. The model only writes short
decision summaries and draft prose; verdicts, scores and actions are computed
deterministically elsewhere, and the model never triggers an action.
"""
from __future__ import annotations

import json

import httpx

from ..core.config import settings
from . import templates

SYSTEM = ("You write short, factual decision summaries for a data-privacy incident tool. Use ONLY the facts "
          "provided. Do not speculate, do not invent numbers, deadlines or legal conclusions. Two sentences max.")


def active_name() -> str:
    return settings().llm_provider or "local"


def model_name() -> str | None:
    s = settings()
    if active_name() == "local":
        return "deterministic-templates-v1"
    return s.llm_model or {"anthropic": "claude-sonnet-5-5", "openai": "gpt-4.1-mini"}.get(active_name())


def _anthropic(prompt: str) -> str:
    s = settings()
    r = httpx.post("https://api.anthropic.com/v1/messages", timeout=30, headers={
        "x-api-key": s.anthropic_api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        json={"model": model_name(), "max_tokens": 300, "system": SYSTEM,
              "messages": [{"role": "user", "content": prompt}]})
    r.raise_for_status()
    return "".join(b.get("text", "") for b in r.json().get("content", [])).strip()


def _openai(prompt: str) -> str:
    s = settings()
    r = httpx.post("https://api.openai.com/v1/chat/completions", timeout=30,
                   headers={"authorization": f"Bearer {s.openai_api_key}"},
                   json={"model": model_name(), "max_tokens": 300,
                         "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}]})
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"].strip()


def generate(purpose: str, payload: dict) -> tuple[str, str, bool]:
    """Returns (text, provider_used, fell_back_to_local)."""
    local = templates.render(purpose, payload)
    name = active_name()
    if name == "local":
        return local, "local", False
    prompt = f"Task: {purpose}\nFacts (JSON):\n{json.dumps(payload, sort_keys=True, default=str)}"
    try:
        if name == "anthropic" and settings().anthropic_api_key:
            return _anthropic(prompt) or local, "anthropic", False
        if name == "openai" and settings().openai_api_key:
            return _openai(prompt) or local, "openai", False
    except httpx.HTTPError:
        pass
    return local, "local", True
