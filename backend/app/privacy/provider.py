"""LLM provider abstraction. Only reachable through privacy.gateway.complete().

LLM_PROVIDER=local (default) uses deterministic reasoning templates and needs no API key.
anthropic / openai / groq send the already-validated metadata payload. The model only writes short
decision summaries and draft prose; verdicts, scores and actions are computed deterministically
elsewhere, and the model never triggers an action.

Every remote answer must pass a grounding check (no number that is absent from the facts) or the
deterministic template is used instead. Any provider failure also falls back to the template, and
the gateway records that fallback on the audited call.
"""
from __future__ import annotations

import json
import logging
import re
import time

import httpx

from ..core.config import settings
from . import templates

log = logging.getLogger("mallya.llm")

SYSTEM = ("You edit decision summaries for a data-privacy incident tool. You receive a REFERENCE SUMMARY that was "
          "computed by deterministic code and is authoritative, plus the facts it came from. Rewrite the reference "
          "summary in clear, plain English for a security analyst. Rules: keep every fact, number, name and identifier "
          "exactly as given; do not add facts, causes, speculation, deadlines or legal conclusions; never change who did "
          "what (an attacker, a partner and an internal job are different actors); keep the same verdict words. "
          "At most three sentences. Plain text, no markdown.")

OPENAI_COMPATIBLE = {
    "openai": "https://api.openai.com/v1",
    "groq": "https://api.groq.com/openai/v1",
}
# groq: gpt-oss-120b stayed closest to the given facts in a side-by-side check (2026-11-07).
DEFAULT_MODELS = {"anthropic": "claude-sonnet-5-5", "openai": "gpt-4.1-mini", "groq": "openai/gpt-oss-120b"}
RETRY_STATUS = {429, 500, 502, 503, 504}

OVERRIDE: str | None = None  # set only by the benchmark's deterministic-vs-LLM comparison


class ProviderError(Exception):
    pass


def active_name() -> str:
    return OVERRIDE or settings().llm_provider or "local"


def model_name() -> str | None:
    if active_name() == "local":
        return "deterministic-templates-v1"
    return settings().llm_model or DEFAULT_MODELS.get(active_name())


def _key(name: str) -> str:
    s = settings()
    return {"anthropic": s.anthropic_api_key, "openai": s.openai_api_key, "groq": s.groq_api_key}.get(name, "")


def _post(url: str, headers: dict, body: dict) -> dict:
    """POST with one retry on rate limits / transient server errors. Never logs the payload or the key."""
    for attempt in (1, 2):
        r = httpx.post(url, headers=headers, json=body, timeout=httpx.Timeout(20.0, connect=5.0))
        if r.status_code in RETRY_STATUS and attempt == 1:
            time.sleep(min(float(r.headers.get("retry-after", "1") or 1), 3.0))
            continue
        if r.status_code >= 400:
            raise ProviderError(f"HTTP {r.status_code}")
        return r.json()
    raise ProviderError("retry exhausted")


def _anthropic(prompt: str) -> str:
    data = _post("https://api.anthropic.com/v1/messages",
                 {"x-api-key": _key("anthropic"), "anthropic-version": "2023-06-01", "content-type": "application/json"},
                 {"model": model_name(), "max_tokens": 300, "system": SYSTEM,
                  "messages": [{"role": "user", "content": prompt}]})
    return "".join(b.get("text", "") for b in data.get("content", [])).strip()


def _openai_compatible(name: str, prompt: str) -> str:
    body = {"model": model_name(), "max_tokens": 600, "temperature": 0,
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}]}
    if "gpt-oss" in (model_name() or ""):
        body["reasoning_effort"] = "low"  # reasoning models spend tokens thinking; keep summaries fast
    data = _post(f"{OPENAI_COMPATIBLE[name]}/chat/completions",
                 {"authorization": f"Bearer {_key(name)}", "content-type": "application/json"}, body)
    return (data["choices"][0]["message"]["content"] or "").strip()


_NUM = re.compile(r"\d[\d,]*(?:\.\d+)?")


def _numbers(text: str) -> set[str]:
    return {n.replace(",", "").rstrip(".") for n in _NUM.findall(text)}


def grounded(text: str, payload: dict, local: str) -> bool:
    """Every number the model writes must appear in the facts (or the deterministic summary)."""
    allowed = _numbers(json.dumps(payload, default=str)) | _numbers(local)
    return _numbers(text) <= allowed


def generate(purpose: str, payload: dict) -> tuple[str, str, bool]:
    """Returns (text, provider_used, fell_back_to_local)."""
    local = templates.render(purpose, payload)
    name = active_name()
    if name == "local":
        return local, "local", False
    if name not in DEFAULT_MODELS or not _key(name):
        log.warning("llm provider %s not configured; using local templates", name)
        return local, "local", True
    prompt = (f"Task: {purpose}\nREFERENCE SUMMARY (authoritative):\n{local}\n\n"
              f"Facts (JSON, for context only):\n{json.dumps(payload, sort_keys=True, default=str)}")
    try:
        text = _anthropic(prompt) if name == "anthropic" else _openai_compatible(name, prompt)
    except (httpx.HTTPError, ProviderError, KeyError, IndexError, TypeError, ValueError) as exc:
        log.warning("llm provider %s failed (%s); using local templates", name, type(exc).__name__ if not isinstance(exc, ProviderError) else exc)
        return local, "local", True
    if not text or not grounded(text, payload, local):
        log.warning("llm provider %s answer rejected by grounding check; using local templates", name)
        return local, "local", True
    return text, name, False
