"""LLM provider: grounding check and fallback (no network: _post is replaced)."""
from __future__ import annotations

import httpx
import pytest

from app.privacy import provider

FACTS = {"facts": {"verdict": "ACCESS_ATTEMPTED_NOT_SUCCESSFUL", "external": {"attempts": 3, "successful_downloads": 0}}}


@pytest.fixture
def groq(monkeypatch):
    monkeypatch.setattr(provider, "OVERRIDE", "groq")
    monkeypatch.setattr(provider, "_key", lambda name: "test-key")
    return monkeypatch


def _answer(text):
    return lambda url, headers, body: {"choices": [{"message": {"content": text}}]}


def test_grounded_answer_is_used(groq):
    groq.setattr(provider, "_post", _answer("Three attempts (3) were made and 0 downloads succeeded."))
    text, used, fell_back = provider.generate("investigation.summary", FACTS)
    assert used == "groq" and not fell_back and "3" in text


def test_invented_number_is_rejected(groq):
    groq.setattr(provider, "_post", _answer("5,200 records were downloaded by 4 attackers."))
    text, used, fell_back = provider.generate("investigation.summary", FACTS)
    assert used == "local" and fell_back and "5,200" not in text


@pytest.mark.parametrize("exc", [httpx.ConnectTimeout("t"), provider.ProviderError("HTTP 429"), KeyError("choices")])
def test_provider_failure_falls_back_to_templates(groq, exc):
    def boom(*a, **k):
        raise exc
    groq.setattr(provider, "_post", boom)
    text, used, fell_back = provider.generate("investigation.summary", FACTS)
    assert used == "local" and fell_back and text


def test_missing_key_falls_back(monkeypatch):
    monkeypatch.setattr(provider, "OVERRIDE", "groq")
    monkeypatch.setattr(provider, "_key", lambda name: "")
    _, used, fell_back = provider.generate("investigation.summary", FACTS)
    assert used == "local" and fell_back


def test_groq_request_shape(groq):
    seen = {}

    def capture(url, headers, body):
        seen.update(url=url, auth=headers["authorization"], body=body)
        return {"choices": [{"message": {"content": "3 attempts, 0 downloads."}}]}
    groq.setattr(provider, "_post", capture)
    provider.generate("investigation.summary", FACTS)
    assert seen["url"] == "https://api.groq.com/openai/v1/chat/completions"
    assert seen["auth"] == "Bearer test-key" and seen["body"]["temperature"] == 0
    assert seen["body"]["messages"][0]["role"] == "system"
