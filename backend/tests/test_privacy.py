"""Privacy boundary unit suite (SPEC 7.5). Leak scans over logs/telemetry/exports run in
tools/privacy_suite.py, inside the worker, against the real sandbox identifiers."""
from __future__ import annotations

import random

import pytest
from sqlalchemy import select

from app.core.db import session_scope
from app.models import LLMCall, PrivacyViolation
from app.privacy import gateway, provider
from mallya_common.detectors import (CONFIRMED_SYNTHETIC_TEST_VALUE, FORMAT_MATCH, STRUCTURAL_MATCH, classify_column,
                                     classify_pan, is_aadhaar_candidate)
from mallya_common.fingerprint import FP_RE, Fingerprinter
from mallya_common.masking import mask_aadhaar, mask_email, mask_pan, mask_phone
from mallya_common.verhoeff import check_digit, checksum_ok

pytestmark = pytest.mark.privacy
R = random.Random(7)
L = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def pan(holder="P") -> str:
    return "".join(R.choice(L) for _ in range(3)) + holder + R.choice(L) + "".join(R.choice("0123456789") for _ in range(4)) + R.choice(L)


def aadhaar() -> str:
    p = R.choice("23456789") + "".join(R.choice("0123456789") for _ in range(10))
    return p + check_digit(p)


def test_01_pan_detection():
    vals = [pan() for _ in range(100)]
    v = classify_column("pan_number", vals, "customers", ["full_name", "email"])
    assert v.category == "pan" and v.is_customer_identifier and v.matched == 100


def test_02_pan_structure_outcomes():
    assert classify_pan("ABCDE1234F") == FORMAT_MATCH  # 4th char 'D' is not a holder type
    assert classify_pan("ABCPE1234F") == STRUCTURAL_MATCH
    assert classify_pan("abcpe1234f") == STRUCTURAL_MATCH
    assert classify_pan("ABCPE1234") is None
    f = Fingerprinter(b"k" * 32)
    assert classify_pan("ABCPE1234F", {f("pan", "ABCPE1234F")}, f("pan", "ABCPE1234F")) == CONFIRMED_SYNTHETIC_TEST_VALUE


def test_03_verhoeff():
    assert checksum_ok("2363") and not checksum_ok("2364")
    a = aadhaar()
    assert is_aadhaar_candidate(a) and is_aadhaar_candidate(f"{a[:4]} {a[4:8]} {a[8:]}")
    assert not is_aadhaar_candidate("1" + a[1:])  # leading 0/1 excluded
    bad = a[:-1] + str((int(a[-1]) + 1) % 10)
    assert not is_aadhaar_candidate(bad)


def test_04_decoys_not_flagged():
    skus = ["".join(R.choice(L) for _ in range(5)) + "".join(R.choice("0123456789") for _ in range(4)) + R.choice(L) for _ in range(300)]
    assert not classify_column("sku", skus, "products.csv").is_customer_identifier
    qa = [pan("P") for _ in range(120)]
    assert not classify_column("label_code", qa, "qa_fixture_cases", ["test_case_id", "expected_result"]).is_customer_identifier
    inv = []
    while len(inv) < 200:
        n = R.choice("23456789") + "".join(R.choice("0123456789") for _ in range(11))
        if not checksum_ok(n):
            inv.append(n)
    assert not classify_column("invoice_number", inv, "invoices.csv").is_customer_identifier


def test_05_masking():
    assert mask_pan("ABCPE1234F") == "ABCPE*****"
    a = aadhaar()
    assert mask_aadhaar(a) == "XXXX XXXX " + a[-4:]
    assert mask_phone("+91 9876543210") == "******3210"
    assert mask_email("kavya.r@meridian-customer.test") == "k***@meridian-customer.test"
    for m in (mask_pan("ABCPE1234F"), mask_aadhaar(a)):
        found, _ = gateway.dlp_scan({"facts": {"sample": m}})
        assert not found


def test_06_fingerprint_match_across_datasets():
    f = Fingerprinter(b"test-key-not-the-real-one-000000")
    assert f("pan", "abcpe1234f ") == f("pan", "ABCPE1234F")
    assert f("phone", "+91 98765 43210") == f("phone", "9876543210")
    assert f("email", "A@B.test") == f("email", "a@b.test")
    assert FP_RE.match(f("pan", "ABCPE1234F"))


def test_07_different_ids_different_fingerprints():
    f = Fingerprinter(b"test-key-not-the-real-one-000000")
    fps = {f("pan", pan()) for _ in range(2000)}
    assert len(fps) == 2000
    g = Fingerprinter(b"another-key-000000000000000000000")
    assert f("pan", "ABCPE1234F") != g("pan", "ABCPE1234F")  # keyed, not a plain hash
    assert "key" not in repr(f).replace("key=<redacted>", "")


def _blocked(payload: dict) -> gateway.PrivacyPolicyViolation:
    with pytest.raises(gateway.PrivacyPolicyViolation) as ei:
        gateway.complete("pytest", "test.summary", payload, is_test=True)
    return ei.value


def test_08_no_raw_pan_in_llm_payload():
    raw = pan()
    exc = _blocked({"facts": {"note": f"customer {raw} found"}})
    assert exc.detectors.get("pan") == 1 and raw not in str(exc) and raw not in str(exc.paths)
    with session_scope() as db:
        v = db.execute(select(PrivacyViolation).order_by(PrivacyViolation.ts.desc())).scalars().first()
        assert v.is_test and v.action == "BLOCKED" and raw not in str(v.detectors) + str(v.field_paths)
        c = db.execute(select(LLMCall).order_by(LLMCall.ts.desc())).scalars().first()
        assert c.blocked and c.raw_identifiers_sent == 0


def test_09_no_raw_aadhaar_in_llm_payload():
    raw = aadhaar()
    exc = _blocked({"facts": {"rows": None, "x": f"{raw[:4]} {raw[4:8]} {raw[8:]}"}}) if False else \
        _blocked({"facts": {"x": f"{raw[:4]} {raw[4:8]} {raw[8:]}"}})
    assert exc.detectors.get("aadhaar") == 1 and raw not in str(exc)


def test_13_gateway_blocks_unsafe_payloads(monkeypatch):
    # deterministic wording for the assertion below; the live provider is exercised by the E2E drills
    monkeypatch.setattr(provider, "OVERRIDE", "local")
    assert _blocked({"facts": {"contact": "someone@meridian-customer.test"}}).detectors.get("email")
    assert _blocked({"facts": {"m": "+91 9876543210"}}).detectors.get("phone")
    assert _blocked({"rows": [["a", "b"]]}).rule == "schema_unknown_fields"
    assert _blocked({"facts": {"full_name": "Arvani Kelthar"}}).rule == "schema_forbidden_fields"
    # a safe payload passes and records exactly which fields were shared
    out = gateway.complete("pytest", "blast.summary", {"facts": {"record_count": 5, "categories": ["pan"],
                                                                  "masked": "ABCPE*****"}}, is_test=True)
    assert "5 records" in out
    with session_scope() as db:
        c = db.execute(select(LLMCall).where(LLMCall.blocked.is_(False)).order_by(LLMCall.ts.desc())).scalars().first()
        assert c.shared_fields == ["facts.categories[0]", "facts.masked", "facts.record_count"]
        assert c.raw_identifiers_sent == 0
