"""LLM privacy gateway: the only path to any model (including the local template provider).

Before every call:
  1. schema validation - only allowlisted metadata fields; forbidden field names rejected
  2. deterministic outbound DLP - unmasked PAN / Aadhaar candidates, full emails and phones
  3. if anything is found: BLOCK, record a PrivacyPolicyViolation (types + counts + field
     paths only, never the value) and raise
  4. otherwise record exactly which metadata fields were shared, then call the provider
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Any

from mallya_common.canonical import canonical
from mallya_common.detectors import (AADHAAR_IN_TEXT, EMAIL_RE, PAN_HOLDER_TYPES, PAN_IN_TEXT, PHONE_IN_TEXT,
                                     is_aadhaar_candidate)

from ..core.db import session_scope
from ..models import LLMCall, PrivacyViolation
from . import provider as providers

ALLOWED_FIELDS = {
    "task", "incident_ref", "exposure_type", "assets", "asset_refs", "data_categories", "record_count",
    "masked_samples", "facts", "counts", "verdict", "reasons", "root_cause", "timeline", "actions", "locations",
    "residual", "consent", "risk", "regime_context", "status", "decision",
}
FORBIDDEN_FIELD_NAMES = {"rows", "raw", "raw_rows", "full_name", "name", "email", "phone", "pan", "pan_number",
                         "aadhaar", "address", "dob", "content", "body", "subject_fingerprints", "fingerprints"}


class PrivacyPolicyViolation(Exception):
    def __init__(self, rule: str, detectors: dict, paths: list[str]) -> None:
        super().__init__(f"{rule}: blocked outbound LLM payload ({', '.join(f'{k}={v}' for k, v in detectors.items())})")
        self.rule, self.detectors, self.paths = rule, detectors, paths


def _walk(obj: Any, path: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_walk(v, f"{path}.{k}" if path else str(k)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(_walk(v, f"{path}[{i}]"))
    else:
        out.append((path, obj))
    return out


def _keys(obj: Any) -> set[str]:
    ks: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            ks.add(str(k).lower())
            ks |= _keys(v)
    elif isinstance(obj, list):
        for v in obj:
            ks |= _keys(v)
    return ks


def dlp_scan(payload: dict) -> tuple[dict, list[str]]:
    """Deterministic outbound DLP. Returns ({detector: count}, [field paths])."""
    found: dict[str, int] = {}
    paths: list[str] = []
    for path, val in _walk(payload):
        if not isinstance(val, str):
            val = str(val)
        hit = False
        for m in PAN_IN_TEXT.finditer(val):
            if m.group(0)[3] in PAN_HOLDER_TYPES:
                found["pan"] = found.get("pan", 0) + 1
                hit = True
        for m in AADHAAR_IN_TEXT.finditer(val):
            if is_aadhaar_candidate("".join(m.groups())):
                found["aadhaar"] = found.get("aadhaar", 0) + 1
                hit = True
        n = len(EMAIL_RE.findall(val))
        if n:
            found["email"] = found.get("email", 0) + n
            hit = True
        if not re.search(r"HMAC-SHA256:v\d+:", val):  # fingerprint hex never counts as a phone
            n = len(PHONE_IN_TEXT.findall(val))
            if n:
                found["phone"] = found.get("phone", 0) + n
                hit = True
        if hit:
            paths.append(path)
    return found, paths


def validate_schema(payload: dict) -> None:
    unknown = set(payload) - ALLOWED_FIELDS
    if unknown:
        raise PrivacyPolicyViolation("schema_unknown_fields", {"unknown_fields": len(unknown)}, sorted(unknown))
    bad = _keys(payload) & FORBIDDEN_FIELD_NAMES
    if bad:
        raise PrivacyPolicyViolation("schema_forbidden_fields", {"forbidden_fields": len(bad)}, sorted(bad))


def _record_block(agent: str, incident_id: str | None, purpose: str, payload: dict, exc: PrivacyPolicyViolation,
                  is_test: bool) -> None:
    data = canonical(payload)
    with session_scope() as db:
        db.add(LLMCall(agent=agent, incident_id=incident_id, provider=providers.active_name(), model=providers.model_name(),
                       purpose=purpose, shared_fields=[], payload_bytes=len(data),
                       payload_sha256=hashlib.sha256(data).hexdigest(), blocked=True,
                       dlp_findings=exc.detectors, raw_identifiers_sent=0, is_test=is_test))
        db.add(PrivacyViolation(agent=agent, incident_id=incident_id, rule=exc.rule, detectors=exc.detectors,
                                field_paths=exc.paths, action="BLOCKED", is_test=is_test))


def complete(agent: str, purpose: str, payload: dict, *, incident_id: str | None = None, is_test: bool = False) -> str:
    try:
        validate_schema(payload)
        found, paths = dlp_scan(payload)
        if found:
            raise PrivacyPolicyViolation("outbound_dlp_identifier", found, paths)
    except PrivacyPolicyViolation as exc:
        _record_block(agent, incident_id, purpose, payload, exc, is_test)
        raise
    data = canonical(payload)
    shared = sorted({p for p, _ in _walk(payload)})
    t0 = time.monotonic()
    text, used, fallback = providers.generate(purpose, payload)
    with session_scope() as db:
        db.add(LLMCall(agent=agent, incident_id=incident_id, provider=used, model=providers.model_name(),
                       purpose=purpose, shared_fields=shared, payload_bytes=len(data),
                       payload_sha256=hashlib.sha256(data).hexdigest(), blocked=False, dlp_findings={},
                       raw_identifiers_sent=0, latency_ms=round((time.monotonic() - t0) * 1000, 1), fallback=fallback,
                       is_test=is_test))
    return text
