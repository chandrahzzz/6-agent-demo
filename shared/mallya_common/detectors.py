"""Deterministic identifier detectors. The LLM is never the detector.

Outcomes for PAN-shaped values (SPEC 7.2):
  FORMAT_MATCH                   - matches ^[A-Z]{5}[0-9]{4}[A-Z]$ only
  STRUCTURAL_MATCH               - format + valid 4th-character holder type
  CONFIRMED_SYNTHETIC_TEST_VALUE - structural + present in the sandbox's synthetic fixture registry
A pattern match is never a claim that a value is a real PAN.

Column context decides whether a structurally valid value is treated as a customer
identifier: SKU codes and test-fixture columns that happen to be PAN-shaped are not.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from .verhoeff import checksum_ok

PAN_RE = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$")
PAN_IN_TEXT = re.compile(r"(?<![A-Z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Z0-9])")
PAN_HOLDER_TYPES = frozenset("PCHFATBLJG")
AADHAAR_IN_TEXT = re.compile(r"(?<!\d)([2-9]\d{3})[ -]?(\d{4})[ -]?(\d{4})(?!\d)")
EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w-])")
PHONE_IN_TEXT = re.compile(r"(?<!\d)(?:\+?91[ -]?)?([6-9]\d{4})[ -]?(\d{5})(?!\d)")

FORMAT_MATCH = "FORMAT_MATCH"
STRUCTURAL_MATCH = "STRUCTURAL_MATCH"
CONFIRMED_SYNTHETIC_TEST_VALUE = "CONFIRMED_SYNTHETIC_TEST_VALUE"

# Column / container name tokens that raise or lower the chance a value is a customer identifier.
_POSITIVE = {
    "pan": 0.6, "pan_number": 0.7, "tax_id": 0.6, "permanent_account": 0.7, "aadhaar": 0.7, "uid": 0.3,
    "kyc": 0.4, "customer": 0.3, "customers": 0.3, "holder": 0.2, "email": 0.6, "mail": 0.4,
    "phone": 0.6, "mobile": 0.6, "msisdn": 0.6, "contact": 0.3, "backup": 0.2, "patient": 0.3,
}
_NEGATIVE = {
    "sku": -0.9, "product": -0.6, "products": -0.6, "item": -0.4, "part": -0.4, "invoice": -0.8,
    "order": -0.5, "catalog": -0.6, "inventory": -0.6, "test": -0.5, "qa": -0.6, "fixture": -0.7,
    "label": -0.4, "sample": -0.3, "code": -0.3, "serial": -0.6, "batch": -0.4, "ref": -0.2,
}
_TEXT_KEYWORDS = {
    "pan": ("pan", "permanent account", "tax id"),
    "aadhaar": ("aadhaar", "aadhar", "uid", "uidai"),
}


def _tokens(*names: str | None) -> list[str]:
    out: list[str] = []
    for n in names:
        if n:
            out.extend(t for t in re.split(r"[^a-z0-9]+", n.lower().replace("-", "_")) if t)
            out.append(n.lower())
    return out


def context_score(column: str | None, container: str | None = None, sibling_columns: Iterable[str] = ()) -> float:
    """0.0 (certainly not customer data) .. 1.0 (certainly customer data). Deterministic."""
    score = 0.5
    toks = _tokens(column)
    ctoks = _tokens(container)
    for t in toks:
        score += _POSITIVE.get(t, 0.0) * 0.6 + _NEGATIVE.get(t, 0.0) * 0.6
    for t in ctoks:
        score += _POSITIVE.get(t, 0.0) * 0.25 + _NEGATIVE.get(t, 0.0) * 0.35
    sib = set(_tokens(*sibling_columns))
    pii_siblings = len(sib & {"name", "full_name", "email", "phone", "dob", "address", "mobile"})
    score += min(pii_siblings, 3) * 0.06
    return max(0.0, min(1.0, round(score, 3)))


def classify_pan(value: str, synthetic_registry: set[str] | None = None, fingerprint: str | None = None) -> str | None:
    v = value.strip().upper()
    if not PAN_RE.match(v):
        return None
    if v[3] not in PAN_HOLDER_TYPES:
        return FORMAT_MATCH
    if synthetic_registry is not None and fingerprint is not None and fingerprint in synthetic_registry:
        return CONFIRMED_SYNTHETIC_TEST_VALUE
    return STRUCTURAL_MATCH


def normalise_aadhaar(value: str) -> str:
    return re.sub(r"[ -]", "", value.strip())


def is_aadhaar_candidate(value: str) -> bool:
    d = normalise_aadhaar(value)
    return len(d) == 12 and d.isdigit() and d[0] not in "01" and checksum_ok(d)


def normalise_phone(value: str) -> str:
    d = re.sub(r"\D", "", value)
    return d[-10:]


def is_phone(value: str) -> bool:
    d = re.sub(r"\D", "", value)
    if len(d) == 12 and d.startswith("91"):
        d = d[2:]
    return len(d) == 10 and d[0] in "6789"


def is_email(value: str) -> bool:
    return bool(EMAIL_RE.fullmatch(value.strip()))


@dataclass
class ColumnVerdict:
    column: str
    category: str | None  # pan | aadhaar | email | phone | None
    outcome: str | None
    matched: int
    total: int
    context: float
    is_customer_identifier: bool
    reasons: list[str] = field(default_factory=list)


def classify_column(column: str, values: list[str], container: str | None = None,
                    siblings: Iterable[str] = ()) -> ColumnVerdict:
    """Decide what (if anything) a column holds, from values + context. Values never leave this function."""
    vals = [str(v) for v in values if v not in (None, "")]
    total = len(vals)
    ctx = context_score(column, container, siblings)
    if total == 0:
        return ColumnVerdict(column, None, None, 0, 0, ctx, False, ["empty"])
    pan_fmt = [v for v in vals if PAN_RE.match(v.strip().upper())]
    pan_struct = [v for v in pan_fmt if v.strip().upper()[3] in PAN_HOLDER_TYPES]
    aad_shape = [v for v in vals if re.fullmatch(r"\d{4}[ -]?\d{4}[ -]?\d{4}", v.strip())]
    aad_ok = [v for v in aad_shape if is_aadhaar_candidate(v)]
    emails = [v for v in vals if is_email(v)]
    phones = [v for v in vals if is_phone(v)]
    reasons: list[str] = []

    if len(pan_fmt) / total >= 0.8:
        struct_ratio = len(pan_struct) / max(len(pan_fmt), 1)
        reasons.append(f"{len(pan_fmt)}/{total} PAN-format; {len(pan_struct)} with valid holder type")
        # Real PAN columns are ~100% structurally valid; random codes are ~10/26.
        structural = struct_ratio >= 0.95
        outcome = STRUCTURAL_MATCH if structural else FORMAT_MATCH
        flagged = structural and ctx >= 0.5
        reasons.append(f"context score {ctx}")
        return ColumnVerdict(column, "pan", outcome, len(pan_struct if structural else pan_fmt), total, ctx, flagged, reasons)
    if len(aad_shape) / total >= 0.8:
        ok_ratio = len(aad_ok) / max(len(aad_shape), 1)
        reasons.append(f"{len(aad_shape)}/{total} 12-digit; {len(aad_ok)} pass Verhoeff + leading-digit rule")
        reasons.append(f"context score {ctx}")
        flagged = ok_ratio >= 0.95 and ctx >= 0.45
        return ColumnVerdict(column, "aadhaar", "VERHOEFF_VALID" if ok_ratio >= 0.95 else "CHECKSUM_FAIL",
                             len(aad_ok), total, ctx, flagged, reasons)
    if len(emails) / total >= 0.8:
        return ColumnVerdict(column, "email", "EMAIL", len(emails), total, ctx, ctx >= 0.35,
                             [f"{len(emails)}/{total} email-shaped", f"context score {ctx}"])
    if len(phones) / total >= 0.8:
        return ColumnVerdict(column, "phone", "PHONE", len(phones), total, ctx, ctx >= 0.35,
                             [f"{len(phones)}/{total} phone-shaped", f"context score {ctx}"])
    return ColumnVerdict(column, None, None, 0, total, ctx, False, ["no identifier pattern"])


@dataclass
class TextHit:
    category: str
    value: str  # raw - stays inside the worker
    start: int
    context: float


def scan_text(text: str) -> list[TextHit]:
    """Find identifiers in free text using a keyword window for context."""
    hits: list[TextHit] = []
    low = text.lower()

    def window(start: int, end: int) -> str:
        return low[max(0, start - 40): end + 10]

    for m in PAN_IN_TEXT.finditer(text):
        v = m.group(0)
        if v[3] not in PAN_HOLDER_TYPES:
            continue
        w = window(m.start(), m.end())
        ctx = 0.9 if any(k in w for k in _TEXT_KEYWORDS["pan"]) else 0.3
        if any(k in w for k in ("sku", "product", "invoice", "part no")):
            ctx = 0.1
        hits.append(TextHit("pan", v, m.start(), ctx))
    for m in AADHAAR_IN_TEXT.finditer(text):
        v = "".join(m.groups())
        if not is_aadhaar_candidate(v):
            continue
        w = window(m.start(), m.end())
        ctx = 0.9 if any(k in w for k in _TEXT_KEYWORDS["aadhaar"]) else 0.4
        if "invoice" in w:
            ctx = 0.1
        hits.append(TextHit("aadhaar", v, m.start(), ctx))
    for m in EMAIL_RE.finditer(text):
        hits.append(TextHit("email", m.group(0), m.start(), 0.7))
    return hits
