"""Keyed record fingerprints: HMAC-SHA-256 with a versioned key, never plain hashes.

Format: HMAC-SHA256:<key version>:<hex>. The key (FINGERPRINT_KEY) exists only in the
customer-side worker's environment; it is never stored in a database.
"""
from __future__ import annotations

import hashlib
import hmac
import re

from .detectors import normalise_aadhaar, normalise_phone


def normalise(category: str, value: str) -> str:
    v = value.strip()
    if category == "pan":
        return v.upper()
    if category == "aadhaar":
        return normalise_aadhaar(v)
    if category == "phone":
        return normalise_phone(v)
    if category == "email":
        return v.lower()
    return re.sub(r"\s+", " ", v).lower()


class Fingerprinter:
    def __init__(self, key: bytes, version: str = "v1") -> None:
        if not key or len(key) < 16:
            raise ValueError("FINGERPRINT_KEY missing or too short")
        self._key = key
        self.version = version

    def __call__(self, category: str, value: str) -> str:
        msg = f"{category}:{normalise(category, value)}".encode("utf-8")
        return f"HMAC-SHA256:{self.version}:" + hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def __repr__(self) -> str:  # never leak the key in logs/tracebacks
        return f"Fingerprinter(version={self.version!r}, key=<redacted>)"


FP_RE = re.compile(r"^HMAC-SHA256:v\d+:[0-9a-f]{64}$")
