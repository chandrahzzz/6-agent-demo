"""Canonical JSON (sorted keys, UTF-8, no insignificant whitespace) + SHA-256 helpers."""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def chain_hash(metadata: dict, payload_hash: str, previous_event_hash: str) -> str:
    """event_hash = SHA256(canonical(metadata + payload_hash + previous_event_hash)) (SPEC 8)."""
    return sha256_hex(canonical({"metadata": metadata, "payload_hash": payload_hash,
                                 "previous_event_hash": previous_event_hash}))
