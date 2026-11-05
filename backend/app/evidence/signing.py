"""Ed25519 signing of evidence manifests.

The private key is read from EVIDENCE_SIGNING_KEY_PATH (a file in a secrets volume) and is
never stored in the database, sent to the frontend, or committed to git. The development
key is generated on first start and labelled DEV-NON-PRODUCTION. Key IDs are versioned
(<label>-<fingerprint prefix>) so keys can be rotated and old packs still verify against the
public key shipped inside them.
"""
from __future__ import annotations

import base64
import hashlib
import os
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..core.config import settings

ALGORITHM = "Ed25519"
DEV_LABEL = "DEV-NON-PRODUCTION"


def ensure_dev_key(path: str) -> None:
    p = Path(path)
    if p.exists():
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    p.write_bytes(pem)
    os.chmod(p, 0o600)
    (p.parent / (p.name + ".label")).write_text(DEV_LABEL)


@lru_cache
def _key() -> Ed25519PrivateKey:
    path = settings().evidence_signing_key_path
    data = Path(path).read_bytes()
    k = serialization.load_pem_private_key(data, password=None)
    if not isinstance(k, Ed25519PrivateKey):
        raise RuntimeError("evidence signing key is not Ed25519")
    return k


def label() -> str:
    p = Path(settings().evidence_signing_key_path + ".label")
    return p.read_text().strip() if p.exists() else "PRODUCTION"


def public_pem() -> bytes:
    return _key().public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def key_id() -> str:
    raw = _key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return f"{label().lower()}-v1-{hashlib.sha256(raw).hexdigest()[:16]}"


def sign(data: bytes) -> str:
    return base64.b64encode(_key().sign(data)).decode()


def verify(data: bytes, signature_b64: str, pub_pem: bytes) -> bool:
    pub = serialization.load_pem_public_key(pub_pem)
    assert isinstance(pub, Ed25519PublicKey)
    try:
        pub.verify(base64.b64decode(signature_b64), data)
        return True
    except Exception:  # noqa: BLE001
        return False
