"""Masking: the only form in which an identifier may ever appear outside the worker."""
from __future__ import annotations

import re


def mask_pan(v: str) -> str:
    v = v.strip().upper()
    return v[:5] + "*****" if len(v) == 10 else "**********"


def mask_aadhaar(v: str) -> str:
    d = re.sub(r"\D", "", v)
    return "XXXX XXXX " + d[-4:] if len(d) == 12 else "XXXX XXXX XXXX"


def mask_phone(v: str) -> str:
    d = re.sub(r"\D", "", v)[-10:]
    return "******" + d[-4:] if len(d) == 10 else "**********"


def mask_email(v: str) -> str:
    local, _, domain = v.strip().partition("@")
    return (local[:1] + "***@" + domain) if domain else "***"


def mask(category: str, v: str) -> str:
    return {"pan": mask_pan, "aadhaar": mask_aadhaar, "phone": mask_phone, "email": mask_email}.get(
        category, lambda _: "[REDACTED]")(v)
