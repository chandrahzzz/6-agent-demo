"""Thin clients for sandbox services the customer side talks to."""
from __future__ import annotations

import httpx

from .config import settings


def iam(method: str, path: str, **kw):
    s = settings()
    r = httpx.request(method, f"{s.mock_iam_url}{path}", headers={"X-Mock-IAM-Token": s.mock_iam_token}, timeout=15, **kw)
    r.raise_for_status()
    return r.json()


def vendor(method: str, path: str, **kw):
    s = settings()
    r = httpx.request(method, f"{s.mock_vendor_url}{path}", headers={"X-Mock-Vendor-Token": s.mock_vendor_token,
                                                                       "X-Api-Key-Id": "meridian-prod-key-01"},
                      timeout=20, **kw)
    r.raise_for_status()
    return r.json()


def cdn_admin(method: str, path: str, **kw):
    s = settings()
    r = httpx.request(method, f"{s.cdn_admin_url}{path}", headers={"X-CDN-Admin-Token": s.cdn_admin_token}, timeout=20, **kw)
    r.raise_for_status()
    return r.json()
