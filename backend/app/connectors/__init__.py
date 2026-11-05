"""Connectors from the control plane to the (MOCK/SANDBOX) customer environment.

The control plane holds no customer-data credentials: storage, database and vendor access
all go through the customer-side worker, which returns metadata only.
"""
from __future__ import annotations

import httpx

from ..core.config import settings


class ConnectorError(Exception):
    pass


def _call(method: str, url: str, headers: dict, timeout: float = 60.0, **kw):
    try:
        r = httpx.request(method, url, headers=headers, timeout=timeout, **kw)
    except httpx.HTTPError as exc:
        raise ConnectorError(f"{type(exc).__name__} calling {httpx.URL(url).host}") from exc
    if r.status_code >= 400:
        try:
            detail = r.json().get("detail") or r.json().get("error")
        except ValueError:
            detail = r.text[:200]
        raise ConnectorError(f"{httpx.URL(url).host} returned {r.status_code}: {detail}")
    return r.json()


def worker(method: str, path: str, timeout: float = 120.0, **kw):
    s = settings()
    return _call(method, f"{s.worker_url}{path}", {"X-Worker-Token": s.worker_token}, timeout, **kw)


def verifier(method: str, path: str, **kw):
    s = settings()
    return _call(method, f"{s.probe_gateway_url}/verifier{path}", {"X-Probe-Token": s.probe_token}, 180.0, **kw)


def attacker(method: str, path: str, **kw):
    s = settings()
    return _call(method, f"{s.probe_gateway_url}/attacker{path}", {"X-Probe-Token": s.probe_token}, 180.0, **kw)


def cdn_admin(method: str, path: str, **kw):
    s = settings()
    return _call(method, f"{s.cdn_admin_url}{path}", {"X-CDN-Admin-Token": s.cdn_admin_token}, 30.0, **kw)


def iam(method: str, path: str, **kw):
    s = settings()
    return _call(method, f"{s.mock_iam_url}{path}", {"X-Mock-IAM-Token": s.mock_iam_token}, 30.0, **kw)


CONNECTORS = [
    {"name": "worker", "label": "Customer-side worker", "mode": "SANDBOX"},
    {"name": "minio", "label": "Object storage (MinIO)", "mode": "SANDBOX"},
    {"name": "nginx-cdn", "label": "Edge CDN (nginx proxy_cache)", "mode": "SANDBOX"},
    {"name": "cdn-admin", "label": "CDN admin sidecar", "mode": "SANDBOX"},
    {"name": "mock-iam", "label": "Identity & access (mock IAM)", "mode": "MOCK"},
    {"name": "mock-vendor", "label": "Vendor APIs (Northwind, QuickSummarize)", "mode": "MOCK"},
    {"name": "verifier", "label": "External verifier probe", "mode": "SANDBOX"},
    {"name": "attacker", "label": "Scripted attacker", "mode": "SANDBOX"},
    {"name": "infra-config", "label": "infra-config git repository", "mode": "SANDBOX"},
]
