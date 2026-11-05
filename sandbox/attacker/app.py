"""Scripted attacker (SANDBOX). Lives only on external_net and can reach nothing but the
public CDN edge (nginx). Runs per-variant request scripts so access logs contain real traffic.

Variant A - attempts, no download: anonymous LIST, GET of a wrong key, HEAD of the real object.
            Zero bytes of the real object are served.
Variant B - confirmed download: anonymous GET of the real object (bytes transferred).

The attacker reads and discards response bodies: it counts bytes, never stores content.
Results are returned to the drill harness only; agents never read them (they use logs).
"""
from __future__ import annotations

import os
import time

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

CDN = os.environ.get("CDN_URL", "http://cdn.meridian.sandbox:8080")
TOKEN = os.environ.get("PROBE_TOKEN", "")
UA = "Mozilla/5.0 (compatible; bucket-scan/0.9)"
app = FastAPI(title="attacker (SANDBOX)", version="1.0")


def auth(x_probe_token: str = Header(default="")) -> None:
    if not TOKEN or x_probe_token != TOKEN:
        raise HTTPException(status_code=401, detail="invalid probe token")


class Target(BaseModel):
    bucket: str
    key: str


class RunRequest(BaseModel):
    variant: str  # "A" | "B" | "none"
    targets: list[Target]


def _req(client: httpx.Client, method: str, path: str) -> dict:
    t0 = time.monotonic()
    try:
        with client.stream(method, CDN + path, headers={"User-Agent": UA}) as r:
            n = sum(len(chunk) for chunk in r.iter_bytes())
            return {"method": method, "path": path, "status": r.status_code, "bytes": n,
                    "cache": r.headers.get("x-cache-status"), "ms": round((time.monotonic() - t0) * 1000)}
    except httpx.HTTPError as exc:
        return {"method": method, "path": path, "status": None, "bytes": 0, "error": type(exc).__name__}


@app.get("/health")
def health() -> dict:
    return {"ok": True, "service": "attacker", "sandbox": True}


@app.post("/run", dependencies=[Depends(auth)])
def run(req: RunRequest) -> dict:
    results: list[dict] = []
    with httpx.Client(timeout=10.0) as client:
        for t in req.targets:
            if req.variant == "A":
                results.append(_req(client, "GET", f"/{t.bucket}/?list-type=2"))
                stem = t.key.rsplit(".", 1)[0]
                results.append(_req(client, "GET", f"/{t.bucket}/{stem}-old.bak"))
                results.append(_req(client, "HEAD", f"/{t.bucket}/{t.key}"))
            elif req.variant == "B":
                results.append(_req(client, "GET", f"/{t.bucket}/{t.key}"))
    return {"variant": req.variant, "requests": results}
