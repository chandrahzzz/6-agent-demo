"""Mock IAM (SANDBOX / MOCK).

Holds Meridian Bank's principals (service accounts backed by real MinIO users), an IAM /
policy-change event log, a registry of known network origins, and issues presigned URLs
for the authorised consumer (reporting-service) so the verifier can prove legitimate
access still works after a fix.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from minio import Minio
from pydantic import BaseModel, Field

STATE = Path(os.environ.get("STATE_DIR", "/state")) / "iam.json"
TOKEN = os.environ.get("MOCK_IAM_TOKEN", "")
PUBLIC_ENDPOINT = os.environ.get("CDN_PUBLIC_ENDPOINT", "cdn.meridian.sandbox:8080")
_lock = threading.Lock()
app = FastAPI(title="Mock IAM (SANDBOX)", version="1.0")


def auth(x_mock_iam_token: str = Header(default="")) -> None:
    if not TOKEN or x_mock_iam_token != TOKEN:
        raise HTTPException(status_code=401, detail="invalid mock-iam token")


def _load() -> dict:
    if STATE.exists():
        return json.loads(STATE.read_text())
    return {"principals": {}, "events": [], "networks": [], "next_event_id": 1}


def _save(state: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True))
    tmp.replace(STATE)


class Principal(BaseModel):
    name: str
    kind: str = "service"  # service | human | partner | pipeline
    description: str = ""
    access_key: str | None = None
    secret_key: str | None = Field(default=None, repr=False)
    permissions: list[dict] = []  # [{"bucket": ..., "actions": ["s3:GetObject"]}]
    credential_expires_at: str | None = None
    approved: bool = True
    source_ips: list[str] = []


class Event(BaseModel):
    ts: str | None = None
    type: str  # e.g. BucketPolicyChanged, CredentialIssued, PrincipalCreated
    principal: str
    target: str
    details: dict = {}
    synthetic_history: bool = False


class NetworkOrigin(BaseModel):
    cidr: str
    label: str
    zone: str  # internal | partner | probe | external
    role: str = "consumer"  # consumer | infrastructure | security


class PresignRequest(BaseModel):
    principal: str
    bucket: str
    key: str
    expires_seconds: int = 900


def _public(p: dict) -> dict:
    return {k: v for k, v in p.items() if k != "secret_key"}


@app.get("/health")
def health() -> dict:
    return {"ok": True, "service": "mock-iam", "mock": True}


@app.post("/reset", dependencies=[Depends(auth)])
def reset() -> dict:
    with _lock:
        _save({"principals": {}, "events": [], "networks": [], "next_event_id": 1})
    return {"ok": True}


@app.put("/principals/{name}", dependencies=[Depends(auth)])
def put_principal(name: str, p: Principal) -> dict:
    with _lock:
        st = _load()
        st["principals"][name] = p.model_dump()
        _save(st)
    return _public(p.model_dump())


@app.get("/principals", dependencies=[Depends(auth)])
def list_principals() -> list[dict]:
    return [_public(p) for p in _load()["principals"].values()]


@app.post("/events", dependencies=[Depends(auth)])
def add_event(e: Event) -> dict:
    with _lock:
        st = _load()
        rec = e.model_dump()
        rec["ts"] = rec["ts"] or datetime.now(timezone.utc).isoformat()
        rec["id"] = st["next_event_id"]
        st["next_event_id"] += 1
        st["events"].append(rec)
        _save(st)
    return rec


@app.get("/events", dependencies=[Depends(auth)])
def list_events(since_id: int = 0) -> list[dict]:
    return [e for e in _load()["events"] if e["id"] > since_id]


@app.put("/networks", dependencies=[Depends(auth)])
def put_networks(origins: list[NetworkOrigin]) -> dict:
    with _lock:
        st = _load()
        st["networks"] = [o.model_dump() for o in origins]
        _save(st)
    return {"ok": True, "count": len(origins)}


@app.get("/networks", dependencies=[Depends(auth)])
def networks() -> list[dict]:
    return _load()["networks"]


@app.post("/presign", dependencies=[Depends(auth)])
def presign(req: PresignRequest) -> dict:
    """Presigned GET for an authorised principal, addressed to the public CDN host."""
    p = _load()["principals"].get(req.principal)
    if not p or not p.get("access_key") or not p.get("secret_key"):
        raise HTTPException(status_code=404, detail="principal has no credentials")
    allowed = any(
        perm.get("bucket") == req.bucket and "s3:GetObject" in perm.get("actions", [])
        for perm in p.get("permissions", [])
    )
    if not allowed:
        raise HTTPException(status_code=403, detail="principal is not authorised for this bucket")
    client = Minio(PUBLIC_ENDPOINT, access_key=p["access_key"], secret_key=p["secret_key"],
                   secure=False, region="us-east-1")
    url = client.presigned_get_object(req.bucket, req.key, expires=timedelta(seconds=req.expires_seconds))
    return {"principal": req.principal, "url": url, "expires_seconds": req.expires_seconds}
