"""Access-log ingestion into access_events.

Sources:
  * minio_audit - pushed by MinIO's audit webhook to /internal/minio-audit
  * nginx       - CDN JSON access log, pulled through the customer-side worker
  * synthetic   - pre-scenario history only, always labelled synthetic_history=true
"""
from __future__ import annotations

import hashlib
import logging
import threading
from datetime import datetime

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from .. import connectors
from ..core.db import session_scope
from ..models import KV, AccessEvent

log = logging.getLogger("mallya.ingest")
_lock = threading.Lock()


def _ts(v: str) -> datetime:
    return datetime.fromisoformat(v.replace("Z", "+00:00"))


def minio_entry(e: dict) -> dict | None:
    api = e.get("api") or {}
    if not api.get("name") or not e.get("time"):
        return None
    hdr = {k.lower(): v for k, v in (e.get("requestHeader") or {}).items()}
    probe = hdr.get("x-mallya-probe")
    rid = e.get("requestID") or hashlib.sha256(repr(sorted(e.items())).encode()).hexdigest()[:32]
    return {
        "source": "minio_audit", "request_id": rid, "ts": _ts(e["time"]), "bucket": api.get("bucket"),
        "object_key": api.get("object"), "api": api.get("name"), "method": e.get("requestMethod") or hdr.get(":method"),
        "status": api.get("statusCode"), "bytes": int(api.get("tx") or 0) if api.get("name") == "GetObject" else 0,
        "remote_ip": (e.get("remotehost") or "").split(",")[0].strip() or None,
        "principal": e.get("accessKey") or None, "user_agent": e.get("userAgent"),
        "probe_run_id": probe, "authenticated": bool(e.get("accessKey")), "synthetic_history": False,
        "raw": {"api": {k: api.get(k) for k in ("name", "bucket", "object", "status", "statusCode", "rx", "tx",
                                                  "timeToResponse")},
                "requestPath": e.get("requestPath"), "requestHost": e.get("requestHost"),
                "parentUser": e.get("parentUser")},
    }


def nginx_entry(e: dict) -> dict | None:
    uri = e.get("uri") or ""
    parts = uri.lstrip("/").split("/", 1)
    bucket = parts[0] or None
    key = parts[1] if len(parts) > 1 and parts[1] else None
    method = e.get("method")
    api = "ListObjects" if e.get("args") and "list-type" in e.get("args", "") else (
        "HeadObject" if method == "HEAD" else "GetObject" if key else "ListObjects")
    return {
        "source": "nginx", "request_id": e.get("request_id"), "ts": _ts(e["ts"]), "bucket": bucket,
        "object_key": key, "api": api, "method": method, "status": int(e.get("status") or 0),
        "bytes": int(e.get("body_bytes_sent") or 0) if method == "GET" else 0,
        "remote_ip": e.get("remote_addr"), "principal": None, "user_agent": e.get("ua"),
        "cache_status": e.get("cache") or None, "probe_run_id": e.get("probe") or None,
        "authenticated": e.get("authenticated") == "1", "synthetic_history": False,
        "raw": {"upstream_status": e.get("upstream_status"), "server_port": e.get("server_port")},
    }


def store(db: Session, rows: list[dict]) -> int:
    if not rows:
        return 0
    stmt = insert(AccessEvent).values(rows).on_conflict_do_nothing(index_elements=["source", "request_id"])
    return db.execute(stmt).rowcount or 0


def ingest_minio(payload) -> int:
    entries = payload if isinstance(payload, list) else [payload]
    rows = [r for r in (minio_entry(e) for e in entries if isinstance(e, dict)) if r]
    with session_scope() as db:
        return store(db, rows)


def pull_nginx() -> dict:
    """Pull new CDN log lines through the worker. Returns coverage info."""
    with _lock, session_scope() as db:
        st = db.get(KV, "ingest:nginx") or KV(key="ingest:nginx", value={"offset": 0})
        try:
            res = connectors.worker("GET", "/logs/nginx", params={"offset": st.value.get("offset", 0)}, timeout=30)
        except connectors.ConnectorError as exc:
            log.warning("nginx log pull failed: %s", exc)
            return {"available": False, "error": str(exc)}
        rows = [r for r in (nginx_entry(e) for e in res["entries"]) if r and r["request_id"]]
        n = store(db, rows)
        st.value = {"offset": res["next_offset"], "last_pull": datetime.utcnow().isoformat()}
        db.merge(st)
        return {"available": res.get("available", True), "new": n}


def import_synthetic_history() -> int:
    hist = connectors.worker("GET", "/history/synthetic")
    rows = []
    for h in hist:
        rows.append({**{k: h.get(k) for k in ("source", "bucket", "object_key", "api", "method", "status", "bytes",
                                               "remote_ip", "principal", "user_agent")},
                     "source": "synthetic", "ts": _ts(h["ts"]), "synthetic_history": True, "authenticated": True,
                     "request_id": hashlib.sha256(f"{h['ts']}{h['object_key']}".encode()).hexdigest()[:32],
                     "raw": {"label": "synthetic_history=true (pre-scenario period only)"}})
    with session_scope() as db:
        return store(db, rows)
