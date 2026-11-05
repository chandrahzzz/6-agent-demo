"""Mock third-party vendor APIs (SANDBOX / MOCK).

Two fictional vendors live here:
  * Northwind Analytics  - marketing-campaign contact sync (approved vendor)
  * QuickSummarize AI    - an UNAPPROVED "AI tool" that accepts file uploads

Every call is logged (endpoint, time, bytes, caller IP, API key id) so investigations can
prove what left Meridian. Stored payloads contain synthetic identifiers only; they are read
back exclusively by the customer-side worker, which fingerprints them locally.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

DB = Path(os.environ.get("STATE_DIR", "/state")) / "vendor.db"
TOKEN = os.environ.get("MOCK_VENDOR_TOKEN", "")
_lock = threading.Lock()
app = FastAPI(title="Mock Vendor APIs (SANDBOX)", version="1.0")

SCHEMA = """
CREATE TABLE IF NOT EXISTS contacts (customer_ref TEXT PRIMARY KEY, payload TEXT NOT NULL, received_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ai_uploads (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, content TEXT,
    received_at TEXT, api_key_id TEXT, used_for_training INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS calls (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, vendor TEXT, endpoint TEXT,
    method TEXT, bytes_in INTEGER, source_ip TEXT, api_key_id TEXT, status INTEGER, synthetic_history INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT);
"""


def _db() -> sqlite3.Connection:
    DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def admin(x_mock_vendor_token: str = Header(default="")) -> None:
    if not TOKEN or x_mock_vendor_token != TOKEN:
        raise HTTPException(status_code=401, detail="invalid vendor admin token")


def _log(con, vendor: str, request: Request, bytes_in: int, status: int, api_key_id: str | None) -> None:
    con.execute(
        "INSERT INTO calls (ts, vendor, endpoint, method, bytes_in, source_ip, api_key_id, status) VALUES (?,?,?,?,?,?,?,?)",
        (_now(), vendor, request.url.path, request.method, bytes_in,
         request.client.host if request.client else None, api_key_id, status),
    )


@app.get("/health")
def health() -> dict:
    return {"ok": True, "service": "mock-vendor", "mock": True}


@app.post("/admin/reset", dependencies=[Depends(admin)])
def reset() -> dict:
    with _lock:
        if DB.exists():
            DB.unlink()
        _db().close()
    return {"ok": True}


# ---------------------------------------------------------------- Northwind Analytics
class ContactBatch(BaseModel):
    contacts: list[dict]


class RefBatch(BaseModel):
    customer_refs: list[str]


@app.post("/northwind/v1/contacts:batchUpsert")
async def nw_upsert(batch: ContactBatch, request: Request, x_api_key_id: str = Header(default="")) -> dict:
    body = await request.body()
    with _lock:
        con = _db()
        for c in batch.contacts:
            ref = str(c.get("customer_ref"))
            con.execute(
                "INSERT INTO contacts (customer_ref, payload, received_at) VALUES (?,?,?) "
                "ON CONFLICT(customer_ref) DO UPDATE SET payload=excluded.payload, received_at=excluded.received_at",
                (ref, json.dumps(c, sort_keys=True), _now()),
            )
        _log(con, "northwind", request, len(body), 200, x_api_key_id or None)
        con.commit()
        con.close()
    return {"upserted": len(batch.contacts)}


@app.post("/northwind/v1/contacts:batchDelete")
async def nw_delete(batch: RefBatch, request: Request, x_api_key_id: str = Header(default="")) -> dict:
    body = await request.body()
    with _lock:
        con = _db()
        n = 0
        for ref in batch.customer_refs:
            n += con.execute("DELETE FROM contacts WHERE customer_ref = ?", (ref,)).rowcount
        _log(con, "northwind", request, len(body), 200, x_api_key_id or None)
        con.commit()
        con.close()
    return {"deleted": n}


@app.get("/northwind/v1/contacts", dependencies=[Depends(admin)])
def nw_list() -> dict:
    con = _db()
    rows = [json.loads(r["payload"]) for r in con.execute("SELECT payload FROM contacts ORDER BY customer_ref")]
    con.close()
    return {"vendor": "northwind", "count": len(rows), "contacts": rows}


# ---------------------------------------------------------------- QuickSummarize AI (unapproved)
class Upload(BaseModel):
    filename: str
    content: str


@app.post("/quicksummarize/v1/upload")
async def ai_upload(up: Upload, request: Request, x_api_key_id: str = Header(default="")) -> dict:
    body = await request.body()
    with _lock:
        con = _db()
        training = (con.execute("SELECT v FROM settings WHERE k='training_opt_in'").fetchone() or {"v": "1"})["v"] == "1"
        cur = con.execute(
            "INSERT INTO ai_uploads (filename, content, received_at, api_key_id, used_for_training) VALUES (?,?,?,?,?)",
            (up.filename, up.content, _now(), x_api_key_id or None, 1 if training else 0),
        )
        _log(con, "quicksummarize", request, len(body), 200, x_api_key_id or None)
        con.commit()
        upload_id = cur.lastrowid
        con.close()
    return {"upload_id": upload_id, "summary": f"Received {len(up.content)} characters."}


@app.get("/quicksummarize/v1/received", dependencies=[Depends(admin)])
def ai_received() -> dict:
    con = _db()
    rows = [dict(r) for r in con.execute("SELECT * FROM ai_uploads WHERE deleted = 0 ORDER BY id")]
    con.close()
    return {"vendor": "quicksummarize", "uploads": rows}


@app.delete("/quicksummarize/v1/received/{upload_id}", dependencies=[Depends(admin)])
def ai_delete(upload_id: int) -> dict:
    with _lock:
        con = _db()
        n = con.execute("UPDATE ai_uploads SET deleted = 1, content = '' WHERE id = ?", (upload_id,)).rowcount
        con.commit()
        con.close()
    return {"deleted": n}


@app.put("/quicksummarize/v1/account/training", dependencies=[Depends(admin)])
def ai_training(opt_in: bool) -> dict:
    with _lock:
        con = _db()
        con.execute("INSERT INTO settings (k, v) VALUES ('training_opt_in', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                    ("1" if opt_in else "0",))
        con.commit()
        con.close()
    return {"training_opt_in": opt_in}


@app.get("/quicksummarize/v1/account", dependencies=[Depends(admin)])
def ai_account() -> dict:
    con = _db()
    row = con.execute("SELECT v FROM settings WHERE k='training_opt_in'").fetchone()
    con.close()
    return {"vendor": "quicksummarize", "training_opt_in": (row["v"] if row else "1") == "1"}


class PullRequest(BaseModel):
    url: str


@app.post("/admin/simulate-pull", dependencies=[Depends(admin)])
def simulate_pull(req: PullRequest) -> dict:
    """Northwind's nightly backup pull, issued from the vendor's own host (real request)."""
    import httpx

    if not req.url.startswith("http://cdn.meridian.sandbox:8080/"):
        raise HTTPException(status_code=400, detail="pull target must be the Meridian CDN")
    with httpx.stream("GET", req.url, headers={"User-Agent": "northwind-backup-pull/2.3"}, timeout=15) as r:
        n = sum(len(c) for c in r.iter_bytes())
        return {"status": r.status_code, "bytes": n, "cache": r.headers.get("x-cache-status")}


class DeliveryLink(BaseModel):
    url: str
    expires_seconds: int
    note: str = ""


@app.post("/northwind/v1/delivery-links")
async def nw_delivery_link(link: DeliveryLink, request: Request, x_api_key_id: str = Header(default="")) -> dict:
    """Meridian hands Northwind a scoped, expiring presigned link instead of anonymous access."""
    body = await request.body()
    with _lock:
        con = _db()
        con.execute("INSERT INTO settings (k, v) VALUES ('northwind_delivery_link', ?) "
                    "ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                    (json.dumps({"expires_seconds": link.expires_seconds, "note": link.note, "received_at": _now()}),))
        _log(con, "northwind", request, len(body), 200, x_api_key_id or None)
        con.commit()
        con.close()
    return {"accepted": True}


# ---------------------------------------------------------------- call log
@app.get("/admin/calls", dependencies=[Depends(admin)])
def calls(since_id: int = 0) -> list[dict]:
    con = _db()
    rows = [dict(r) for r in con.execute("SELECT * FROM calls WHERE id > ? ORDER BY id", (since_id,))]
    con.close()
    return rows
