"""cdn-admin sidecar (SANDBOX): inspect and purge the nginx proxy cache.

Reads nginx's on-disk cache files directly. Each cache file starts with a binary header
(version, valid_sec, ...) followed by "\nKEY: <cache key>\n". Our cache key is
"<METHOD>:<uri>", e.g. "GET:/meridian-customer-backups/backup.csv".

Deleting a cache file makes nginx treat the next request as a MISS, so purge is real.
"""
from __future__ import annotations

import os
import struct
import time
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query

CACHE_DIR = Path(os.environ.get("CACHE_DIR", "/var/cache/nginx/cdn"))
TOKEN = os.environ.get("CDN_ADMIN_TOKEN", "")
app = FastAPI(title="cdn-admin (SANDBOX)", version="1.0")


def auth(x_cdn_admin_token: str = Header(default="")) -> None:
    if not TOKEN or x_cdn_admin_token != TOKEN:
        raise HTTPException(status_code=401, detail="invalid cdn-admin token")


def _entries() -> list[dict]:
    out: list[dict] = []
    if not CACHE_DIR.exists():
        return out
    now = int(time.time())
    for p in CACHE_DIR.rglob("*"):
        if not p.is_file() or ".tmp" in p.name:
            continue
        try:
            head = p.open("rb").read(4096)
        except OSError:
            continue
        i = head.find(b"\nKEY: ")
        if i < 0:
            continue
        j = head.find(b"\n", i + 6)
        key = head[i + 6 : j].decode("utf-8", "replace")
        valid_sec = struct.unpack_from("<q", head, 8)[0] if len(head) >= 16 else 0
        status_line = head[j + 1 : head.find(b"\r\n", j + 1)].decode("latin-1", "replace")
        method, _, uri = key.partition(":")
        out.append(
            {
                "key": key,
                "method": method,
                "path": uri,
                "file": str(p.relative_to(CACHE_DIR)),
                "size_bytes": p.stat().st_size,
                "valid_until_epoch": valid_sec,
                "fresh": valid_sec > now,
                "cached_status": status_line,
            }
        )
    return sorted(out, key=lambda e: e["key"])


@app.get("/health")
def health() -> dict:
    return {"ok": True, "service": "cdn-admin", "sandbox": True}


@app.get("/cache/inspect", dependencies=[Depends(auth)])
def inspect(key: str | None = Query(default=None, description="object path, e.g. /bucket/obj")) -> dict:
    entries = _entries()
    if key is None:
        return {"cached": bool(entries), "entries": entries}
    path = key.split(":", 1)[1] if key.startswith(("GET:", "HEAD:")) else key
    matches = [e for e in entries if e["path"] == path]
    return {"key": path, "cached": any(e["fresh"] for e in matches), "entries": matches}


@app.post("/prefetch", dependencies=[Depends(auth)])
def prefetch(path: str = Query(..., description="object path to warm into the edge cache")) -> dict:
    """Meridian's edge-prefetch job: fetches an object through the CDN so it is cached."""
    import httpx

    url = os.environ.get("CDN_INTERNAL_URL", "http://cdn.meridian.sandbox:8080") + path
    with httpx.stream("GET", url, headers={"User-Agent": "meridian-cdn-prefetch/1.0"}, timeout=15) as r:
        n = sum(len(c) for c in r.iter_bytes())
        return {"path": path, "status": r.status_code, "bytes": n, "cache": r.headers.get("x-cache-status")}


@app.post("/purge", dependencies=[Depends(auth)])
def purge(key: str = Query(..., description="object path, or a bucket prefix ending in '/'")) -> dict:
    path = key.split(":", 1)[1] if key.startswith(("GET:", "HEAD:")) else key
    purged: list[str] = []
    for e in _entries():
        if e["path"] == path or (path.endswith("/") and e["path"].startswith(path)):
            try:
                (CACHE_DIR / e["file"]).unlink()
                purged.append(e["key"])
            except FileNotFoundError:
                pass
    return {"key": path, "purged": purged, "purged_count": len(purged)}
