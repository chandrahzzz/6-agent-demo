"""External verifier probe (SANDBOX). Lives only on external_net, like a real outside attacker.

It does not trust anyone's success message: it sends real requests through the public CDN
edge and classifies what actually happens. Only a genuine denial counts as BLOCKED; DNS
failures, refused connections, timeouts and 5xx are reported as such (never as blocked).

Response bodies are read and discarded (byte counts + a digest of the first bytes only), so
the verifier never stores customer data.
"""
from __future__ import annotations

import hashlib
import os
import socket
import time
from datetime import datetime, timezone

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

VERSION = "mallya-verifier/1.2.0"
CDN = os.environ.get("CDN_URL", "http://cdn.meridian.sandbox:8080")
TOKEN = os.environ.get("PROBE_TOKEN", "")
app = FastAPI(title="verifier (SANDBOX)", version=VERSION)


def auth(x_probe_token: str = Header(default="")) -> None:
    if not TOKEN or x_probe_token != TOKEN:
        raise HTTPException(status_code=401, detail="invalid probe token")


class Probe(BaseModel):
    probe_id: str
    kind: str  # anonymous_get | anonymous_head | authorised_get
    path: str | None = None  # for anonymous probes: /bucket/key
    url: str | None = None  # for authorised probes: presigned URL addressed to the CDN host
    expect_sha256: str | None = None  # canary integrity check
    max_body_bytes: int = 1_000_000


class ProbeJob(BaseModel):
    run_id: str
    probes: list[Probe]


def _origin() -> dict:
    host = socket.gethostname()
    try:
        ips = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)})
    except OSError:
        ips = []
    return {"hostname": host, "ips": ips, "network": "external_net", "verifier_version": VERSION}


def _classify_error(exc: Exception) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "TIMEOUT"
    cause = exc.__cause__ or exc.__context__
    text = f"{exc} {cause}".lower()
    if isinstance(cause, socket.gaierror) or "name or service not known" in text or "nodename" in text \
            or "temporary failure in name resolution" in text or "name resolution" in text:
        return "DNS_FAILURE"
    if "refused" in text:
        return "CONNECTION_REFUSED"
    return "CONNECTION_ERROR"


def _run_probe(client: httpx.Client, run_id: str, p: Probe) -> dict:
    url = p.url if p.kind == "authorised_get" else CDN + (p.path or "/")
    method = "HEAD" if p.kind == "anonymous_head" else "GET"
    started = datetime.now(timezone.utc).isoformat()
    t0 = time.monotonic()
    rec: dict = {"probe_id": p.probe_id, "kind": p.kind, "method": method,
                 "path": p.path if p.kind != "authorised_get" else httpx.URL(url).path,
                 "authenticated": p.kind == "authorised_get", "started_at": started}
    try:
        with client.stream(method, url, headers={"User-Agent": VERSION, "X-Mallya-Probe": run_id}) as r:
            digest = hashlib.sha256()
            n = 0
            head = b""
            for chunk in r.iter_bytes():
                if n < p.max_body_bytes:
                    digest.update(chunk[: p.max_body_bytes - n])
                if len(head) < 512:
                    head += chunk[: 512 - len(head)]
                n += len(chunk)
            status = r.status_code
            rec.update({
                "status": status,
                "bytes": n,
                "headers": {k: r.headers.get(k) for k in ("content-type", "content-length", "x-cache-status", "server", "etag")
                            if r.headers.get(k) is not None},
            })
            if status in (401, 403):
                rec["outcome"] = "DENIED"
                rec["denial_source"] = "origin" if b"AccessDenied" in head else "edge"
            elif status in (200, 206):
                rec["outcome"] = "ACCESSIBLE"
                rec["served_from_cache"] = r.headers.get("x-cache-status") == "HIT"
                if p.expect_sha256:
                    rec["canary_integrity"] = digest.hexdigest() == p.expect_sha256
            elif status == 404:
                rec["outcome"] = "NOT_FOUND"
            elif status >= 500:
                rec["outcome"] = "SERVER_ERROR"
            else:
                rec["outcome"] = "UNEXPECTED_STATUS"
    except Exception as exc:  # noqa: BLE001 - classify every transport failure explicitly
        rec.update({"status": None, "bytes": 0, "outcome": _classify_error(exc), "error": type(exc).__name__})
    rec["duration_ms"] = round((time.monotonic() - t0) * 1000, 1)
    return rec


@app.get("/health")
def health() -> dict:
    return {"ok": True, "service": "verifier", "version": VERSION, "sandbox": True}


@app.post("/probe", dependencies=[Depends(auth)])
def probe(job: ProbeJob) -> dict:
    started = datetime.now(timezone.utc).isoformat()
    with httpx.Client(timeout=httpx.Timeout(8.0, connect=3.0)) as client:
        results = [_run_probe(client, job.run_id, p) for p in job.probes]
    return {"run_id": job.run_id, "origin": _origin(), "started_at": started,
            "finished_at": datetime.now(timezone.utc).isoformat(), "results": results}


@app.get("/selftest/network", dependencies=[Depends(auth)])
def selftest_network() -> dict:
    """Attempts direct connections that MUST fail (verifier is only on external_net)."""
    targets = [("minio", 9000), ("172.28.0.12", 9000), ("postgres", 5432), ("worker", 7100),
               ("cdn.meridian.sandbox", 8080)]
    out = []
    for host, port in targets:
        t0 = time.monotonic()
        try:
            addr = socket.getaddrinfo(host, port, socket.AF_INET)[0][4]
        except socket.gaierror:
            out.append({"target": f"{host}:{port}", "reachable": False, "result": "DNS_FAILURE"})
            continue
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect(addr)
            out.append({"target": f"{host}:{port}", "resolved": addr[0], "reachable": True, "result": "CONNECTED"})
        except TimeoutError:
            out.append({"target": f"{host}:{port}", "resolved": addr[0], "reachable": False, "result": "TIMEOUT"})
        except OSError as exc:
            out.append({"target": f"{host}:{port}", "resolved": addr[0], "reachable": False,
                        "result": "CONNECTION_REFUSED" if "refused" in str(exc).lower() else "UNREACHABLE"})
        finally:
            s.close()
        out[-1]["ms"] = round((time.monotonic() - t0) * 1000)
    return {"origin": _origin(), "checks": out}
