"""Customer-side worker API (customer_net only, token-authenticated).

Contract: responses carry METADATA ONLY - counts, masked samples, keyed fingerprints,
config/state facts. No endpoint returns raw identifiers or raw rows.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from . import actions, checks, infra, lite, meridian, scan, scenarios, seed, storage
from .clients import cdn_admin, iam, vendor
from .config import settings

logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
app = FastAPI(title="MALLYA customer-side worker", version="1.0")


def auth(x_worker_token: str = Header(default="")) -> None:
    if x_worker_token != settings().worker_token:
        raise HTTPException(status_code=401, detail="invalid worker token")


A = [Depends(auth)]


class SeedReq(BaseModel):
    seed: int | None = None


class SetupReq(BaseModel):
    params: dict = {}


class ObjReq(BaseModel):
    bucket: str
    key: str
    include_fingerprints: bool = False


class TableReq(BaseModel):
    table: str
    include_fingerprints: bool = False


class StoreReq(BaseModel):
    store: str
    include_fingerprints: bool = False


class CdnReq(BaseModel):
    path: str
    include_fingerprints: bool = False


class Location(BaseModel):
    kind: str  # object | table | vendor | cdn
    ref: str  # bucket/key | table | store | /bucket/key


class SearchReq(BaseModel):
    subject_fingerprints: list[str]
    locations: list[Location]


class FpReq(BaseModel):
    subject_fingerprints: list[str]


class ActionReq(BaseModel):
    action_type: str
    params: dict
    approval: dict


@app.get("/health")
def health() -> dict:
    return {"ok": True, "service": "worker", "side": "customer"}


@app.post("/seed", dependencies=A)
def do_seed(req: SeedReq) -> dict:
    return seed.seed(req.seed if req.seed is not None else settings().seed)


@app.post("/scenarios/{scenario_id}/setup", dependencies=A)
def setup(scenario_id: str, req: SetupReq) -> dict:
    fn = scenarios.SETUP.get(scenario_id) or lite.SETUP.get(scenario_id)
    if not fn:
        raise HTTPException(status_code=404, detail="unknown scenario")
    return fn(req.params)


@app.get("/history/synthetic", dependencies=A)
def history() -> list[dict]:
    return seed.synthetic_history(settings().seed)


@app.get("/inventory", dependencies=A)
def inventory() -> dict:
    import yaml

    cfg_path = infra.repo() / "buckets.yaml"
    cfg = {b["name"]: b for b in yaml.safe_load(cfg_path.read_text())["buckets"]} if cfg_path.exists() else {}
    c = storage.as_principal("mallya-scanner")
    buckets = []
    for b in c.list_buckets():
        name = b.name
        objs = [{"key": o.object_name, "size": o.size, "last_modified": o.last_modified.isoformat() if o.last_modified else None}
                for o in c.list_objects(name, recursive=True)]
        try:
            tags = dict(c.get_bucket_tags(name) or {})
        except Exception:  # noqa: BLE001
            tags = {}
        anon = storage.get_anonymous(name)
        rules = storage.anonymous_rules(name)
        for o in objs:
            o["public"] = storage.object_public(o["key"], rules)
        declared = cfg.get(name)
        canary = next((o for o in objs if o["key"] == seed.CANARY_KEY), None)
        bucket_public = any(r["prefix"] == "" for r in rules)
        buckets.append({
            "name": name, "anonymous": anon, "public": bucket_public, "anonymous_rules": rules,
            "has_public_objects": any(o["public"] for o in objs),
            "classification": (declared or {}).get("classification") or tags.get("classification"),
            "declared_in_config": declared is not None,
            "declared_public": bool((declared or {}).get("public")) if declared else None,
            "drift": declared is not None and (bool(declared.get("public")) != bucket_public
                                                or (not declared.get("public") and any(r["prefix"] for r in rules))),
            "replicate_to": (declared or {}).get("replicate_to"), "replica_of": (declared or {}).get("replica_of"),
            "encryption_declared": (declared or {}).get("encryption"),
            "objects": [o for o in objs if not o["key"].startswith("_mallya_canary/")],
            "canary": {"key": canary["key"], "sha256": hashlib.sha256(seed.canary_body(name, settings().seed)).hexdigest()}
                      if canary else None,
        })
    tables = []
    for t in meridian.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY 1"):
        n = t["table_name"]
        if n in ("worker_stats", "synthetic_registry", "executed_actions"):
            continue
        cols = [r["column_name"] for r in meridian.query(
            "SELECT column_name FROM information_schema.columns WHERE table_name=:t ORDER BY ordinal_position", t=n)]
        cnt = meridian.query(f'SELECT count(*) AS n FROM "{n}"')[0]["n"]  # n comes from the catalog
        tables.append({"name": n, "columns": cols, "row_count": int(cnt)})
    integrations = meridian.query("SELECT * FROM integration_registry ORDER BY integration_id")
    jobs = meridian.query("SELECT * FROM integration_jobs ORDER BY job_id")
    return {"buckets": buckets, "tables": tables, "integrations": integrations, "integration_jobs": jobs,
            "cdn": {"name": "cdn.meridian.sandbox", "fronts": [b["name"] for b in buckets], "kind": "nginx proxy_cache"}}


@app.post("/scan/object", dependencies=A)
def scan_object(req: ObjReq) -> dict:
    return scan.scan_object(req.bucket, req.key, req.include_fingerprints)


@app.post("/scan/table", dependencies=A)
def scan_table(req: TableReq) -> dict:
    try:
        return scan.scan_table(req.table, req.include_fingerprints)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/scan/vendor", dependencies=A)
def scan_vendor(req: StoreReq) -> dict:
    return scan.scan_vendor(req.store, req.include_fingerprints)


@app.post("/scan/cdn", dependencies=A)
def scan_cdn(req: CdnReq) -> dict:
    return scan.scan_cdn(req.path, req.include_fingerprints)


@app.post("/fingerprints/search", dependencies=A)
def fp_search(req: SearchReq) -> dict:
    """Intersect the incident's subject fingerprints with what each location holds."""
    wanted = set(req.subject_fingerprints)
    results = []
    for loc in req.locations:
        try:
            if loc.kind == "object":
                b, k = loc.ref.split("/", 1)
                r = scan.scan_object(b, k, True)
            elif loc.kind == "table":
                r = scan.scan_table(loc.ref, True)
            elif loc.kind == "vendor":
                r = scan.scan_vendor(loc.ref, True)
            elif loc.kind == "cdn":
                r = scan.scan_cdn(loc.ref, True)
                if not r.get("served"):
                    results.append({"kind": loc.kind, "ref": loc.ref, "checked": True, "matches": 0,
                                    "present": False, "note": f"CDN did not serve object (HTTP {r['status']})"})
                    continue
            else:
                raise ValueError("unknown location kind")
            have = set(r.get("subject_fingerprints") or [])
            m = len(have & wanted)
            results.append({"kind": loc.kind, "ref": loc.ref, "checked": True, "matches": m, "present": m > 0,
                            "location_subjects": len(have), "categories": r.get("categories", {})})
        except Exception as exc:  # noqa: BLE001 - an uninspectable location is reported UNVERIFIED, never assumed clean
            results.append({"kind": loc.kind, "ref": loc.ref, "checked": False, "matches": None, "present": None,
                            "error": type(exc).__name__})
    return {"searched_for": len(wanted), "results": results}


@app.post("/consent/breakdown", dependencies=A)
def consent(req: FpReq) -> dict:
    return scan.consent_breakdown(req.subject_fingerprints)


@app.get("/logs/nginx", dependencies=A)
def nginx_logs(offset: int = 0) -> dict:
    path = settings().nginx_log_path
    if not os.path.exists(path):
        return {"entries": [], "next_offset": 0, "available": False}
    size = os.path.getsize(path)
    if offset > size:  # log rotated / recreated
        offset = 0
    with open(path, "rb") as fh:
        fh.seek(offset)
        chunk = fh.read(5_000_000)
    lines = chunk.split(b"\n")
    tail = lines.pop() if not chunk.endswith(b"\n") else b""
    entries = [json.loads(line) for line in lines if line.strip()]
    return {"entries": entries, "next_offset": offset + len(chunk) - len(tail), "available": True}


@app.get("/git/log", dependencies=A)
def git_log(limit: int = 50) -> list[dict]:
    return infra.log(limit)


@app.get("/git/show/{sha}", dependencies=A)
def git_show(sha: str) -> dict:
    try:
        return infra.show(sha)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/infra/patch-preview", dependencies=A)
def patch_preview(bucket: str, reclassify: str | None = None) -> dict:
    text = infra.set_public(bucket, False)
    if reclassify:
        text = infra.set_classification(bucket, reclassify, text)
    return {"path": "buckets.yaml", "diff": infra.unified_diff("buckets.yaml", text),
            "declared_public": bucket in infra.current_buckets_public(), "gates": infra.enabled_gates()}


@app.get("/checks/consent-sync", dependencies=A)
def check_consent(include_fingerprints: bool = False) -> list[dict]:
    return checks.consent_sync(include_fingerprints)


@app.get("/checks/lite", dependencies=A)
def check_lite() -> list[dict]:
    return lite.run_checks()


@app.get("/checks/egress", dependencies=A)
def check_egress(include_fingerprints: bool = False) -> list[dict]:
    return checks.egress(include_fingerprints)


@app.post("/jobs/{job_id}/run", dependencies=A)
def run_job(job_id: str) -> dict:
    """Runs the real sync job (used by verification to attack the fix: does a re-sync leak again?)."""
    return checks.run_sync(job_id)


@app.get("/storage/anonymous/{bucket}", dependencies=A)
def anonymous(bucket: str) -> dict:
    return {"bucket": bucket, "anonymous": storage.get_anonymous(bucket)}


@app.get("/cdn/inspect", dependencies=A)
def cdn_inspect(key: str | None = None) -> dict:
    return cdn_admin("GET", "/cache/inspect", params={"key": key} if key else {})


@app.get("/iam/events", dependencies=A)
def iam_events(since_id: int = 0) -> list[dict]:
    return iam("GET", "/events", params={"since_id": since_id})


@app.get("/iam/principals", dependencies=A)
def iam_principals() -> list[dict]:
    return iam("GET", "/principals")


@app.get("/iam/networks", dependencies=A)
def iam_networks() -> list[dict]:
    return iam("GET", "/networks")


@app.get("/vendor/calls", dependencies=A)
def vendor_calls(since_id: int = 0) -> list[dict]:
    return vendor("GET", "/admin/calls", params={"since_id": since_id})


@app.post("/actions/execute", dependencies=A)
def execute(req: ActionReq) -> dict:
    try:
        return {"ok": True, "result": actions.execute(req.action_type, req.params, req.approval)}
    except actions.ApprovalError as exc:
        raise HTTPException(status_code=403, detail=f"approval rejected: {exc}") from exc


@app.get("/stats", dependencies=A)
def stats() -> dict:
    return meridian.stats()
