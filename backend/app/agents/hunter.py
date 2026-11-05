"""Exposure Hunter: discover assets, inspect permissions, run deterministic detectors in the
worker, and emit findings. The LLM is never the detector; it only phrases the summary.
"""
from __future__ import annotations

from sqlalchemy import select

from .. import connectors
from ..core.db import session_scope
from ..models import Finding, Incident
from .base import AgentOutput, Ctx
from .registry import next_incident_ref, relate, upsert_asset

SENSITIVE_CATS = {"pan", "aadhaar", "email", "phone"}


def _severity(categories: dict, public: bool) -> str:
    if public and ({"pan", "aadhaar"} & set(categories)):
        return "Critical"
    if public and categories:
        return "High"
    if public:
        return "Moderate"
    return "Low"


def sweep(ctx: Ctx) -> AgentOutput:
    ctx.step("Requesting inventory from the customer-side worker")
    inv = connectors.worker("GET", "/inventory")
    findings: list[dict] = []
    decoys = 0
    scanned = 0
    exposures: list[str] = []

    with session_scope() as db:
        cdn = upsert_asset(db, "cdn://cdn.meridian.sandbox", "cdn", "cdn.meridian.sandbox", "nginx-cdn",
                           attributes={"kind": inv["cdn"]["kind"], "public_edge": True})
        internet = upsert_asset(db, "net://internet", "network", "Internet (anonymous)", "external",
                                attributes={"note": "any unauthenticated client"})
        relate(db, internet, cdn, "reaches")
        bucket_assets = {}
        for b in inv["buckets"]:
            a = upsert_asset(db, f"s3://{b['name']}", "bucket", b["name"], "minio", b["classification"],
                             {"anonymous": b["anonymous"], "public": b["public"], "drift": b["drift"],
                              "declared_in_config": b["declared_in_config"], "declared_public": b["declared_public"],
                              "encryption_declared": b["encryption_declared"], "objects": len(b["objects"]),
                              "replicate_to": b["replicate_to"], "replica_of": b["replica_of"]},
                             status="EXPOSED" if b["public"] else "OK")
            bucket_assets[b["name"]] = a
            relate(db, cdn, a, "fronts")
        for b in inv["buckets"]:
            if b.get("replicate_to") and b["replicate_to"] in bucket_assets:
                relate(db, bucket_assets[b["name"]], bucket_assets[b["replicate_to"]], "replicates_to")
        for t in inv["tables"]:
            upsert_asset(db, f"db://meridian/{t['name']}", "table", t["name"], "worker:postgres", None,
                         {"columns": t["columns"], "row_count": t["row_count"]})
        for i in inv["integrations"]:
            upsert_asset(db, f"vendor://{i['integration_id']}", "ai_tool" if i["is_ai_tool"] else "vendor", i["vendor"],
                         "mock-vendor", None, {k: i[k] for k in ("purpose", "approved", "is_ai_tool", "data_categories",
                                                                 "granted_scopes", "required_scopes", "ropa_ref")}
                         | {"credential_expires_at": str(i["credential_expires_at"])})

    ctx.step(f"Inventory: {len(inv['buckets'])} buckets, {len(inv['tables'])} tables, {len(inv['integrations'])} integrations")
    for b in inv["buckets"]:
        for o in b["objects"]:
            r = connectors.worker("POST", "/scan/object", json={"bucket": b["name"], "key": o["key"]})
            scanned += 1
            decoys += len(r["decoy_columns"])
            for col in r["decoy_columns"]:
                findings.append({"asset_ref": r["location"], "detector": "column-context", "finding_type": "DECOY_REJECTED",
                                 "title": f"Pattern match rejected in {col} (not a customer identifier)", "severity": "Info",
                                 "suppressed": True, "data_categories": {}, "record_count": r["record_count"],
                                 "masked_samples": {}, "details": {"column": next(c for c in r["columns"] if c["column"] == col)},
                                 "confidence": 0.9})
            if r["contains_identifiers"]:
                sev = _severity(r["categories"], b["public"])
                ftype = "PUBLIC_OBJECT_WITH_IDENTIFIERS" if b["public"] else "IDENTIFIERS_AT_REST"
                findings.append({
                    "asset_ref": r["location"], "detector": "worker-detectors-v1", "finding_type": ftype,
                    "title": (f"{', '.join(sorted(r['categories']))} identifiers in {'PUBLIC ' if b['public'] else ''}object "
                              f"{b['name']}/{o['key']}"),
                    "severity": sev if b["public"] else "Info", "suppressed": not b["public"],
                    "data_categories": r["categories"], "record_count": r["record_count"] or r["subject_count"],
                    "masked_samples": r["masked_samples"],
                    "details": {"bucket": b["name"], "key": o["key"], "bucket_public": b["public"],
                                "anonymous": b["anonymous"], "columns": r["columns"], "drift": b["drift"],
                                "synthetic_confirmed": r["synthetic_confirmed"], "bytes": r.get("bytes")},
                    "confidence": 0.97,
                })
                if b["public"]:
                    exposures.append(f"{b['name']}/{o['key']} is anonymously readable")
        if b["drift"]:
            findings.append({"asset_ref": f"s3://{b['name']}", "detector": "config-drift", "finding_type": "CONFIG_DRIFT",
                             "title": f"{b['name']}: live access ({b['anonymous']}) differs from buckets.yaml "
                                      f"(public: {str(b['declared_public']).lower()})",
                             "severity": "High" if b["public"] else "Moderate", "suppressed": False,
                             "data_categories": {}, "record_count": None, "masked_samples": {},
                             "details": {"bucket": b["name"], "live": b["anonymous"], "declared_public": b["declared_public"]},
                             "confidence": 0.99})
    ctx.step(f"Scanned {scanned} objects; {len(exposures)} exposure(s); {decoys} decoy column(s) rejected")

    incident_ids = _group_into_incidents(ctx, inv, findings)
    summary = ctx.summarise("hunter.summary", {"assets_scanned": scanned, "exposures": exposures,
                                               "decoys_rejected": decoys})
    return AgentOutput(summary=summary, confidence=0.95 if exposures else 0.9,
                       evidence_refs=[f"finding:{f['finding_type']}:{f['asset_ref']}" for f in findings if not f["suppressed"]][:20],
                       data={"incident_ids": incident_ids, "findings": len(findings), "exposures": exposures,
                             "decoys_rejected": decoys, "objects_scanned": scanned})


def _group_into_incidents(ctx: Ctx, inv: dict, findings: list[dict]) -> list[str]:
    """One incident per cluster of public sensitive buckets connected by replication."""
    public_hits = [f for f in findings if f["finding_type"] == "PUBLIC_OBJECT_WITH_IDENTIFIERS"]
    buckets = {f["details"]["bucket"] for f in public_hits}
    rel = {b["name"]: {b.get("replicate_to"), b.get("replica_of")} - {None} for b in inv["buckets"]}
    clusters: list[set[str]] = []
    for b in sorted(buckets):
        merged = {b} | (rel.get(b, set()) & buckets)
        for c in [c for c in clusters if c & merged]:
            merged |= c
            clusters.remove(c)
        clusters.append(merged)
    ids = []
    with session_scope() as db:
        for f in [f for f in findings if f["finding_type"] in ("DECOY_REJECTED", "IDENTIFIERS_AT_REST")]:
            db.add(Finding(drill_id=ctx.drill_id, **f))
        for cluster in clusters:
            open_existing = db.execute(select(Incident).where(Incident.status.notin_(["CLOSED", "VERIFIED_FIXED"]),
                                                              Incident.exposure_type == "PUBLIC_STORAGE")).scalars().all()
            existing = next((i for i in open_existing if set((i.scope or {}).get("buckets", [])) & cluster), None)
            if existing:
                continue
            primary = sorted(cluster, key=lambda b: (rel.get(b, set()) and b.endswith("replica"), b))[0]
            primary = next((b for b in cluster if not b.endswith("replica")), primary)
            cats = sorted({c for f in public_hits if f["details"]["bucket"] in cluster for c in f["data_categories"]})
            inc = Incident(ref=next_incident_ref(db), drill_id=ctx.drill_id, exposure_type="PUBLIC_STORAGE",
                           title=f"Customer data publicly readable: {primary}" + (f" (+{len(cluster) - 1} related)" if len(cluster) > 1 else ""),
                           summary=f"Anonymous read access to {', '.join(sorted(cluster))} containing {', '.join(cats)} identifiers.",
                           status="DETECTED", severity="Critical", scope={"buckets": sorted(cluster), "primary": primary})
            db.add(inc)
            db.flush()
            for f in findings:
                if (f.get("details") or {}).get("bucket") in cluster and f["finding_type"] in (
                        "PUBLIC_OBJECT_WITH_IDENTIFIERS", "CONFIG_DRIFT"):
                    db.add(Finding(incident_id=inc.id, drill_id=ctx.drill_id, **f))
            ids.append(inc.id)
    return ids
