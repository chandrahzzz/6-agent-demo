"""Investigation Agent: did anyone actually take the data, and what caused the exposure?"""
from __future__ import annotations

import time
from datetime import datetime, timedelta

from sqlalchemy import select

from .. import connectors
from ..core.db import session_scope
from ..investigation import ingest, rootcause, verdict
from ..models import AccessEvent, Finding, Incident, Investigation, VerificationRun
from .base import AgentOutput, Ctx


def _rows(db, buckets: list[str], since: datetime) -> list[dict]:
    q = select(AccessEvent).where(AccessEvent.bucket.in_(buckets), AccessEvent.ts >= since).order_by(AccessEvent.ts)
    return [{c: getattr(e, c) for c in ("source", "ts", "bucket", "object_key", "api", "method", "status", "bytes",
                                         "remote_ip", "principal", "user_agent", "cache_status", "probe_run_id",
                                         "authenticated", "synthetic_history")} for e in db.execute(q).scalars()]


def _iso(d) -> str:
    return d.isoformat() if hasattr(d, "isoformat") else str(d)


def wait_for_coverage(ctx: Ctx, buckets: list[str], since: datetime, timeout_s: float = 20) -> dict:
    """Every CDN request that reached the origin (cache MISS / BYPASS) must also appear in the MinIO
    audit log. Wait for the webhook to catch up; report a gap honestly if it never does."""
    deadline = time.monotonic() + timeout_s
    while True:
        pulled = ingest.pull_nginx()
        with session_scope() as db:
            rows = _rows(db, buckets, since)
        origin_hits = [r for r in rows if r["source"] == "nginx" and r["cache_status"] in ("MISS", "BYPASS", "EXPIRED")]
        audit = [r for r in rows if r["source"] == "minio_audit" and not r["authenticated"]
                 and r["api"] in ("GetObject", "HeadObject", "ListObjectsV2", "ListObjectsV1", "ListObjects")]
        origin_hits = [r for r in origin_hits if not r["authenticated"]]
        covered = len(audit) >= len(origin_hits)
        if (covered and pulled.get("available", False)) or time.monotonic() > deadline:
            return {"nginx": bool(pulled.get("available")), "minio_audit": covered,
                    "origin_hits": len(origin_hits), "audit_records": len(audit)}
        time.sleep(1.0)


def investigate(ctx: Ctx) -> AgentOutput:
    with session_scope() as db:
        inc = db.get(Incident, ctx.incident_id)
        inc.status = "INVESTIGATING"
        primary = (inc.scope or {}).get("primary")
        buckets = sorted((inc.scope or {}).get("buckets", []), key=lambda b: b != primary)  # primary first
        fnds = db.execute(select(Finding).where(Finding.incident_id == inc.id,
                                                Finding.finding_type == "PUBLIC_OBJECT_WITH_IDENTIFIERS")).scalars().all()
        sensitive = {(f.details["bucket"], f.details["key"]) for f in fnds}
        runs = db.execute(select(VerificationRun.ref).where(VerificationRun.incident_id == inc.id)).scalars().all()
        detected_at = inc.detected_at

    ctx.step("Loading policy-change events from IAM and the network-origin registry")
    iam_events = connectors.worker("GET", "/iam/events")
    networks = connectors.worker("GET", "/iam/networks")
    opened = {}
    for b in buckets:
        changes = [e for e in iam_events if e["type"] == "BucketPolicyChanged" and e["target"] == b]
        opens = [e for e in changes if e["details"].get("anonymous") == "download"]
        if opens:
            opened[b] = datetime.fromisoformat(opens[-1]["ts"])
    window_start = min(opened.values()) if opened else detected_at - timedelta(hours=24)

    ctx.step("Correlating CDN (nginx) and origin (MinIO audit) logs", window_start=_iso(window_start))
    coverage = wait_for_coverage(ctx, buckets, window_start - timedelta(seconds=5))
    with session_scope() as db:
        rows = _rows(db, buckets, window_start - timedelta(seconds=5))
        audit_policy = [r for r in _rows(db, buckets, window_start - timedelta(days=60))
                        if r["source"] == "minio_audit" and r["api"] in ("PutBucketPolicy", "DeleteBucketPolicy")]
    ev = verdict.collect(rows, sensitive, networks, set(runs), {"172.29.0.77"})
    v, conf, reasons = verdict.decide(ev, {"nginx_cdn_log": coverage["nginx"], "minio_audit_log": coverage["minio_audit"]})
    ctx.step(f"Access verdict: {v}", reasons=reasons)

    ctx.step("Tracing root cause through infra-config git history")
    commits = connectors.worker("GET", "/git/log")
    with_diffs = [connectors.worker("GET", f"/git/show/{c['sha']}") for c in commits]
    causes = []
    for b in buckets:
        c = rootcause.find_commit(b, with_diffs)
        causes.append(rootcause.correlate(b, c, iam_events, audit_policy))

    timeline = []
    for rc in causes:
        if rc.get("commit"):
            timeline.append({"ts": rc["commit"]["date"], "kind": "commit", "label": f"Commit {rc['commit']['sha'][:8]} \"{rc['commit']['subject']}\" by {rc['commit']['author']}"})
        if rc.get("policy_change_event"):
            e = rc["policy_change_event"]
            timeline.append({"ts": e["ts"], "kind": "policy_change",
                             "label": f"{e['target']} anonymous=download applied by {e['principal']} ({e['details'].get('via', 'infra-sync')})"})
    for e in ev.internal + ev.partner:
        if e["source"] == "nginx" or e["zone"] == "partner":
            timeline.append({"ts": _iso(e["ts"]), "kind": "access_internal" if e["zone"] == "internal" else "access_partner",
                             "label": f"{e['method']} /{e['bucket']}/{e['object_key'] or ''} -> {e['status']} ({e['origin_label']}, {e['bytes']:,} B)"})
    for e in ev.external_attempts + ev.external_success:
        timeline.append({"ts": _iso(e["ts"]), "kind": "access_external_success" if e in ev.external_success else "access_external_attempt",
                         "label": f"{e['method']} /{e['bucket']}/{e['object_key'] or ''} -> {e['status']} from {e['remote_ip']} "
                                  f"({e['bytes']:,} B{', cache ' + e['cache_status'] if e.get('cache_status') else ''})"})
    timeline.append({"ts": _iso(detected_at), "kind": "detected", "label": "Exposure detected by Exposure Hunter"})
    timeline.sort(key=lambda t: t["ts"])

    def brief(e: dict) -> dict:
        return {"ts": _iso(e["ts"]), "source": e["source"], "method": e["method"], "path": f"/{e['bucket']}/{e['object_key'] or ''}",
                "status": e["status"], "bytes": e["bytes"], "remote_ip": e["remote_ip"], "origin": e["origin_label"],
                "cache": e.get("cache_status"), "user_agent": e.get("user_agent")}

    partner_bytes = sum(e["bytes"] for e in ev.partner if e["method"] == "GET" and e["status"] == 200)
    evidence = {
        "external_attempts": [brief(e) for e in ev.external_attempts],
        "external_success": [brief(e) for e in ev.external_success],
        "internal": [brief(e) for e in ev.internal],
        "partner": [brief(e) for e in ev.partner],
        "probe_requests_excluded": ev.probe_excluded,
        "events_by_source": ev.by_source,
        "window_start": _iso(window_start),
        "reasons": reasons,
    }
    rc_text = "; ".join(c["statement"] for c in causes)
    facts = {"verdict": v, "external": {"attempts": len(ev.external_attempts), "successful_downloads": len(ev.external_success),
                                        "bytes_served_real_object": sum(e["bytes"] for e in ev.external_success)},
             "root_cause": causes[0]["statement"] if causes else None,
             "partner_access": (f"{ev.partner[0]['origin_label']} downloaded {partner_bytes:,} bytes" if partner_bytes else None)}
    summary = ctx.summarise("investigation.summary", facts)
    with session_scope() as db:
        db.add(Investigation(incident_id=ctx.incident_id, verdict=v, confidence=conf, summary=summary, evidence=evidence,
                             root_cause=causes, timeline=timeline, log_coverage=coverage))
        inc = db.get(Incident, ctx.incident_id)
        inc.access_verdict = v
        inc.exposure_started_at = window_start
    return AgentOutput(summary=summary, confidence=conf,
                       evidence_refs=[f"log:{e['source']}:{_iso(e['ts'])}" for e in (ev.external_success or ev.external_attempts)][:10]
                       + [f"git:{c['commit']['sha']}" for c in causes if c.get("commit")],
                       data={"verdict": v, "reasons": reasons, "root_cause": [{k: c[k] for k in ("bucket", "kind", "statement", "confidence")} for c in causes],
                             "coverage": coverage, "external_attempts": len(ev.external_attempts),
                             "external_success": len(ev.external_success)})
