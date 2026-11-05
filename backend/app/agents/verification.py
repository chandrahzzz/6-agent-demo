"""Adversarial Verification Agent - independent of remediation; it ignores success messages
and attacks the fix from external_net through the public CDN, exactly as an attacker would.

A. External attack test: unauthenticated GET of every exposed path, plus an origin-bypass GET
   (query string => nginx never serves it from cache) so origin state and CDN state are
   measured separately; canary downloads; authorised consumer (reporting-service) must get 200.
B. Copy hunt: keyed-fingerprint search of every known location (data PRESENT?) and, separately,
   whether each copy is externally ACCESSIBLE. Anything not inspectable is UNVERIFIED.
C. Verdict: verification/verdict.py.
"""
from __future__ import annotations

from sqlalchemy import func, select

from .. import connectors
from ..core.db import session_scope
from ..evidence import chain
from ..models import Asset, Finding, Incident, SubjectSet, VerificationRun, now
from ..verification import verdict as vd
from .base import AgentOutput, Ctx
from .blast_radius import known_locations

CDN_HOST = "cdn://cdn.meridian.sandbox"
INTERNAL_PRINCIPALS = {"infra-sync", "dev-rahul", "mallya-scanner", "mallya-remediator"}


def verify(ctx: Ctx) -> AgentOutput:
    with session_scope() as db:
        etype = db.get(Incident, ctx.incident_id).exposure_type
    if etype in ("CONSENT_MISMATCH", "SHADOW_AI_UPLOAD"):
        return verify_vendor(ctx, etype)
    with session_scope() as db:
        inc = db.get(Incident, ctx.incident_id)
        inc.status = "VERIFYING"
        n = db.execute(select(func.count()).select_from(VerificationRun).where(VerificationRun.incident_id == inc.id)).scalar_one()
        run = VerificationRun(incident_id=inc.id, run_number=n + 1, ref=f"VER-{inc.ref[4:]}-{n + 1}")
        db.add(run)
        db.flush()
        run_id, run_ref = run.id, run.ref
        primary = (inc.scope or {}).get("primary")
        buckets = list((inc.scope or {}).get("buckets", []))
        fnds = db.execute(select(Finding).where(Finding.incident_id == inc.id,
                                                Finding.finding_type.in_(["PUBLIC_OBJECT_WITH_IDENTIFIERS"]))).scalars().all()
        exposed = sorted({(f.details["bucket"], f.details["key"]) for f in fnds})
        subjects = sorted({fp for s in db.execute(select(SubjectSet).where(SubjectSet.incident_id == inc.id)).scalars()
                           for fp in s.fingerprints})

    ctx.step(f"{run_ref}: hunting copies of {len(subjects):,} subject fingerprints across every known location")
    inv = connectors.worker("GET", "/inventory")
    locs = known_locations(inv)
    hunt = connectors.worker("POST", "/fingerprints/search", json={"subject_fingerprints": subjects, "locations": locs},
                             timeout=300)["results"]
    cache = connectors.cdn_admin("GET", "/cache/inspect")
    data_objects = {r["ref"] for r in hunt if r["kind"] == "object" and r["present"]}
    cached_paths = sorted({e["path"] for e in cache["entries"] if e["fresh"] and e["method"] == "GET"
                           and e["path"].lstrip("/") in data_objects})
    cdn_hunt = []
    if cached_paths:
        cdn_hunt = connectors.worker("POST", "/fingerprints/search", json={
            "subject_fingerprints": subjects, "locations": [{"kind": "cdn", "ref": p} for p in cached_paths]})["results"]

    # A. probes ---------------------------------------------------------------
    probe_paths = sorted({f"/{r['ref']}" for r in hunt if r["kind"] == "object" and r["present"]} | {f"/{b}/{k}" for b, k in exposed})
    probes = []
    for i, p in enumerate(probe_paths):
        probes.append({"probe_id": f"edge-{i}", "kind": "anonymous_get", "path": p})
        probes.append({"probe_id": f"origin-{i}", "kind": "anonymous_get", "path": p + "?x-mallya-origin-check=1"})
    canaries = {b["name"]: b["canary"] for b in inv["buckets"] if b["name"] in buckets and b.get("canary")}
    for b, c in canaries.items():
        probes.append({"probe_id": f"canary-{b}", "kind": "anonymous_get", "path": f"/{b}/{c['key']}", "expect_sha256": c["sha256"]})
    authorised_targets = []
    # The legitimate consumer of the primary bucket (if any) must keep working after the fix.
    consumers = [p["name"] for p in connectors.worker("GET", "/iam/principals")
                 if p["name"] not in INTERNAL_PRINCIPALS and p.get("access_key")
                 and any(perm.get("bucket") == primary and "s3:GetObject" in perm.get("actions", []) for perm in p.get("permissions", []))]
    consumer = consumers[0] if consumers else None
    if primary and primary in canaries and consumer:
        try:
            ps = connectors.iam("POST", "/presign", json={"principal": consumer, "bucket": primary,
                                                          "key": canaries[primary]["key"], "expires_seconds": 300})
            probes.append({"probe_id": "authorised-consumer", "principal": consumer, "kind": "authorised_get", "url": ps["url"],
                           "expect_sha256": canaries[primary]["sha256"]})
            authorised_targets.append(f"/{primary}/{canaries[primary]['key']}")
        except connectors.ConnectorError as exc:
            ctx.step(f"Could not obtain authorised-consumer credential: {exc}")
    ctx.step(f"Attacking the fix from external_net: {len(probes)} real requests through the public CDN")
    verifier_ok = True
    try:
        job = connectors.verifier("POST", "/probe", json={"run_id": run_ref, "probes": probes})
        net = connectors.verifier("GET", "/selftest/network")
    except connectors.ConnectorError as exc:
        verifier_ok, job, net = False, {"results": [], "origin": {}}, {"checks": []}
        ctx.step(f"Verifier unavailable: {exc}")
    results = {r["probe_id"]: r for r in job["results"]}

    def label(path: str, cached: bool) -> str:
        b = path.strip("/").split("?")[0].split("/", 1)[0]
        if cached:
            return f"CDN cache ({path.split('?')[0]})"
        return "replica bucket" if b.endswith("replica") else f"{b}"

    original_probes, copy_probes, edge_rows = [], [], []
    for i, p in enumerate(probe_paths):
        edge, origin = results.get(f"edge-{i}"), results.get(f"origin-{i}")
        if not edge or not origin:
            continue
        b = p.strip("/").split("/", 1)[0]
        edge = {**edge, "layer": "edge"}
        origin = {**origin, "layer": "origin", "path": p, "location_label": label(p, False)}
        edge_rows += [edge, origin]
        is_primary = b == primary
        (original_probes if is_primary else copy_probes).append(origin)
        if edge["outcome"] == "ACCESSIBLE" and edge.get("served_from_cache"):
            copy_probes.append({**edge, "location_label": label(p, True)})
        elif not is_primary or edge["outcome"] != "ACCESSIBLE":
            pass
    for b in canaries:
        r = results.get(f"canary-{b}")
        if r:
            r = {**r, "layer": "canary", "location_label": f"{b} (canary)"}
            edge_rows.append(r)
            (original_probes if b == primary else copy_probes).append(r)
    authorised = [{**results["authorised-consumer"], "principal": consumer}] if "authorised-consumer" in results else []

    # B. copy hunt table --------------------------------------------------------
    db_unreachable = all(not c["reachable"] for c in net.get("checks", []) if c["target"].startswith(("postgres", "worker")))
    origin_by_path = {r["path"]: r for r in edge_rows if r.get("layer") == "origin"}
    copy_hunt = []
    for r in hunt:
        loc = {"object": f"s3://{r['ref']}", "table": f"db://meridian/{r['ref']}", "vendor": f"vendor://{r['ref']}"}[r["kind"]]
        row = {"location": loc, "kind": r["kind"], "checked": r["checked"], "matches": r["matches"], "present": r["present"]}
        if not r["checked"]:
            row.update(accessible=None, status="UNVERIFIED", evidence=f"could not inspect ({r.get('error')})")
        elif not r["present"]:
            row.update(accessible=False, status="NO_MATCH", evidence="no fingerprint match")
        elif r["kind"] == "object":
            o = origin_by_path.get(f"/{r['ref']}")
            acc = None if not o else (True if o["outcome"] == "ACCESSIBLE" else False if o["outcome"] == "DENIED" else None)
            row.update(accessible=acc, status={True: "EXPOSED", False: "PROTECTED", None: "UNVERIFIED"}[acc],
                       evidence=(f"origin GET -> {o['status']} {o['outcome']}" if o else "not probed"))
        elif r["kind"] == "table":
            row.update(accessible=False if db_unreachable else None, status="PROTECTED" if db_unreachable else "UNVERIFIED",
                       evidence="database not reachable from external_net (verifier network self-test)" if db_unreachable
                       else "external reachability not proven")
        else:
            row.update(accessible=None, status="THIRD_PARTY_COPY",
                       evidence="copy held by a third party; remove at the vendor and re-verify")
        copy_hunt.append(row)
    for r in cdn_hunt:
        p = r["ref"]
        edge = next((e for e in edge_rows if e.get("layer") == "edge" and e["path"] == p), None)
        acc = bool(edge and edge["outcome"] == "ACCESSIBLE" and edge.get("served_from_cache"))
        copy_hunt.append({"location": f"{CDN_HOST}{p}", "kind": "cdn", "checked": r["checked"], "matches": r["matches"],
                          "present": r["present"], "accessible": acc if r["checked"] else None,
                          "status": "EXPOSED" if acc else ("PROTECTED" if r["checked"] else "UNVERIFIED"),
                          "evidence": f"cdn-admin: cached; external GET -> {edge['status'] if edge else 'n/a'} "
                                      f"{'(HIT)' if edge and edge.get('served_from_cache') else ''}".strip()})
    unverified = [c for c in copy_hunt if c["status"] == "UNVERIFIED"]

    result = vd.decide(original_probes=original_probes, copy_probes=copy_probes,
                       copy_hunt=[c for c in copy_hunt if c["kind"] != "vendor" or c["present"]],
                       authorised=authorised, evidence_recorded=True, verifier_ok=verifier_ok,
                       authorised_required=consumer is not None)
    if consumer is None:
        result["reasons"].append(f"no authorised consumer is registered for {primary}; legitimate-access check not applicable")
    v = result["verdict"]
    with session_scope() as db:
        run = db.get(VerificationRun, run_id)
        run.status, run.verdict, run.reasons, run.residual = "COMPLETED", v, result["reasons"], result["residual"]
        run.targets = probe_paths + [f"/{b}/{c['key']}" for b, c in canaries.items()] + authorised_targets
        run.origin = {**job.get("origin", {}), "network_selftest": net.get("checks", [])}
        run.external_results = [r for r in edge_rows]
        run.authorised_results = authorised
        run.copy_hunt = copy_hunt
        run.unverified = unverified
        run.verifier_version = (job.get("origin") or {}).get("verifier_version")
        run.finished_at = now()
        inc = db.get(Incident, ctx.incident_id)
        inc.status = v if v in ("VERIFIED_FIXED", "PARTIALLY_FIXED", "STILL_EXPOSED", "UNVERIFIED") else "UNVERIFIED"
        inc.latest_verification = v
        if v == "VERIFIED_FIXED" and not inc.verified_fixed_at:
            inc.verified_fixed_at = now()
        for a in db.execute(select(Asset).where(Asset.kind == "bucket", Asset.name.in_(buckets))).scalars():
            open_ = any(c["location"] == f"s3://{a.name}" or c["location"].startswith(f"s3://{a.name}/") for c in copy_hunt
                        if c["status"] == "EXPOSED")
            a.status = "EXPOSED" if open_ else "VERIFIED_PRIVATE"
        chain.append(inc.id, "verification.completed", "agent:adversarial_verification",
                     {"run": run_ref, "verdict": v, "residual": result["residual"], "reasons": result["reasons"],
                      "requests": [{k: r.get(k) for k in ("method", "path", "status", "bytes", "outcome", "layer", "served_from_cache")}
                                   for r in edge_rows],
                      "authorised": [{k: r.get(k) for k in ("status", "outcome")} for r in authorised],
                      "copy_hunt": [{k: c[k] for k in ("location", "matches", "present", "accessible", "status")} for c in copy_hunt],
                      "origin": job.get("origin")}, db=db)
    facts = {"verdict": v, "residual": result["residual"], "reasons": result["reasons"],
             "external_blocked": sum(1 for r in original_probes + copy_probes if r["outcome"] == "DENIED")}
    summary = ctx.summarise("verification.summary", facts)
    return AgentOutput(summary=summary, confidence=0.97 if v in ("VERIFIED_FIXED", "PARTIALLY_FIXED", "STILL_EXPOSED") else 0.6,
                       evidence_refs=[f"verification:{run_ref}"],
                       data={"run_id": run_id, "run_ref": run_ref, "verdict": v, "residual": result["residual"]})


from .verification_vendor import verify_vendor  # noqa: E402  (vendor-type branch)
