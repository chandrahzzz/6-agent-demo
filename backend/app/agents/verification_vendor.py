"""Adversarial verification for data that left through an integration.

It does not trust "deletion requested": it forces the real sync job to run (does the leak come
back?), re-queries the vendor's store by keyed fingerprint, and checks that legitimate flows
still work. Results are recorded in the same VerificationRun shape as storage verification.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select

from .. import connectors
from ..core.db import session_scope
from ..evidence import chain
from ..models import Incident, SubjectSet, VerificationRun, now
from ..verification import verdict as vd
from .base import AgentOutput, Ctx
from .blast_radius import known_locations


def _row(pid: str, method: str, path: str, ok: bool | None, status, detail: str, n: int = 0) -> dict:
    return {"probe_id": pid, "kind": "vendor_check", "method": method, "path": path, "status": status, "bytes": n,
            "outcome": "DENIED" if ok else ("ACCESSIBLE" if ok is False else "UNEXPECTED_STATUS"), "layer": "vendor",
            "detail": detail, "started_at": datetime.now(timezone.utc).isoformat(), "duration_ms": 0}


def verify_vendor(ctx: Ctx, etype: str) -> AgentOutput:
    with session_scope() as db:
        inc = db.get(Incident, ctx.incident_id)
        inc.status = "VERIFYING"
        scope = dict(inc.scope or {})
        n = db.execute(select(func.count()).select_from(VerificationRun).where(VerificationRun.incident_id == inc.id)).scalar_one()
        run = VerificationRun(incident_id=inc.id, run_number=n + 1, ref=f"VER-{inc.ref[4:]}-{n + 1}")
        db.add(run)
        db.flush()
        run_id, run_ref = run.id, run.ref
        subjects = sorted({fp for s in db.execute(select(SubjectSet).where(SubjectSet.incident_id == inc.id)).scalars() for fp in s.fingerprints})

    checks, authorised = [], []
    store = scope["vendor_store"]
    if etype == "CONSENT_MISMATCH":
        ctx.step(f"Attacking the fix: forcing {scope['job_id']} to run")
        res = connectors.worker("POST", f"/jobs/{scope['job_id']}/run")
        checks.append(_row("force-sync", "POST", f"job://{scope['job_id']}/run", None, res["status"],
                           f"forced sync: {res['status']}" + (f", sent {res['sent']} rows, consent filter {res['consent_filter']}" if res["status"] == "RAN" else "")))
    ctx.step(f"Re-querying vendor://{store} by keyed fingerprint")
    hunt = connectors.worker("POST", "/fingerprints/search", json={"subject_fingerprints": subjects,
                                                                  "locations": known_locations(connectors.worker("GET", "/inventory"))},
                             timeout=300)["results"]
    at_vendor = next((r for r in hunt if r["kind"] == "vendor" and r["ref"] == store), None)
    left = at_vendor["matches"] if at_vendor and at_vendor["checked"] else None
    if checks:
        checks[0]["outcome"] = "DENIED" if left == 0 else ("ACCESSIBLE" if left else "UNEXPECTED_STATUS")
    checks.append(_row("vendor-query", "QUERY", f"vendor://{store}", None if left is None else left == 0,
                       "0 matches" if left == 0 else f"{left} matches", f"{left} affected subject(s) still held by the vendor"))
    if etype == "CONSENT_MISMATCH":
        job = next(j for j in connectors.worker("GET", "/checks/consent-sync") if j["job_id"] == scope["job_id"])
        checks.append(_row("cause", "CHECK", f"job://{scope['job_id']}", job["filter_withdrawn_consent"] or not job["enabled"],
                           f"enabled={job['enabled']} filter={job['filter_withdrawn_consent']}", "root-cause control"))
        consented = job["vendor_rows"] - job["withdrawn_at_vendor"]
        authorised.append({**_row("authorised", "QUERY", f"vendor://{store} (consented members)", None, f"{consented} rows",
                                  "consented members remain available to the approved processor"),
                           "outcome": "ACCESSIBLE" if consented > 0 else "DENIED", "authenticated": True})
    else:
        reg = {v["vendor"]: v for v in connectors.worker("GET", "/checks/egress")}
        blocked = reg.get(scope["vendor"], {}).get("blocked", False)
        checks.append(_row("cause", "CHECK", f"registry://{scope['integration_id']}", blocked, f"blocked={blocked}", "egress governance"))
        approved_ok = any(v["approved"] and not v["blocked"] for v in reg.values()) or not reg
        inv = connectors.worker("GET", "/inventory")
        nw = next((i for i in inv["integrations"] if i["integration_id"] == "INT-NW"), None)
        authorised.append({**_row("authorised", "CHECK", "registry://INT-NW (approved vendor)", None, "approved" if nw and nw["approved"] else "missing",
                                  "approved integrations unaffected"),
                           "outcome": "ACCESSIBLE" if (nw and nw["approved"] and not nw.get("blocked")) or approved_ok else "DENIED",
                           "authenticated": True})

    copy_hunt = []
    for r in hunt:
        loc = {"object": f"s3://{r['ref']}", "table": f"db://meridian/{r['ref']}", "vendor": f"vendor://{r['ref']}"}[r["kind"]]
        row = {"location": loc, "kind": r["kind"], "checked": r["checked"], "matches": r["matches"], "present": r["present"]}
        if not r["checked"]:
            row.update(accessible=None, status="UNVERIFIED", evidence="could not inspect")
        elif not r["present"]:
            row.update(accessible=False, status="NO_MATCH", evidence="no fingerprint match")
        elif r["kind"] == "vendor":
            row.update(accessible=True, status="EXPOSED", evidence="third party still holds affected subjects")
        else:
            row.update(accessible=False, status="PROTECTED", evidence="internal system of record / private storage")
        copy_hunt.append(row)

    cause_ok = all(c["outcome"] == "DENIED" for c in checks if c["probe_id"] == "cause")
    vendor_rows = [c for c in copy_hunt if c["kind"] == "vendor" and c["present"]]
    result = vd.decide(original_probes=[c for c in checks if c["probe_id"] != "cause"],
                       copy_probes=[{**c, "outcome": "ACCESSIBLE", "path": c["location"], "method": "QUERY", "status": c["matches"],
                                     "location_label": c["location"]} for c in vendor_rows],
                       copy_hunt=[c for c in copy_hunt if c["kind"] != "vendor"], authorised=authorised, evidence_recorded=True)
    v = result["verdict"]
    if v == "VERIFIED_FIXED" and not cause_ok:
        v, result["reasons"] = "PARTIALLY_FIXED", result["reasons"] + ["root-cause control not in place"]
        result["residual"] = result["residual"] + ["root cause unfixed"]
    with session_scope() as db:
        run = db.get(VerificationRun, run_id)
        run.status, run.verdict, run.reasons, run.residual = "COMPLETED", v, result["reasons"], result["residual"]
        run.targets = [c["path"] for c in checks]
        run.origin = {"network": "customer_net (worker)", "verifier_version": "mallya-vendor-verifier/1.0",
                      "note": "vendor stores are re-queried from the customer side; no external probe applies"}
        run.external_results, run.authorised_results, run.copy_hunt = checks, authorised, copy_hunt
        run.unverified = [c for c in copy_hunt if c["status"] == "UNVERIFIED"]
        run.verifier_version, run.finished_at = "mallya-vendor-verifier/1.0", now()
        inc = db.get(Incident, ctx.incident_id)
        inc.status, inc.latest_verification = (v if v in ("VERIFIED_FIXED", "PARTIALLY_FIXED", "STILL_EXPOSED", "UNVERIFIED") else "UNVERIFIED"), v
        if v == "VERIFIED_FIXED" and not inc.verified_fixed_at:
            inc.verified_fixed_at = now()
        chain.append(inc.id, "verification.completed", "agent:adversarial_verification",
                     {"run": run_ref, "verdict": v, "residual": result["residual"], "reasons": result["reasons"],
                      "requests": [{k: c.get(k) for k in ("method", "path", "status", "outcome", "detail")} for c in checks],
                      "copy_hunt": [{k: c[k] for k in ("location", "matches", "present", "accessible", "status")} for c in copy_hunt]}, db=db)
    summary = ctx.summarise("verification.summary", {"verdict": v, "residual": result["residual"], "reasons": result["reasons"],
                                                     "external_blocked": sum(1 for c in checks if c["outcome"] == "DENIED"), "mode": "vendor"})
    return AgentOutput(summary=summary, confidence=0.95, evidence_refs=[f"verification:{run_ref}"],
                       data={"run_id": run_id, "run_ref": run_ref, "verdict": v, "residual": result["residual"]})
