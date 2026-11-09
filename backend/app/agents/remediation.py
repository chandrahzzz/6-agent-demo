"""Remediation Agent: propose -> (human approval) -> execute approved actions only.

* Fix the cause, not just the symptom: live fix + buckets.yaml patch + policy gate that rejects
  the bad config if it is ever reintroduced (with a regression test against the bad commit).
* Safety check before every access-removal: read the last N access events; if a legitimate
  consumer depends on the access being removed, HOLD the action and propose a safer alternative.
* The agent never executes anything itself without a recorded approval; the worker re-verifies
  a signed approval token for each action.
"""
from __future__ import annotations

from sqlalchemy import select

from .. import connectors
from ..audit.log import audit
from ..core import events
from ..core.db import session_scope
from ..evidence import chain
from ..investigation.verdict import classify_ip
from ..models import (AccessEvent, Approval, Finding, Incident, Investigation, RemediationAction, SubjectSet,
                      VerificationRun, now)
from ..remediation.approvals import mint
from ..remediation.deps import execution_plan, is_open
from .base import AgentOutput, Ctx

SAFETY_WINDOW_EVENTS = 200


def safety_check(bucket: str, networks: list[dict]) -> dict:
    """Who would break if anonymous access to `bucket` were removed?"""
    with session_scope() as db:
        evs = db.execute(select(AccessEvent).where(AccessEvent.bucket == bucket, AccessEvent.status.in_([200, 206]),
                                                   AccessEvent.method == "GET").order_by(AccessEvent.ts.desc())
                         .limit(SAFETY_WINDOW_EVENTS)).scalars().all()
    dependents, unaffected = {}, {}
    for e in evs:
        if e.probe_run_id:
            continue
        o = classify_ip(e.remote_ip, networks)
        if e.authenticated or e.principal:
            unaffected.setdefault(e.principal or "authenticated client",
                                  {"principal": e.principal, "reads": 0, "reason": "uses its own credentials; anonymous access not needed"})
            unaffected[e.principal or "authenticated client"]["reads"] += 1
        elif o.zone in ("partner", "internal") and o.role == "consumer":
            d = dependents.setdefault(o.label, {"origin": o.label, "zone": o.zone, "reads": 0, "last_read": None})
            d["reads"] += 1
            d["last_read"] = d["last_read"] or e.ts.isoformat()
    return {"events_examined": len(evs), "window": f"last {SAFETY_WINDOW_EVENTS} successful GETs",
            "dependents": list(dependents.values()), "unaffected": list(unaffected.values()),
            "result": "DEPENDENCY_FOUND" if dependents else "NO_DEPENDENCY"}


def _next_code(db, incident_id: str) -> str:
    n = len(db.execute(select(RemediationAction.id).where(RemediationAction.incident_id == incident_id)).all())
    return f"ACT-{n + 1:02d}"


def _add(db, incident_id: str, wave: int, **kw) -> RemediationAction:
    a = RemediationAction(incident_id=incident_id, wave=wave, code=_next_code(db, incident_id), **kw)
    db.add(a)
    db.flush()
    chain.append(incident_id, "remediation.proposed", "agent:remediation",
                 {"code": a.code, "action_type": a.action_type, "target": a.target, "params": a.params,
                  "approval_status": a.approval_status, "safety": a.safety, "wave": wave}, db=db)
    return a


def plan(ctx: Ctx) -> AgentOutput:
    with session_scope() as db:
        inc = db.get(Incident, ctx.incident_id)
        inv = db.execute(select(Investigation).where(Investigation.incident_id == inc.id)
                         .order_by(Investigation.created_at.desc())).scalars().first()
        fnds = db.execute(select(Finding).where(Finding.incident_id == inc.id,
                                                Finding.finding_type == "PUBLIC_OBJECT_WITH_IDENTIFIERS")).scalars().all()
        sensitive = {}
        for f in fnds:
            sensitive.setdefault(f.details["bucket"], []).append(f.details["key"])
        causes = {c["bucket"]: c for c in (inv.root_cause if inv else [])}
        buckets = list((inc.scope or {}).get("buckets", []))
        ref = inc.ref
        etype, scope = inc.exposure_type, dict(inc.scope or {})
        classes = {f.details["bucket"]: f.details.get("classification") for f in fnds}
    if etype in ("CONSENT_MISMATCH", "SHADOW_AI_UPLOAD"):
        return plan_vendor(ctx, etype, scope)
    prefixes = {x.split("/", 1)[0]: x.split("/", 1)[1] for x in scope.get("prefixes", [])}
    networks = connectors.worker("GET", "/iam/networks")
    held, proposed = [], 0
    with session_scope() as db:
        bad_commits = []
        for b in sorted(buckets, key=lambda x: (x.endswith("replica"), x)):
            rc = causes.get(b, {})
            safety = safety_check(b, networks)
            ctx.step(f"Safety check {b}: {safety['result']}", dependents=[d["origin"] for d in safety["dependents"]])
            req = (f"External anonymous GET of every exposed path in {b} returns a genuine 403 through the CDN; "
                   "reporting-service still gets 200")
            if safety["dependents"]:
                dep = safety["dependents"][0]
                _add(db, ctx.incident_id, 1, action_type="partner.presigned_handoff", target=f"s3://{b}",
                     problem=f"{b} is anonymously readable; {dep['origin']} read it anonymously {dep['reads']}x (latest {dep['last_read']})",
                     change=f"Deliver a scoped presigned URL (24h) to {dep['origin']}, then `mc anonymous set none {b}`",
                     risk="Partner pipeline must switch to the presigned link; coordinate before executing",
                     side_effects=f"{dep['origin']} loses anonymous access; receives an expiring link instead",
                     expected_outcome=f"{b} private; partner retains time-boxed access to one object",
                     rollback_plan=f"`mc anonymous set download {b}` (re-opens exposure; not recommended)",
                     verification_requirement=req, safety=safety,
                     params={"bucket": b, "key": sorted(sensitive.get(b, [""]))[0], "partner": dep["origin"],
                             "expires_seconds": 86400},
                     approval_status="HELD")
                held.append(f"{b} is used anonymously by {dep['origin']}")
            elif b in prefixes:
                _add(db, ctx.incident_id, 1, action_type="bucket.set_private", target=f"s3://{b}/{prefixes[b]}",
                     problem=f"Anonymous read grant on prefix {b}/{prefixes[b]}* (a public link created outside infra-config)",
                     change=f"`mc anonymous set none {b}/{prefixes[b].rstrip('/')}` (revoke the public link only)",
                     risk="Low: no consumer depends on the anonymous link (safety check)",
                     side_effects="Anyone holding the link loses access; named users keep their own credentials",
                     expected_outcome=f"Anonymous requests under {b}/{prefixes[b]} receive 403",
                     rollback_plan=f"`mc anonymous set download {b}/{prefixes[b].rstrip('/')}` (re-opens exposure)",
                     verification_requirement=req, safety=safety, params={"bucket": b, "prefix": prefixes[b]})
            else:
                _add(db, ctx.incident_id, 1, action_type="bucket.set_private", target=f"s3://{b}",
                     problem=f"{b} allows anonymous download", change=f"`mc anonymous set none {b}` (live fix)",
                     risk="Low: no consumer depends on anonymous access (safety check)",
                     side_effects="; ".join(f"{u['principal']} unaffected ({u['reason']})" for u in safety["unaffected"]) or "none observed",
                     expected_outcome=f"Anonymous requests to {b} receive 403", rollback_plan=f"`mc anonymous set download {b}`",
                     verification_requirement=req, safety=safety, params={"bucket": b})
            proposed += 1
            if rc.get("kind") == "CONFIG_COMMIT":
                reclass = None if (classes.get(b) or "") in ("pii", "confidential", "restricted") else "confidential"
                prev = connectors.worker("GET", "/infra/patch-preview", params={"bucket": b, **({"reclassify": reclass} if reclass else {})})
                bad_commits.append(rc["commit"]["sha"])
                _add(db, ctx.incident_id, 1, action_type="infra.patch_bucket_private", target="infra-config/buckets.yaml",
                     problem=f"buckets.yaml declares {b} public: true (commit {rc['commit']['sha'][:8]})",
                     change="Commit the patch below and run infra-sync", risk="Low: config change matches the live fix",
                     side_effects="infra-sync re-applies the bucket policy",
                     expected_outcome="Config and live state agree; a full re-sync cannot re-open the bucket",
                     rollback_plan="git revert the MALLYA commit", verification_requirement="buckets.yaml declares private; sync APPLIED",
                     params={"bucket": b, "incident_ref": ref, **({"reclassify": reclass} if reclass else {})},
                     patch_diff=prev["diff"], safety={"result": "N/A (config only)"})
                if reclass:
                    a = db.execute(select(RemediationAction).where(RemediationAction.incident_id == ctx.incident_id)
                                   .order_by(RemediationAction.created_at.desc())).scalars().first()
                    a.problem += f"; bucket is classified '{classes.get(b)}' but holds customer identifiers"
                    a.change = f"Commit the patch below (public: false, classification: {reclass}) and run infra-sync"
                proposed += 1
        if bad_commits:
            _add(db, ctx.incident_id, 1, action_type="infra.enable_policy_gate", target="infra-config/.mallya/gates.yaml",
                 problem="Nothing stops a PII bucket being made public again by a config commit",
                 change="Enable policy gate no_public_pii_buckets in the infra-sync pipeline",
                 risk="Low: blocks only configs that make pii/confidential buckets public",
                 side_effects="Future commits that make a sensitive bucket public are refused at sync",
                 expected_outcome=f"Re-applying commit {bad_commits[0][:8]} is BLOCKED",
                 rollback_plan="Remove the gate from .mallya/gates.yaml", verification_requirement="Regression: re-applying the bad commit is blocked",
                 params={"gate": "no_public_pii_buckets", "bad_commit": bad_commits[0]}, safety={"result": "N/A (preventive control)"})
            proposed += 1
        inc = db.get(Incident, ctx.incident_id)
        inc.status = "AWAITING_APPROVAL"
    summary = ctx.summarise("remediation.summary", {"proposed": proposed, "wave": 1, "held": len(held),
                                                    "held_reason": "; ".join(held)})
    return AgentOutput(summary=summary, confidence=0.9, data={"proposed": proposed, "held": held, "wave": 1})


def replan(ctx: Ctx, run_id: str) -> AgentOutput:
    """Wave N+1 from verification evidence (the residual exposures the verifier proved)."""
    with session_scope() as db:
        run = db.get(VerificationRun, run_id)
        inc = db.get(Incident, ctx.incident_id)
        actions = db.execute(select(RemediationAction).where(RemediationAction.incident_id == inc.id)).scalars().all()
        wave = max((a.wave for a in actions), default=1) + 1
        buckets = set((inc.scope or {}).get("buckets", []))
        probes = run.external_results
        new = 0
        if inc.exposure_type in ("CONSENT_MISMATCH", "SHADOW_AI_UPLOAD"):
            residual_vendor = [c for c in run.copy_hunt if c["kind"] == "vendor" and c.get("present")]
            for c in residual_vendor:
                fps = sorted({fp for s in db.execute(select(SubjectSet).where(SubjectSet.incident_id == inc.id)).scalars() for fp in s.fingerprints})
                _add(db, inc.id, wave, action_type="vendor.delete_subjects" if inc.exposure_type == "CONSENT_MISMATCH" else "vendor.ai_delete_uploads",
                     target=c["location"], problem=f"Verification {run.ref}: {c['matches']} subject(s) still present at the vendor",
                     change="Repeat the deletion request at the vendor", risk="Low", side_effects="none",
                     expected_outcome="0 fingerprint matches at the vendor", rollback_plan="Not reversible (deletion at third party)",
                     verification_requirement="Re-query the vendor store: 0 matches",
                     params={"subject_fingerprints": fps} if inc.exposure_type == "CONSENT_MISMATCH" else {"upload_ids": [u["upload_id"] for f in db.execute(select(Finding).where(Finding.incident_id == inc.id)).scalars() for u in (f.details.get("uploads") or [])]},
                     safety={"result": "from verification evidence"})
                new += 1
        open_buckets = {p["path"].strip("/").split("/", 1)[0] for p in probes
                        if p["outcome"] == "ACCESSIBLE" and not p.get("served_from_cache")}
        cached = sorted({p["path"] for p in probes if p["outcome"] == "ACCESSIBLE" and p.get("served_from_cache")})
        cached += [c["location"].removeprefix("cdn://cdn.meridian.sandbox") for c in run.copy_hunt
                   if c["kind"] == "cdn" and c.get("accessible") and c["location"].removeprefix("cdn://cdn.meridian.sandbox") not in cached]
        for b in sorted(open_buckets):
            mine = [a for a in actions if a.target == f"s3://{b}" and a.execution_status != "SUCCEEDED"]
            live = [a for a in mine if is_open(a)]
            held = next((a for a in live if a.approval_status == "HELD"), None)
            if held:
                held.approval_status = "PENDING"
                held.wave = wave
                held.safety = {**held.safety, "reconsidered": f"verification {run.ref} proved {b} still serves data externally"}
                chain.append(inc.id, "remediation.reproposed", "agent:remediation",
                             {"code": held.code, "reason": held.safety["reconsidered"], "wave": wave}, db=db)
                new += 1
            elif live:
                continue  # a fix for this bucket is already waiting for a decision or for execution
            elif (rejected := [a for a in mine if a.approval_status == "REJECTED"]):
                # The human rejected the only fix, but the verifier proves the bucket still leaks. Offer it again
                # (a person can reject it again); never execute it without a fresh approval.
                r = rejected[-1]
                note = f"{r.code} was rejected, but verification {run.ref} proved {b} still serves data externally"
                _add(db, inc.id, wave, action_type=r.action_type, target=r.target,
                     problem=f"Verification {run.ref}: {b} still serves data to anonymous clients ({r.code} was rejected)",
                     change=r.change, risk=r.risk, side_effects=r.side_effects, expected_outcome=r.expected_outcome,
                     rollback_plan=r.rollback_plan, verification_requirement=r.verification_requirement,
                     params=dict(r.params or {}), patch_diff=r.patch_diff, safety={**(r.safety or {}), "reconsidered": note})
                new += 1
            else:
                _add(db, inc.id, wave, action_type="bucket.set_private", target=f"s3://{b}",
                     problem=f"Verification {run.ref}: {b} still serves data to anonymous clients",
                     change=f"`mc anonymous set none {b}`", risk="Low", side_effects="none observed",
                     expected_outcome=f"Anonymous requests to {b} receive 403", rollback_plan=f"`mc anonymous set download {b}`",
                     verification_requirement="External GET returns 403", params={"bucket": b}, safety={"result": "from verification evidence"})
                new += 1
        if cached:
            db.flush()
            actions = db.execute(select(RemediationAction).where(RemediationAction.incident_id == inc.id)
                                 .order_by(RemediationAction.code)).scalars().all()
            origin_codes = [a.code for a in actions if a.target in {f"s3://{b}" for b in buckets} and is_open(a)]
            paths = sorted(set(cached))
            purges = [a for a in actions if a.action_type == "cdn.purge" and is_open(a)]
            keep = next((a for a in purges if a.approval_status == "APPROVED"), purges[0] if purges else None)
            if keep and (keep.approval_status != "APPROVED" or set(paths) <= set((keep.params or {}).get("paths", []))):
                # Reuse the purge that is already waiting instead of stacking a new one per verification run.
                if keep.approval_status != "APPROVED":
                    keep.params = {"paths": sorted(set(paths) | set((keep.params or {}).get("paths", [])))}
                    keep.problem = (f"Verification {run.ref}: the CDN edge still serves cached copies "
                                    f"({len(keep.params['paths'])} path(s))")
                keep.depends_on = origin_codes
                chain.append(inc.id, "remediation.updated", "agent:remediation",
                             {"code": keep.code, "verification": run.ref, "paths": keep.params.get("paths"),
                              "depends_on": origin_codes}, db=db)
            else:
                keep = _add(db, inc.id, wave, action_type="cdn.purge", target="cdn://cdn.meridian.sandbox",
                            problem=f"Verification {run.ref}: the CDN edge still serves cached copies ({len(paths)} path(s))",
                            change="Purge the cached paths via cdn-admin (after origins are private)",
                            risk="Low: next request re-fetches from the (now private) origin and is denied",
                            side_effects="Cold cache for these paths", expected_outcome="External GET of each path is denied by the origin",
                            rollback_plan="None needed (cache refills only if the origin is public)",
                            verification_requirement="External GET of every purged path returns a genuine 403 (cache MISS)",
                            params={"paths": paths}, depends_on=origin_codes, safety={"result": "N/A (cache)"})
                new += 1
            for a in purges:
                if a is not keep and a.approval_status != "APPROVED":
                    a.approval_status = "SUPERSEDED"
                    chain.append(inc.id, "remediation.superseded", "agent:remediation",
                                 {"code": a.code, "superseded_by": keep.code, "verification": run.ref}, db=db)
        inc.status = "AWAITING_APPROVAL"
    summary = ctx.summarise("remediation.summary", {"proposed": new, "wave": wave, "held": 0})
    return AgentOutput(summary=summary, confidence=0.9, data={"proposed": new, "wave": wave})


def execute(ctx: Ctx) -> AgentOutput:
    """Execute every APPROVED, not-yet-run action, dependencies first."""
    done, failed, skipped = [], [], []
    with session_scope() as db:
        inc = db.get(Incident, ctx.incident_id)
        inc.status = "REMEDIATING"
        every = db.execute(select(RemediationAction).where(RemediationAction.incident_id == inc.id)).scalars().all()
        order, blocked = execution_plan(every)
        by_code = {a.code: a for a in every}
        # Dependencies first (a re-proposed fix can have a higher code than the purge that waits for it).
        ids = [by_code[c].id for c in order] + [by_code[c].id for c in sorted(blocked)]
    for aid in ids:
        with session_scope() as db:
            a = db.get(RemediationAction, aid)
            appr = db.execute(select(Approval).where(Approval.action_id == aid, Approval.decision == "APPROVED")
                              .order_by(Approval.created_at.desc())).scalars().first()
            if not appr:  # defence in depth: never run without a recorded approval
                skipped.append(a.code)
                continue
            deps = db.execute(select(RemediationAction).where(RemediationAction.incident_id == a.incident_id,
                                                              RemediationAction.code.in_(a.depends_on or []))).scalars().all()
            # Dependencies run earlier in this loop (code order) and are committed before we get here.
            if any(d.execution_status != "SUCCEEDED" for d in deps):
                skipped.append(a.code)
                continue
            token = mint(a, appr)
            a.execution_status = "RUNNING"
            code, atype, params = a.code, a.action_type, dict(a.params)
        ctx.step(f"Executing {code} ({atype})")
        try:
            res = connectors.worker("POST", "/actions/execute",
                                    json={"action_type": atype, "params": params, "approval": token}, timeout=120)["result"]
            status = "SUCCEEDED"
            done.append(code)
        except connectors.ConnectorError as exc:
            res, status = {"error": str(exc)}, "FAILED"
            failed.append(code)
        with session_scope() as db:
            a = db.get(RemediationAction, aid)
            a.execution_status, a.result, a.executed_at = status, res, now()
            chain.append(a.incident_id, "remediation.executed", "agent:remediation",
                         {"code": code, "action_type": atype, "status": status, "approval_id": token["approval_id"],
                          "approved_by": token["approved_by"], "result": res}, db=db)
        audit("remediation.executed", actor="agent:remediation", target_type="action", target_id=aid,
              details={"code": code, "status": status, "approved_by": token["approved_by"]})
        events.emit("beat", f"{code} {status.lower()}: {atype}", drill_id=ctx.drill_id, incident_id=ctx.incident_id,
                    agent="remediation", data={"code": code, "status": status, "result": res})
    summary = (f"Executed {len(done)} approved action(s)" + (f": {', '.join(done)}" if done else "")
               + (f"; {len(failed)} failed ({', '.join(failed)})" if failed else "")
               + (f"; {len(skipped)} waiting on dependencies/approval ({', '.join(skipped)})" if skipped else "") + ".")
    return AgentOutput(summary=summary, confidence=1.0 if not failed else 0.5,
                       evidence_refs=[f"action:{c}" for c in done], data={"executed": done, "failed": failed, "skipped": skipped})


def plan_vendor(ctx: Ctx, etype: str, scope: dict) -> AgentOutput:
    """Integration exposures: stop the flow, remove the third-party copy, fix the cause."""
    with session_scope() as db:
        fps = sorted({fp for s in db.execute(select(SubjectSet).where(SubjectSet.incident_id == ctx.incident_id)).scalars()
                      for fp in s.fingerprints})
        fnd = db.execute(select(Finding).where(Finding.incident_id == ctx.incident_id)).scalars().first()
        n = 0
        if etype == "CONSENT_MISMATCH":
            job = scope["job_id"]
            _add(db, ctx.incident_id, 1, action_type="integration.disable_sync", target=f"job://{job}",
                 problem=f"{job} keeps sending customers who withdrew marketing consent to the vendor",
                 change=f"Disable {job} (containment)", risk="Medium: the campaign sync pauses for all members",
                 side_effects="Marketing must re-enable the job after the consent filter is in place",
                 expected_outcome="No further sync calls", rollback_plan=f"Re-enable {job}",
                 verification_requirement="A forced sync run is refused", params={"job_id": job},
                 safety={"result": "NO_DEPENDENCY", "window": "integration registry", "events_examined": 0,
                         "unaffected": [{"principal": "consented members", "reason": "re-synced once the filter is on"}]})
            _add(db, ctx.incident_id, 1, action_type="vendor.delete_subjects", target=f"vendor://{scope['vendor_store']}",
                 problem=f"{len(fps)} withdrawn-consent subjects are held by the vendor",
                 change=f"Request deletion of exactly those {len(fps)} subjects at Northwind (matched locally by keyed fingerprint)",
                 risk="Low: only withdrawn-consent subjects are removed", side_effects="None for consented members",
                 expected_outcome="0 withdrawn-consent fingerprints at the vendor", rollback_plan="Not reversible (deletion at third party)",
                 verification_requirement="Re-query the vendor store: 0 matches", params={"subject_fingerprints": fps},
                 safety={"result": "N/A (deletion of non-consented data)"})
            _add(db, ctx.incident_id, 1, action_type="integration.enable_consent_filter", target=f"job://{job}",
                 problem="The sync job does not filter customers who withdrew consent (root cause)",
                 change="Set filter_withdrawn_consent = true on the job", risk="Low", side_effects="Withdrawn customers are never synced",
                 expected_outcome="A future sync excludes withdrawn customers", rollback_plan="Set the flag back to false (not recommended)",
                 verification_requirement="Adversarial re-sync sends 0 withdrawn subjects", params={"job_id": job},
                 safety={"result": "N/A (preventive control)"})
            n = 3
        else:
            ids = [u["upload_id"] for u in (fnd.details.get("uploads", []) if fnd else [])]
            _add(db, ctx.incident_id, 1, action_type="vendor.ai_delete_uploads", target=f"vendor://{scope['vendor_store']}",
                 problem=f"{scope['vendor']} holds {len(fps)} identifiable subjects from {len(ids)} upload(s)",
                 change=f"File a deletion request for upload(s) {', '.join(map(str, ids))} through the vendor API",
                 risk="Low", side_effects="The employee loses the AI summary", expected_outcome="0 fingerprint matches at the vendor",
                 rollback_plan="Not reversible", verification_requirement="Re-query the vendor store: 0 matches",
                 params={"upload_ids": ids}, safety={"result": "N/A (deletion at unapproved vendor)"})
            _add(db, ctx.incident_id, 1, action_type="integration.block_vendor", target=f"registry://{scope['integration_id']}",
                 problem=f"{scope['vendor']} is not an approved integration and nothing blocks uploads (root cause)",
                 change=f"Register {scope['vendor']} as BLOCKED in the integration registry (egress governance)",
                 risk="Low", side_effects="Employees cannot use this tool for customer data",
                 expected_outcome="Registry lists the vendor as blocked", rollback_plan="Remove the registry entry",
                 verification_requirement="Registry shows blocked=true",
                 params={"integration_id": scope["integration_id"], "vendor": scope["vendor"]}, safety={"result": "N/A (preventive control)"})
            n = 2
        inc = db.get(Incident, ctx.incident_id)
        inc.status = "AWAITING_APPROVAL"
    summary = ctx.summarise("remediation.summary", {"proposed": n, "wave": 1, "held": 0})
    return AgentOutput(summary=summary, confidence=0.9, data={"proposed": n, "wave": 1})
