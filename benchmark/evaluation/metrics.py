"""Scoring a drill against hidden ground truth. Every number comes from stored run data."""
from __future__ import annotations

from statistics import mean

from sqlalchemy import select

from app import connectors
from app.core.db import session_scope
from app.models import Approval, BlastRadius, Finding, Incident, Investigation, RemediationAction, VerificationRun
from app.remediation.approvals import mint

DECOY_ASSETS = ("catalog/products.csv", "finance/invoices-2026-q3.csv", "qa_fixture_cases")


def _key_of(inc: Incident) -> str:
    s = inc.scope or {}
    if inc.exposure_type.startswith("LITE:"):
        return s.get("asset", "")
    return s.get("primary") or s.get("key") or ""


def score_run(drill_id: str, truth: dict) -> dict:
    with session_scope() as db:
        incs = db.execute(select(Incident).where(Incident.drill_id == drill_id)).scalars().all()
        decoy_hits = db.execute(select(Finding).where(Finding.drill_id == drill_id, Finding.suppressed.is_(False))).scalars().all()
        decoy_fp = sum(1 for f in decoy_hits if any(d in f.asset_ref for d in DECOY_ASSETS))
        got = {(i.exposure_type, _key_of(i)): i for i in incs}
        want = {(e["type"], e["key"]) for e in truth["incidents"]}
        tp = len(want & set(got))
        fp = len(set(got) - want) + decoy_fp
        fn = len(want - set(got))
        out: dict = {"detection": {"tp": tp, "fp": fp, "fn": fn, "decoy_false_positives": decoy_fp},
                     "incidents": [{"ref": i.ref, "type": i.exposure_type, "key": _key_of(i), "status": i.status} for i in incs]}
        match = next((got[k] for k in want if k in got), None)
        if not match:
            return out
        inv = db.execute(select(Investigation).where(Investigation.incident_id == match.id)).scalars().first()
        out["verdict"] = {"expected": truth["verdict"], "got": match.access_verdict, "correct": match.access_verdict == truth["verdict"]}
        out["timings"] = {k: v for k, v in (match.timings or {}).items() if k.endswith("_ms")}
        if truth.get("lite"):
            recs = db.execute(select(RemediationAction).where(RemediationAction.incident_id == match.id)).scalars().all()
            out["recommendation"] = bool(recs) and all(r.approval_status == "RECOMMENDATION" for r in recs)
            return out

        rc = truth.get("root_cause", {})
        cause = (inv.root_cause or [{}])[0] if inv else {}
        ok = cause.get("kind") == rc.get("kind")
        if rc.get("author"):
            ok = ok and (cause.get("commit") or {}).get("author") == rc["author"] and (cause.get("commit") or {}).get("subject") == rc["subject"]
        if rc.get("principal"):
            ok = ok and rc["principal"] in (cause.get("statement") or "")
        out["root_cause"] = {"expected": rc, "got": {"kind": cause.get("kind"), "statement": cause.get("statement")}, "correct": ok}

        br = db.execute(select(BlastRadius).where(BlastRadius.incident_id == match.id)).scalars().first()
        loc_ok = True
        for loc, n in (truth.get("location_counts") or {}).items():
            have = next((x["matches"] for x in (br.locations if br else []) if x["location"] == loc), None)
            loc_ok = loc_ok and have == n
        out["blast_radius"] = {"expected_records": truth["record_count"], "got_records": br.record_count if br else None,
                               "correct": bool(br) and br.record_count == truth["record_count"],
                               "fingerprint_locations_correct": loc_ok}

        acts = db.execute(select(RemediationAction).where(RemediationAction.incident_id == match.id)).scalars().all()
        executed = [a for a in acts if a.execution_status == "SUCCEEDED"]
        types = {a.action_type for a in executed}
        approvals = {a.id: db.execute(select(Approval).where(Approval.action_id == a.id, Approval.decision == "APPROVED")).scalars().first()
                     for a in executed}
        compliant = all(approvals[a.id] and a.executed_at and approvals[a.id].created_at <= a.executed_at for a in executed)
        out["remediation"] = {"expected_actions": sorted(truth["expected_actions"]), "executed": sorted(types),
                              "correct": truth["expected_actions"] <= types and not any(a.execution_status == "FAILED" for a in acts),
                              "approval_compliance": compliant}
        # idempotency: replay the first executed action's approval against the worker; it must not act twice
        idem = None
        if executed:
            a = executed[0]
            tok = mint(a, approvals[a.id])
            try:
                res = connectors.worker("POST", "/actions/execute", json={"action_type": a.action_type, "params": a.params, "approval": tok})
                idem = bool(res["result"].get("replayed"))
            except connectors.ConnectorError:
                idem = False
        out["remediation"]["idempotent"] = idem

        runs = db.execute(select(VerificationRun).where(VerificationRun.incident_id == match.id).order_by(VerificationRun.run_number)).scalars().all()
        first, last = (runs[0], runs[-1]) if runs else (None, None)
        res = " ".join(first.residual) if first else ""
        out["verification"] = {
            "first_expected": truth["first_verification"], "first_got": first.verdict if first else None,
            "final_expected": truth["final_verification"], "final_got": last.verdict if last else None,
            "first_correct": bool(first) and first.verdict == truth["first_verification"],
            "final_correct": bool(last) and last.verdict == truth["final_verification"],
            "residual_expected": truth["residual"], "residual_got": first.residual if first else [],
            "residual_detected": all(kind in res for kind in truth["residual"]) if truth["residual"] else (not first or not first.residual),
            "runs": len(runs),
        }
    return out


def _ratio(xs: list[bool]) -> dict:
    xs = [x for x in xs if x is not None]
    return {"value": round(sum(xs) / len(xs), 3) if xs else None, "n": len(xs)}


def aggregate(runs: list[dict]) -> dict:
    ok = [r for r in runs if "score" in r]
    tp = sum(r["score"]["detection"]["tp"] for r in ok)
    fp = sum(r["score"]["detection"]["fp"] for r in ok)
    fn = sum(r["score"]["detection"]["fn"] for r in ok) + sum(1 for r in runs if "score" not in r)  # a crashed run detected nothing
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else 0.0
    s = [r["score"] for r in ok]
    m = {
        "sample_size": len(runs), "failed_runs": sum(1 for r in runs if r.get("error")),
        "detection": {"tp": tp, "fp": fp, "fn": fn, "precision": round(precision, 3) if precision is not None else None,
                      "recall": round(recall, 3) if recall is not None else None, "f1": round(f1, 3),
                      "decoy_false_positives": sum(x["detection"]["decoy_false_positives"] for x in s)},
        "verdict_accuracy": _ratio([x["verdict"]["correct"] for x in s if "verdict" in x]),
        "verdict_accuracy_attempt_vs_success": _ratio([x["verdict"]["correct"] for x in s if "verdict" in x
                                                       and x["verdict"]["expected"] in ("ACCESS_ATTEMPTED_NOT_SUCCESSFUL", "LIKELY_EXFILTRATED")]),
        "root_cause_accuracy": _ratio([x["root_cause"]["correct"] for x in s if "root_cause" in x]),
        "blast_radius_accuracy": _ratio([x["blast_radius"]["correct"] for x in s if "blast_radius" in x]),
        "fingerprint_accuracy": _ratio([x["blast_radius"]["fingerprint_locations_correct"] for x in s if "blast_radius" in x]),
        "remediation_correctness": _ratio([x["remediation"]["correct"] for x in s if "remediation" in x]),
        "approval_compliance": _ratio([x["remediation"]["approval_compliance"] for x in s if "remediation" in x]),
        "idempotency": _ratio([x["remediation"]["idempotent"] for x in s if "remediation" in x]),
        "verification_accuracy": _ratio([x["verification"]["final_correct"] and x["verification"]["first_correct"] for x in s if "verification" in x]),
        "residual_exposure_detection": _ratio([x["verification"]["residual_detected"] for x in s if "verification" in x and x["verification"]["residual_expected"]]),
        "lite_recommendations": _ratio([x["recommendation"] for x in s if "recommendation" in x]),
    }
    timings: dict[str, list[float]] = {}
    for x in s:
        for k, v in (x.get("timings") or {}).items():
            timings.setdefault(k, []).append(v)
    m["timings_mean_ms"] = {k: round(mean(v), 1) for k, v in sorted(timings.items())}

    def part(keys: list[str]) -> float:
        """Mean of the metrics that have samples; a metric with n = 0 is excluded, not scored as 0."""
        vals = [m[k]["value"] for k in keys if m[k]["value"] is not None]
        return mean(vals) if vals else 0.0
    det = m["detection"]["f1"]
    inv = part(["verdict_accuracy", "root_cause_accuracy", "blast_radius_accuracy"])
    rem = part(["remediation_correctness", "approval_compliance", "idempotency"])
    ver = part(["verification_accuracy", "residual_exposure_detection", "fingerprint_accuracy"])
    m["composite"] = {"value": round(30 * det + 25 * inv + 25 * rem + 20 * ver, 1),
                      "parts": {"detection_30": round(30 * det, 1), "investigation_25": round(25 * inv, 1),
                                "remediation_25": round(25 * rem, 1), "verification_20": round(20 * ver, 1)},
                      "label": "project-defined, not an industry standard"}
    return m
