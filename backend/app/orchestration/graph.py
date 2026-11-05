"""LangGraph orchestration of the six agents.

triage graph:  investigation -> blast_radius -> risk -> remediation_plan -> compliance_drafts
fix graph:     execute_approved -> adversarial_verification -> (VERIFIED_FIXED ? evidence_pack : replan)

Humans sit between the two graphs: nothing in the fix graph runs until an analyst approves
actions (or the visibly-labelled presenter auto-approve does so as analyst@meridian.demo).
"""
from __future__ import annotations

import time
from typing import TypedDict

from langgraph.graph import END, START, StateGraph
from sqlalchemy import select

from ..agents import base, blast_radius, compliance, investigation, remediation, verification
from ..core import events
from ..core.db import session_scope
from ..models import BlastRadius, Finding, Incident, Investigation, now
from ..risk import score as risk


class State(TypedDict, total=False):
    incident_id: str
    drill_id: str | None
    verdict: str
    run_id: str
    timings: dict


def _timed(state: State, key: str, t0: float) -> dict:
    t = dict(state.get("timings") or {})
    t[key] = round((time.monotonic() - t0) * 1000, 1)
    return t


def n_investigate(s: State) -> State:
    t0 = time.monotonic()
    base.run("investigation", investigation.investigate, incident_id=s["incident_id"], drill_id=s.get("drill_id"))
    return {"timings": _timed(s, "verdict_ms", t0)}


def n_blast(s: State) -> State:
    t0 = time.monotonic()
    base.run("blast_radius", blast_radius.analyse, incident_id=s["incident_id"], drill_id=s.get("drill_id"))
    return {"timings": _timed(s, "blast_radius_ms", t0)}


def n_risk(s: State) -> State:
    apply_risk(s["incident_id"])
    return {}


def n_plan(s: State) -> State:
    base.run("remediation", remediation.plan, incident_id=s["incident_id"], drill_id=s.get("drill_id"))
    return {}


def n_drafts(s: State) -> State:
    t0 = time.monotonic()
    base.run("compliance_evidence", compliance.draft, incident_id=s["incident_id"], drill_id=s.get("drill_id"))
    t = _timed(s, "draft_ms", t0)
    _save_timings(s["incident_id"], t)
    return {"timings": t}


def n_execute(s: State) -> State:
    t0 = time.monotonic()
    base.run("remediation", remediation.execute, incident_id=s["incident_id"], drill_id=s.get("drill_id"), retries=0)
    t = _timed(s, "remediation_ms", t0)
    return {"timings": t}


def n_verify(s: State) -> State:
    t0 = time.monotonic()
    out = base.run("adversarial_verification", verification.verify, incident_id=s["incident_id"], drill_id=s.get("drill_id"),
                   retries=0)
    v = out.data["verdict"]
    events.emit("beat", f"Verification {out.data['run_ref']}: {v}", drill_id=s.get("drill_id"), incident_id=s["incident_id"],
                agent="adversarial_verification", data={"verdict": v, "residual": out.data["residual"]})
    return {"verdict": v, "run_id": out.data["run_id"], "timings": _timed(s, "verification_ms", t0)}


def n_replan(s: State) -> State:
    base.run("remediation", lambda ctx: remediation.replan(ctx, s["run_id"]), incident_id=s["incident_id"],
             drill_id=s.get("drill_id"))
    _save_timings(s["incident_id"], s.get("timings") or {})
    return {}


def n_pack(s: State) -> State:
    t0 = time.monotonic()
    base.run("compliance_evidence", compliance.draft, incident_id=s["incident_id"], drill_id=s.get("drill_id"))
    base.run("compliance_evidence", compliance.build_pack, incident_id=s["incident_id"], drill_id=s.get("drill_id"))
    t = _timed(s, "evidence_pack_ms", t0)
    _save_timings(s["incident_id"], t)
    return {"timings": t}


def _route(s: State) -> str:
    return "pack" if s.get("verdict") == "VERIFIED_FIXED" else "replan"


def _save_timings(incident_id: str, t: dict) -> None:
    with session_scope() as db:
        inc = db.get(Incident, incident_id)
        merged = dict(inc.timings or {})
        merged.update({k: v for k, v in t.items() if k.endswith("_ms")})
        if inc.verified_fixed_at and inc.detected_at:
            merged["detect_to_verified_fix_wall_ms"] = round((inc.verified_fixed_at - inc.detected_at).total_seconds() * 1000, 1)
        inc.timings = merged


def triage_graph():
    g = StateGraph(State)
    for name, fn in [("investigation", n_investigate), ("blast_radius", n_blast), ("risk", n_risk),
                     ("remediation_plan", n_plan), ("compliance_drafts", n_drafts)]:
        g.add_node(name, fn)
    g.add_edge(START, "investigation")
    g.add_edge("investigation", "blast_radius")
    g.add_edge("blast_radius", "risk")
    g.add_edge("risk", "remediation_plan")
    g.add_edge("remediation_plan", "compliance_drafts")
    g.add_edge("compliance_drafts", END)
    return g.compile()


def fix_graph():
    g = StateGraph(State)
    g.add_node("execute", n_execute)
    g.add_node("verify", n_verify)
    g.add_node("replan", n_replan)
    g.add_node("pack", n_pack)
    g.add_edge(START, "execute")
    g.add_edge("execute", "verify")
    g.add_conditional_edges("verify", _route, {"pack": "pack", "replan": "replan"})
    g.add_edge("replan", END)
    g.add_edge("pack", END)
    return g.compile()


def verify_only_graph():
    g = StateGraph(State)
    g.add_node("verify", n_verify)
    g.add_node("replan", n_replan)
    g.add_node("pack", n_pack)
    g.add_edge(START, "verify")
    g.add_conditional_edges("verify", _route, {"pack": "pack", "replan": "replan"})
    g.add_edge("replan", END)
    g.add_edge("pack", END)
    return g.compile()


def apply_risk(incident_id: str) -> dict:
    with session_scope() as db:
        inc = db.get(Incident, incident_id)
        br = db.execute(select(BlastRadius).where(BlastRadius.incident_id == incident_id).order_by(BlastRadius.created_at.desc())).scalars().first()
        inv = db.execute(select(Investigation).where(Investigation.incident_id == incident_id).order_by(Investigation.created_at.desc())).scalars().first()
        fnds = db.execute(select(Finding).where(Finding.incident_id == incident_id)).scalars().all()
        cats = sorted({c for f in fnds for c in (f.data_categories or {})})
        partner = bool(inv and inv.evidence.get("partner"))
        r = risk.score(exposure_type=inc.exposure_type, categories=cats, public=inc.exposure_type in ("PUBLIC_STORAGE", "PUBLIC_EXPORT_LINK"),
                       record_count=br.record_count if br else 0, asset_count=len((inc.scope or {}).get("buckets", [])) or 1,
                       access_verdict=inc.access_verdict, encrypted_at_rest=False, replicated=bool(br and sum(1 for loc in br.locations if loc["present"]) > 1),
                       third_party=partner or inc.exposure_type in ("SHADOW_AI_UPLOAD", "CONSENT_MISMATCH"))
        inc.risk_score, inc.severity, inc.risk_factors = r["score"], r["band"], r["factors"]
        inc.updated_at = now()
        return r
