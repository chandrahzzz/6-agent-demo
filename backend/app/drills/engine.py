"""Breach drill engine: plant a scenario in the sandbox, run real attacker traffic, then let
the agents work. The harness record (setup log, attacker results) is stored on the drill row
for operators; agents never read it - they work only from inventory, scans and logs.
"""
from __future__ import annotations

import time

from sqlalchemy import delete, select, update

from .. import connectors
from ..agents import base, hunter
from ..audit.log import audit
from ..core import events
from ..core.db import session_scope
from ..investigation import ingest
from ..models import (KV, AccessEvent, AgentEvent, AgentExecution, Approval, Asset, AssetRelationship, BlastRadius,
                      ComplianceDraft, Drill, EvidenceEvent, EvidencePack, Finding, Incident, Investigation, LLMCall,
                      Obligation, PrivacyViolation, RemediationAction, SubjectSet, User, VerificationRun, now)
from ..orchestration import graph
from ..remediation.approvals import params_sha256

PRESENTER = "analyst@meridian.demo"


def reset_control_plane(keep_drill_id: str | None = None) -> None:
    """Clear incident data. Drill rows are kept as history (unlinked); the running drill keeps its events."""
    with session_scope() as db:
        for m in (Approval, RemediationAction, VerificationRun, SubjectSet, Investigation, BlastRadius, ComplianceDraft,
                  Obligation, EvidencePack, EvidenceEvent, Finding, AgentExecution, Incident,
                  AssetRelationship, Asset, AccessEvent, LLMCall):
            db.execute(delete(m))
        db.execute(delete(AgentEvent).where((AgentEvent.drill_id != keep_drill_id) | AgentEvent.drill_id.is_(None)))
        db.execute(update(Drill).values(incident_id=None))
        db.execute(delete(PrivacyViolation).where(PrivacyViolation.is_test.is_(False)))
        db.execute(delete(KV).where(KV.key == "ingest:nginx"))


def reset_sandbox(seed: int, keep_drill_id: str | None = None) -> dict:
    """Rebuild the sandbox deterministically and clear incident data (users, audit log, benchmark runs kept)."""
    reset_control_plane(keep_drill_id)
    res = connectors.worker("POST", "/seed", json={"seed": seed}, timeout=300)
    ingest.pull_nginx()  # advance past log lines from before the reset
    with session_scope() as db:
        db.execute(delete(AccessEvent))
    ingest.import_synthetic_history()
    return res


def _beat(drill_id: str, msg: str, **data) -> None:
    events.emit("beat", msg, drill_id=drill_id, data=data)


def approve_pending(incident_id: str, *, presenter: bool, user: User) -> list[str]:
    """Approve every PENDING action (never HELD ones) for the given user."""
    approved = []
    with session_scope() as db:
        acts = db.execute(select(RemediationAction).where(RemediationAction.incident_id == incident_id,
                                                          RemediationAction.approval_status == "PENDING")).scalars().all()
        for a in acts:
            db.add(Approval(action_id=a.id, incident_id=incident_id, decision="APPROVED", user_id=user.id,
                            user_email=user.email, role=user.role, presenter_auto=presenter,
                            reason="presenter auto-approve (demo)" if presenter else "", params_sha256=params_sha256(a.params)))
            a.approval_status = "APPROVED"
            approved.append(a.code)
        if approved:
            from ..evidence import chain
            chain.append(incident_id, "approval.recorded", user.email,
                         {"actions": approved, "decision": "APPROVED", "role": user.role, "presenter_auto_approve": presenter}, db=db)
    if approved:
        audit("remediation.approved", actor=user.email, actor_role=user.role, target_type="incident", target_id=incident_id,
              details={"actions": approved, "presenter_auto_approve": presenter})
    return approved


def run_drill(drill_id: str) -> None:
    with session_scope() as db:
        d = db.get(Drill, drill_id)
        d.status, d.started_at = "RUNNING", now()
        scenario, params, seed, auto, demo = d.scenario_id, dict(d.params), d.seed, d.auto_approve, d.demo
    harness: dict = {}
    try:
        if demo or params.get("reset", True):
            _beat(drill_id, "Resetting the Meridian Bank sandbox from seed", seed=seed)
            harness["reset"] = reset_sandbox(seed, drill_id)
        _beat(drill_id, f"Planting scenario {scenario}")
        setup = connectors.worker("POST", f"/scenarios/{scenario}/setup", json={"params": params})
        harness["setup"] = setup
        variant = params.get("access_variant", "A")
        if setup.get("attack_targets"):
            atk = connectors.attacker("POST", "/run", json={"variant": variant, "targets": setup["attack_targets"]})
            harness["attacker"] = atk
            _beat(drill_id, f"Attacker traffic sent from external_net (variant {variant})", requests=len(atk["requests"]))
        with session_scope() as db:
            db.get(Drill, drill_id).harness = harness
        t_start = time.monotonic()
        out = base.run("exposure_hunter", hunter.sweep, incident_id=None, drill_id=drill_id)
        detect_ms = round((time.monotonic() - t_start) * 1000, 1)
        incident_ids = out.data["incident_ids"]
        with session_scope() as db:
            for iid in incident_ids:
                inc = db.get(Incident, iid)
                inc.scenario_id, inc.timings = scenario, {**(inc.timings or {}), "detect_ms": detect_ms}
            db.get(Drill, drill_id).incident_id = incident_ids[0] if incident_ids else None
        for iid in incident_ids:
            from ..evidence import chain
            with session_scope() as db:
                inc = db.get(Incident, iid)
                chain.append(iid, "incident.detected", "agent:exposure_hunter",
                             {"ref": inc.ref, "title": inc.title, "scope": inc.scope, "detected_at": inc.detected_at.isoformat()}, db=db)
            _beat(drill_id, "Exposure detected", incident_id=iid)
            state = graph.triage_graph().invoke({"incident_id": iid, "drill_id": drill_id, "timings": {}})
            if auto:
                with session_scope() as db:
                    presenter = db.execute(select(User).where(User.email == PRESENTER)).scalar_one()
                for wave in range(1, 4):
                    codes = approve_pending(iid, presenter=True, user=presenter)
                    _beat(drill_id, f"Presenter auto-approve (as {PRESENTER}): {', '.join(codes) or 'nothing pending'}",
                          incident_id=iid)
                    if not codes:
                        break
                    state = graph.fix_graph().invoke({"incident_id": iid, "drill_id": drill_id, "timings": state.get("timings", {})})
                    if state.get("verdict") == "VERIFIED_FIXED":
                        break
            else:
                _beat(drill_id, "Waiting for human approval", incident_id=iid)
        with session_scope() as db:
            d = db.get(Drill, drill_id)
            d.status, d.finished_at = "COMPLETED" if incident_ids else "COMPLETED_NO_INCIDENT", now()
        events.emit("drill.completed", "Drill finished", drill_id=drill_id)
    except Exception as exc:  # noqa: BLE001
        with session_scope() as db:
            d = db.get(Drill, drill_id)
            d.status, d.error, d.finished_at, d.harness = "FAILED", f"{type(exc).__name__}: {exc}"[:1000], now(), harness
        events.emit("drill.failed", f"Drill failed: {type(exc).__name__}: {exc}"[:500], drill_id=drill_id)
        raise


def continue_after_approval(incident_id: str) -> dict:
    with session_scope() as db:
        inc = db.get(Incident, incident_id)
        drill_id, timings = inc.drill_id, dict(inc.timings or {})
    return graph.fix_graph().invoke({"incident_id": incident_id, "drill_id": drill_id, "timings": timings})

