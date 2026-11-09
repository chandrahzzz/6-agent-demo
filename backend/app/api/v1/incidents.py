from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...audit.log import audit
from ...core import jobs
from ...core.db import get_db
from ...core.errors import ApiError
from ...core.ratelimit import action_limit
from ...core.security import ANY_USER, CAN_APPROVE, CAN_OPERATE
from ...drills import engine
from ...evidence import chain
from ...remediation.deps import describe_blocked, execution_plan
from ...models import (AgentExecution, Approval, BlastRadius, ComplianceDraft, EvidencePack, Finding, Incident,
                       Investigation, Obligation, RemediationAction, User, VerificationRun, now)
from ..util import Page, get_or_404, paginate, row

router = APIRouter(prefix="/incidents", tags=["incidents"], dependencies=[Depends(ANY_USER)])
CLOSABLE_FIXED = "VERIFIED_FIXED"


def _latest(db: Session, model, incident_id: str):
    return db.execute(select(model).where(model.incident_id == incident_id).order_by(model.created_at.desc())).scalars().first()


@router.get("")
def list_incidents(page: Page = Depends(), status: str | None = None, db: Session = Depends(get_db)) -> dict:
    q = select(Incident).order_by(Incident.detected_at.desc())
    if status:
        q = q.where(Incident.status == status)
    return paginate(db, q, page)


@router.get("/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)) -> dict:
    inc = get_or_404(db, Incident, incident_id, "Incident")
    acts = db.execute(select(RemediationAction).where(RemediationAction.incident_id == inc.id)).scalars().all()
    runs = db.execute(select(VerificationRun.ref, VerificationRun.verdict).where(VerificationRun.incident_id == inc.id)
                      .order_by(VerificationRun.run_number)).all()
    return {**row(inc), "counts": {
        "actions": len(acts), "pending_approval": sum(a.approval_status in ("PENDING", "HELD") for a in acts),
        "approved_not_executed": sum(a.approval_status == "APPROVED" and a.execution_status == "NOT_STARTED" for a in acts),
        "verification_runs": len(runs), "evidence_events": chain.count(db, inc.id)},
        "verification_history": [{"ref": r, "verdict": v} for r, v in runs],
        "busy": jobs.running(f"incident:{inc.id}") or (inc.drill_id is not None and jobs.running(f"drill:{inc.drill_id}"))}


@router.get("/{incident_id}/findings")
def findings(incident_id: str, db: Session = Depends(get_db)) -> dict:
    inc = get_or_404(db, Incident, incident_id, "Incident")
    items = db.execute(select(Finding).where(Finding.incident_id == inc.id).order_by(Finding.created_at)).scalars().all()
    decoys = db.execute(select(Finding).where(Finding.drill_id == inc.drill_id, Finding.incident_id.is_(None))).scalars().all() if inc.drill_id else []
    return {"items": [row(f) for f in items], "suppressed": [row(f) for f in decoys]}


@router.get("/{incident_id}/investigation")
def investigation(incident_id: str, db: Session = Depends(get_db)) -> dict:
    get_or_404(db, Incident, incident_id, "Incident")
    inv = _latest(db, Investigation, incident_id)
    return row(inv) if inv else {}


@router.get("/{incident_id}/blast-radius")
def blast(incident_id: str, db: Session = Depends(get_db)) -> dict:
    get_or_404(db, Incident, incident_id, "Incident")
    br = _latest(db, BlastRadius, incident_id)
    return row(br) if br else {}


@router.get("/{incident_id}/remediation")
def remediation(incident_id: str, db: Session = Depends(get_db)) -> dict:
    get_or_404(db, Incident, incident_id, "Incident")
    acts = db.execute(select(RemediationAction).where(RemediationAction.incident_id == incident_id)
                      .order_by(RemediationAction.code)).scalars().all()
    appr = db.execute(select(Approval).where(Approval.incident_id == incident_id).order_by(Approval.created_at)).scalars().all()
    by_action: dict[str, list] = {}
    for a in appr:
        by_action.setdefault(a.action_id, []).append(row(a))
    return {"items": [{**row(a), "approvals": by_action.get(a.id, [])} for a in acts]}


@router.get("/{incident_id}/verification")
def verification(incident_id: str, db: Session = Depends(get_db)) -> dict:
    get_or_404(db, Incident, incident_id, "Incident")
    runs = db.execute(select(VerificationRun).where(VerificationRun.incident_id == incident_id)
                      .order_by(VerificationRun.run_number)).scalars().all()
    return {"items": [row(r) for r in runs]}


@router.get("/{incident_id}/evidence")
def evidence(incident_id: str, db: Session = Depends(get_db)) -> dict:
    get_or_404(db, Incident, incident_id, "Incident")
    events = chain.load(db, incident_id)
    check = chain.verify_records(chain.as_records(events))
    packs = db.execute(select(EvidencePack).where(EvidencePack.incident_id == incident_id)
                       .order_by(EvidencePack.created_at.desc())).scalars().all()
    return {"chain": check, "events": [{**row(e), "payload": e.payload} for e in events],
            "packs": [row(p) for p in packs]}


@router.get("/{incident_id}/timeline")
def timeline(incident_id: str, db: Session = Depends(get_db)) -> dict:
    get_or_404(db, Incident, incident_id, "Incident")
    inv = _latest(db, Investigation, incident_id)
    items = list(inv.timeline) if inv else []
    for e in chain.load(db, incident_id):
        if e.event_type in ("approval.recorded", "remediation.executed", "verification.completed", "incident.closed",
                            "evidence.pack_requested"):
            p = e.payload
            label = {"approval.recorded": f"Approved {', '.join(p.get('actions', []))} by {e.actor}"
                     + (" (presenter auto-approve)" if p.get("presenter_auto_approve") else ""),
                     "remediation.executed": f"{p.get('code')} {p.get('status', '').lower()}: {p.get('action_type')}",
                     "verification.completed": f"Verification {p.get('run')}: {p.get('verdict')}"
                     + (f" (residual: {', '.join(p.get('residual', []))})" if p.get("residual") else ""),
                     "incident.closed": f"Incident closed by {e.actor}",
                     "evidence.pack_requested": "Evidence pack requested"}[e.event_type]
            items.append({"ts": e.ts.isoformat(), "kind": e.event_type, "label": label})
    items.sort(key=lambda t: t["ts"])
    return {"items": items}


@router.get("/{incident_id}/drafts")
def drafts(incident_id: str, db: Session = Depends(get_db)) -> dict:
    get_or_404(db, Incident, incident_id, "Incident")
    ds = db.execute(select(ComplianceDraft).where(ComplianceDraft.incident_id == incident_id)).scalars().all()
    obs = db.execute(select(Obligation).where(Obligation.incident_id == incident_id)).scalars().all()
    return {"items": [row(d) for d in ds], "obligations": [row(o) for o in obs]}


@router.get("/{incident_id}/agents")
def agents(incident_id: str, db: Session = Depends(get_db)) -> dict:
    inc = get_or_404(db, Incident, incident_id, "Incident")
    q = select(AgentExecution).where((AgentExecution.incident_id == inc.id) |
                                     ((AgentExecution.drill_id == inc.drill_id) & AgentExecution.incident_id.is_(None)))
    return {"items": [row(a, {"input"}) for a in db.execute(q.order_by(AgentExecution.started_at)).scalars()]}


class ObligationIn(BaseModel):
    regime: str = Field(max_length=64)
    label: str = Field(min_length=3, max_length=255)
    start_time: datetime
    deadline_hours: float = Field(gt=0, le=24 * 365)
    note: str = Field(default="", max_length=2000)


@router.post("/{incident_id}/obligations", status_code=201, dependencies=[Depends(action_limit)])
def add_obligation(incident_id: str, body: ObligationIn, user: User = Depends(CAN_APPROVE), db: Session = Depends(get_db)) -> dict:
    """Only a human records an obligation; MALLYA then shows a timer. It never decides one applies."""
    get_or_404(db, Incident, incident_id, "Incident")
    o = Obligation(incident_id=incident_id, set_by=user.email, **body.model_dump())
    db.add(o)
    chain.append(incident_id, "obligation.recorded", user.email, {**body.model_dump(mode="json"), "set_by": user.email}, db=db)
    db.commit()
    audit("obligation.recorded", actor=user.email, actor_role=user.role, target_type="incident", target_id=incident_id)
    return row(o)


@router.post("/{incident_id}/remediation/execute", status_code=202, dependencies=[Depends(action_limit)])
def execute(incident_id: str, user: User = Depends(CAN_OPERATE), db: Session = Depends(get_db)) -> dict:
    get_or_404(db, Incident, incident_id, "Incident")
    every = db.execute(select(RemediationAction).where(RemediationAction.incident_id == incident_id)).scalars().all()
    order, blocked = execution_plan(every)
    if not order:
        if blocked:
            raise ApiError(409, "blocked_by_dependency",
                           f"Nothing can run yet: {describe_blocked(blocked)}. Approve the dependency first.")
        raise ApiError(409, "nothing_approved", "No approved actions are waiting to execute.")
    ready = [a for a in every if a.code in order]
    if not jobs.submit(f"incident:{incident_id}", engine.continue_after_approval, incident_id):
        raise ApiError(409, "busy", "This incident already has a run in progress.")
    audit("remediation.execute_requested", actor=user.email, actor_role=user.role, target_type="incident", target_id=incident_id,
          details={"actions": [a.code for a in ready]})
    return {"accepted": True, "actions": [a.code for a in ready]}


class CloseIn(BaseModel):
    note: str = Field(default="", max_length=2000)


@router.post("/{incident_id}/close", dependencies=[Depends(action_limit)])
def close(incident_id: str, body: CloseIn, user: User = Depends(CAN_APPROVE), db: Session = Depends(get_db)) -> dict:
    """Backend-enforced: an incident can only be closed as fixed if the LATEST verification is VERIFIED_FIXED."""
    inc = get_or_404(db, Incident, incident_id, "Incident")
    latest = db.execute(select(VerificationRun).where(VerificationRun.incident_id == incident_id)
                        .order_by(VerificationRun.run_number.desc())).scalars().first()
    if not latest or latest.verdict != CLOSABLE_FIXED:
        raise ApiError(409, "not_verified", "Cannot close: the latest verification is "
                       f"{latest.verdict if latest else 'missing'}, not VERIFIED_FIXED.",
                       {"latest_verification": latest.verdict if latest else None})
    inc.status, inc.closed_at, inc.closed_by = "CLOSED", now(), user.email
    chain.append(incident_id, "incident.closed", user.email, {"latest_verification": latest.ref, "note": body.note}, db=db)
    db.commit()
    audit("incident.closed", actor=user.email, actor_role=user.role, target_type="incident", target_id=incident_id)
    return row(inc)

