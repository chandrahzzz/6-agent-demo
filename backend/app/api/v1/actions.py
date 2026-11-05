"""Approvals, verification runs and evidence."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...audit.log import audit
from ...core import jobs
from ...core.config import settings
from ...core.db import get_db, session_scope
from ...core.errors import ApiError
from ...core.ratelimit import action_limit
from ...core.security import ANY_USER, CAN_APPROVE, CAN_OPERATE
from ...evidence import chain, pack, signing
from ...models import Approval, EvidencePack, Incident, RemediationAction, User
from ...orchestration import graph
from ...remediation.approvals import params_sha256
from ..util import get_or_404, row

router = APIRouter(tags=["actions"], dependencies=[Depends(ANY_USER)])


class ApprovalIn(BaseModel):
    action_ids: list[str] = Field(min_length=1, max_length=50)
    decision: str = Field(pattern="^(APPROVED|REJECTED)$")
    reason: str = Field(default="", max_length=2000)
    override_hold: bool = False


@router.post("/approvals", dependencies=[Depends(action_limit)])
def decide(body: ApprovalIn, user: User = Depends(CAN_APPROVE), db: Session = Depends(get_db)) -> dict:
    acts = db.execute(select(RemediationAction).where(RemediationAction.id.in_(body.action_ids))).scalars().all()
    if len(acts) != len(set(body.action_ids)):
        raise ApiError(404, "not_found", "One or more actions were not found.")
    if len({a.incident_id for a in acts}) != 1:
        raise ApiError(422, "mixed_incidents", "Approve actions of one incident at a time.")
    for a in acts:
        if a.approval_status not in ("PENDING", "HELD"):
            raise ApiError(409, "already_decided", f"{a.code} is already {a.approval_status}.")
        if a.approval_status == "HELD" and body.decision == "APPROVED" and not (body.override_hold and len(body.reason) >= 10):
            raise ApiError(409, "held_by_safety_check",
                           f"{a.code} is held by the safety check ({'; '.join(d['origin'] for d in a.safety.get('dependents', []))} "
                           "depends on this access). Approve with override_hold and a reason of at least 10 characters.")
    incident_id = acts[0].incident_id
    for a in acts:
        db.add(Approval(action_id=a.id, incident_id=incident_id, decision=body.decision, user_id=user.id, user_email=user.email,
                        role=user.role, reason=body.reason, presenter_auto=False, params_sha256=params_sha256(a.params)))
        a.approval_status = body.decision
    chain.append(incident_id, "approval.recorded", user.email,
                 {"actions": [a.code for a in acts], "decision": body.decision, "role": user.role, "reason": body.reason,
                  "override_hold": body.override_hold, "presenter_auto_approve": False}, db=db)
    db.commit()
    audit(f"remediation.{body.decision.lower()}", actor=user.email, actor_role=user.role, target_type="incident",
          target_id=incident_id, details={"actions": [a.code for a in acts], "override_hold": body.override_hold})
    return {"items": [row(a) for a in acts]}


@router.post("/verification/{incident_id}/run", status_code=202, dependencies=[Depends(action_limit)])
def run_verification(incident_id: str, user: User = Depends(CAN_OPERATE), db: Session = Depends(get_db)) -> dict:
    inc = get_or_404(db, Incident, incident_id, "Incident")

    def go():
        return graph.verify_only_graph().invoke({"incident_id": incident_id, "drill_id": inc.drill_id, "timings": {}})

    if not jobs.submit(f"incident:{incident_id}", go):
        raise ApiError(409, "busy", "This incident already has a run in progress.")
    audit("verification.requested", actor=user.email, actor_role=user.role, target_type="incident", target_id=incident_id)
    return {"accepted": True}


@router.get("/evidence")
def list_packs(db: Session = Depends(get_db)) -> dict:
    packs = db.execute(select(EvidencePack).order_by(EvidencePack.created_at.desc())).scalars().all()
    incs = {i.id: i for i in db.execute(select(Incident)).scalars()}
    out = []
    for p in packs:
        i = incs.get(p.incident_id)
        out.append({**row(p), "incident_ref": i.ref if i else None, "incident_title": i.title if i else None})
    return {"items": out, "signing": {"key_id": signing.key_id(), "algorithm": signing.ALGORITHM, "label": signing.label()}}


@router.post("/evidence/{incident_id}/build", status_code=201, dependencies=[Depends(action_limit)])
def build_pack(incident_id: str, user: User = Depends(CAN_OPERATE)) -> dict:
    with session_scope() as db:
        get_or_404(db, Incident, incident_id, "Incident")
        p = pack.build(db, incident_id)
        out = row(p)
    audit("evidence.pack_built", actor=user.email, actor_role=user.role, target_type="incident", target_id=incident_id)
    return out


def _pack_bytes(p: EvidencePack) -> bytes:
    path = Path(settings().evidence_export_dir) / p.file_name
    if not path.exists():
        raise ApiError(404, "pack_missing", "Pack file is missing from the export store.")
    return path.read_bytes()


@router.get("/evidence/packs/{pack_id}/download")
def download(pack_id: str, db: Session = Depends(get_db)) -> Response:
    p = get_or_404(db, EvidencePack, pack_id, "Evidence pack")
    return Response(_pack_bytes(p), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{p.file_name}"'})


@router.get("/evidence/packs/{pack_id}/file/{name}")
def pack_file(pack_id: str, name: str, db: Session = Depends(get_db)) -> Response:
    p = get_or_404(db, EvidencePack, pack_id, "Evidence pack")
    if name not in ("manifest.json", "report.pdf", "timeline.csv", "checksums.sha256", "public_key.pem"):
        raise ApiError(404, "not_found", "File not in pack.")
    with zipfile.ZipFile(io.BytesIO(_pack_bytes(p))) as z:
        data = z.read(name)
    mt = {"manifest.json": "application/json", "report.pdf": "application/pdf", "timeline.csv": "text/csv"}.get(name, "text/plain")
    return Response(data, media_type=mt, headers={"Content-Disposition": f'attachment; filename="{p.file_name[:-4]}-{name}"'})


@router.get("/evidence/packs/{pack_id}/verify")
def verify_pack(pack_id: str, db: Session = Depends(get_db)) -> dict:
    """Runs the same standalone verifier shipped in tools/ against the stored pack."""
    import importlib.util
    import contextlib
    import tempfile

    p = get_or_404(db, EvidencePack, pack_id, "Evidence pack")
    spec = importlib.util.spec_from_file_location("mallya_verify", "/app/tools/mallya_verify.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    with tempfile.NamedTemporaryFile(suffix=".zip") as tmp:
        tmp.write(_pack_bytes(p))
        tmp.flush()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = mod.main([tmp.name])
    lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
    checks = [{"status": ln[:4], "check": ln[6:].split()[0], "detail": ln[6:].split(None, 1)[1].strip() if len(ln[6:].split(None, 1)) > 1 else ""}
              for ln in lines if ln.startswith(("PASS ", "FAIL "))]
    return {"ok": code == 0, "checks": checks, "command": f"python tools/mallya_verify.py {p.file_name}"}
