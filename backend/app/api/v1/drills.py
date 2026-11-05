from __future__ import annotations

import asyncio
import json

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...audit.log import audit
from ...core import events, jobs
from ...core.config import settings
from ...core.db import get_db, session_scope
from ...core.errors import ApiError
from ...core.ratelimit import action_limit
from ...core.security import ANY_USER, CAN_OPERATE
from ...drills import catalog, engine
from ...models import AgentEvent, Drill, User
from ..util import Page, get_or_404, paginate, row

router = APIRouter(tags=["drills"], dependencies=[Depends(ANY_USER)])


@router.get("/scenarios")
def scenarios() -> dict:
    return {"items": catalog.all_scenarios()}


class DrillIn(BaseModel):
    scenario_id: str = Field(max_length=64)
    access_variant: str = Field(default="A", pattern="^(A|B)$")
    seed: int = Field(default=42, ge=0, le=2**31)
    auto_approve: bool = False
    reset: bool = True


def _start(db: Session, user: User, body: DrillIn, demo: bool) -> Drill:
    sc = catalog.get(body.scenario_id)
    if not sc:
        raise ApiError(404, "unknown_scenario", "Unknown scenario.")
    if not sc["implemented"]:
        raise ApiError(409, "not_implemented", f"{body.scenario_id} is not implemented yet (see PROGRESS.md).")
    if any(jobs.running(f"drill:{d}") for d in db.execute(select(Drill.id).where(Drill.status == "RUNNING")).scalars()):
        raise ApiError(409, "drill_running", "Another drill is running. Wait for it to finish.")
    d = Drill(scenario_id=body.scenario_id, seed=body.seed, auto_approve=body.auto_approve, demo=demo, created_by=user.email,
              params={"access_variant": body.access_variant, "reset": body.reset})
    db.add(d)
    db.commit()
    jobs.submit(f"drill:{d.id}", engine.run_drill, d.id)
    audit("drill.started", actor=user.email, actor_role=user.role, target_type="drill", target_id=d.id,
          details={"scenario": body.scenario_id, "variant": body.access_variant, "auto_approve": body.auto_approve, "demo": demo})
    return d


@router.post("/drills", status_code=202, dependencies=[Depends(action_limit)])
def create_drill(body: DrillIn, user: User = Depends(CAN_OPERATE), db: Session = Depends(get_db)) -> dict:
    return row(_start(db, user, body, demo=False))


class DemoIn(BaseModel):
    auto_approve: bool = False


@router.post("/demo/start", status_code=202, dependencies=[Depends(action_limit)])
def demo(body: DemoIn, user: User = Depends(CAN_OPERATE), db: Session = Depends(get_db)) -> dict:
    """Demo Mode: reset the sandbox and run HERO-01 (variant A). Pauses for approval unless the
    visibly-labelled presenter auto-approve is on."""
    return row(_start(db, user, DrillIn(scenario_id="HERO-01", access_variant="A", auto_approve=body.auto_approve), demo=True))


@router.get("/drills")
def list_drills(page: Page = Depends(), db: Session = Depends(get_db)) -> dict:
    return paginate(db, select(Drill).order_by(Drill.created_at.desc()), page)


@router.get("/drills/{drill_id}")
def get_drill(drill_id: str, db: Session = Depends(get_db)) -> dict:
    d = get_or_404(db, Drill, drill_id, "Drill")
    return {**row(d), "running": jobs.running(f"drill:{d.id}")}


@router.post("/drills/reset", status_code=202, dependencies=[Depends(action_limit)])
def reset(user: User = Depends(CAN_OPERATE)) -> dict:
    if not jobs.submit("reset", engine.reset_sandbox, settings().seed):
        raise ApiError(409, "busy", "A reset is already running.")
    audit("sandbox.reset", actor=user.email, actor_role=user.role)
    return {"accepted": True}


def _history(drill_id: str | None, incident_id: str | None, after: int) -> list[dict]:
    with session_scope() as db:
        q = select(AgentEvent).where(AgentEvent.id > after).order_by(AgentEvent.id)
        if drill_id:
            q = q.where(AgentEvent.drill_id == drill_id)
        if incident_id:
            q = q.where(AgentEvent.incident_id == incident_id)
        return [events.serialise(e) for e in db.execute(q.limit(1000)).scalars()]


async def _stream(request: Request, drill_id: str | None, incident_id: str | None, after: int):
    """SSE: replay persisted events, then follow Redis pub/sub (with a DB poll as a safety net)."""
    last = after
    for ev in await asyncio.to_thread(_history, drill_id, incident_id, last):
        last = ev["id"]
        yield f"id: {ev['id']}\nevent: {ev['kind']}\ndata: {json.dumps(ev, default=str)}\n\n"
    r = aioredis.from_url(settings().redis_url)
    ps = r.pubsub()
    await ps.subscribe(f"mallya:drill:{drill_id}" if drill_id else f"mallya:incident:{incident_id}")
    try:
        idle = 0.0
        while not await request.is_disconnected():
            msg = await ps.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if msg and msg.get("type") == "message":
                ev = json.loads(msg["data"])
                if ev["id"] > last:
                    last = ev["id"]
                    yield f"id: {ev['id']}\nevent: {ev['kind']}\ndata: {json.dumps(ev, default=str)}\n\n"
                idle = 0
            else:
                idle += 1
                if idle >= 5:  # catch anything missed (e.g. Redis hiccup) and keep the connection alive
                    for ev in await asyncio.to_thread(_history, drill_id, incident_id, last):
                        last = ev["id"]
                        yield f"id: {ev['id']}\nevent: {ev['kind']}\ndata: {json.dumps(ev, default=str)}\n\n"
                    yield ": keep-alive\n\n"
                    idle = 0
    finally:
        await ps.unsubscribe()
        await r.aclose()


@router.get("/drills/{drill_id}/events")
async def drill_events(drill_id: str, request: Request) -> StreamingResponse:
    after = int(request.headers.get("last-event-id") or request.query_params.get("after") or 0)
    return StreamingResponse(_stream(request, drill_id, None, after), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/incidents/{incident_id}/events")
async def incident_events(incident_id: str, request: Request) -> StreamingResponse:
    after = int(request.headers.get("last-event-id") or request.query_params.get("after") or 0)
    return StreamingResponse(_stream(request, None, incident_id, after), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/drills/{drill_id}/event-log")
def drill_event_log(drill_id: str, after: int = 0) -> dict:
    return {"items": _history(drill_id, None, after)}
