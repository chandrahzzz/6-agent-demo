"""Live agent events: persisted to agent_events (for replay) and published on Redis (for SSE)."""
from __future__ import annotations

import json
import logging
from functools import lru_cache

import redis

from ..models import AgentEvent
from .config import settings
from .db import session_scope

log = logging.getLogger("mallya.events")


@lru_cache
def _redis() -> redis.Redis:
    return redis.Redis.from_url(settings().redis_url)


def channel(drill_id: str | None, incident_id: str | None) -> list[str]:
    out = ["mallya:events"]
    if drill_id:
        out.append(f"mallya:drill:{drill_id}")
    if incident_id:
        out.append(f"mallya:incident:{incident_id}")
    return out


def emit(kind: str, message: str, *, drill_id: str | None = None, incident_id: str | None = None,
         agent: str | None = None, execution_id: str | None = None, data: dict | None = None) -> dict:
    with session_scope() as db:
        ev = AgentEvent(kind=kind, message=message, drill_id=drill_id, incident_id=incident_id, agent=agent,
                        execution_id=execution_id, data=data or {})
        db.add(ev)
        db.flush()
        out = serialise(ev)
    try:
        payload = json.dumps(out, default=str)
        for ch in channel(drill_id, incident_id):
            _redis().publish(ch, payload)
    except redis.RedisError:
        log.warning("redis publish failed; event persisted for replay")
    return out


def serialise(ev: AgentEvent) -> dict:
    return {"id": ev.id, "ts": ev.ts.isoformat() if ev.ts else None, "kind": ev.kind, "message": ev.message,
            "drill_id": ev.drill_id, "incident_id": ev.incident_id, "agent": ev.agent,
            "execution_id": ev.execution_id, "data": ev.data}
