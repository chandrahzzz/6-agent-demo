"""Append-only audit log of every human and system action."""
from __future__ import annotations

from sqlalchemy.orm import Session

from ..core.db import session_scope
from ..models import AuditLog


def audit(action: str, *, actor: str, actor_role: str | None = None, target_type: str | None = None,
          target_id: str | None = None, ip: str | None = None, details: dict | None = None,
          db: Session | None = None) -> None:
    rec = AuditLog(action=action, actor=actor, actor_role=actor_role, target_type=target_type,
                   target_id=target_id, ip=ip, details=details or {})
    if db is not None:
        db.add(rec)
        return
    with session_scope() as s:
        s.add(rec)
