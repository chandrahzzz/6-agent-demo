"""Authentication: Argon2id password hashes + opaque session tokens in httpOnly cookies.

Only the SHA-256 of a session token is stored server-side.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import User, UserSession
from .config import settings
from .db import get_db
from .errors import ApiError

COOKIE = "mallya_session"
ROLES = ("ADMIN", "SECURITY_ANALYST", "IMPLEMENTATION_ENGINEER", "VIEWER")
_ph = PasswordHasher()


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(pw_hash: str, pw: str) -> bool:
    try:
        return _ph.verify(pw_hash, pw)
    except (VerifyMismatchError, InvalidHashError):
        return False


def _token_id(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db: Session, user: User, ip: str | None) -> str:
    token = secrets.token_urlsafe(32)
    db.add(UserSession(id=_token_id(token), user_id=user.id, ip=ip,
                       expires_at=datetime.now(timezone.utc) + timedelta(hours=settings().session_hours)))
    db.commit()
    return token


def destroy_session(db: Session, token: str | None) -> None:
    if token:
        s = db.get(UserSession, _token_id(token))
        if s:
            db.delete(s)
            db.commit()


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get(COOKIE)
    if not token:
        raise ApiError(401, "unauthenticated", "Sign in required.")
    s = db.get(UserSession, _token_id(token))
    if not s or s.expires_at < datetime.now(timezone.utc):
        raise ApiError(401, "session_expired", "Session expired. Sign in again.")
    user = db.execute(select(User).where(User.id == s.user_id)).scalar_one_or_none()
    if not user:
        raise ApiError(401, "unauthenticated", "Sign in required.")
    return user


def require_roles(*roles: str):
    def dep(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise ApiError(403, "forbidden", f"Requires role: {', '.join(roles)}.")
        return user
    return dep


CAN_APPROVE = require_roles("ADMIN", "SECURITY_ANALYST")
CAN_OPERATE = require_roles("ADMIN", "SECURITY_ANALYST", "IMPLEMENTATION_ENGINEER")
ANY_USER = current_user
