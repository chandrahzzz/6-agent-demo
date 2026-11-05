from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...audit.log import audit
from ...core.config import settings
from ...core.db import get_db
from ...core.errors import ApiError
from ...core.ratelimit import login_limit
from ...core.security import COOKIE, create_session, current_user, destroy_session, verify_password
from ...models import User

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginIn(BaseModel):
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+$", max_length=255)
    password: str = Field(min_length=1, max_length=256)


def me_dict(u: User) -> dict:
    return {"id": u.id, "email": u.email, "name": u.name, "role": u.role, "is_demo": u.is_demo}


@router.post("/login", dependencies=[Depends(login_limit)])
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    u = db.execute(select(User).where(User.email == body.email.lower())).scalar_one_or_none()
    ip = request.client.host if request.client else None
    if not u or not verify_password(u.password_hash, body.password):
        audit("auth.login_failed", actor=body.email.lower(), ip=ip)
        raise ApiError(401, "invalid_credentials", "Email or password is incorrect.")
    token = create_session(db, u, ip)
    response.set_cookie(COOKIE, token, httponly=True, samesite="lax", secure=not settings().is_dev,
                        max_age=settings().session_hours * 3600, path="/")
    audit("auth.login", actor=u.email, actor_role=u.role, ip=ip)
    return me_dict(u)


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    destroy_session(db, request.cookies.get(COOKIE))
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
def me(user: User = Depends(current_user)) -> dict:
    return me_dict(user)
