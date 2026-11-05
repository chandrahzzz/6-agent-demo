from __future__ import annotations

from datetime import datetime

from fastapi import Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.errors import ApiError

HIDDEN = {"password_hash", "harness"}


def row(obj, exclude: set[str] = frozenset()) -> dict:
    out = {}
    for c in obj.__table__.columns:
        key = c.key
        if key in HIDDEN or key in exclude:
            continue
        attr = "metadata_" if key == "metadata" else key
        v = getattr(obj, attr, None)
        out[key] = v.isoformat() if isinstance(v, datetime) else v
    return out


class Page:
    def __init__(self, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500)) -> None:
        self.page, self.page_size = page, page_size


def paginate(db: Session, stmt, page: Page, exclude: set[str] = frozenset(), mapper=None) -> dict:
    total = db.execute(select(func.count()).select_from(stmt.order_by(None).subquery())).scalar_one()
    items = db.execute(stmt.offset((page.page - 1) * page.page_size).limit(page.page_size)).scalars().all()
    return {"items": [mapper(i) if mapper else row(i, exclude) for i in items], "page": page.page,
            "page_size": page.page_size, "total": total}


def get_or_404(db: Session, model, id_: str, what: str):
    obj = db.get(model, id_)
    if obj is None:
        raise ApiError(404, "not_found", f"{what} not found.")
    return obj
