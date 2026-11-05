"""Asset registry upserts (assets + relationships) shared by agents."""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Asset, AssetRelationship, Incident


def upsert_asset(db: Session, ref: str, kind: str, name: str, connector: str, classification: str | None = None,
                 attributes: dict | None = None, status: str | None = None) -> Asset:
    a = db.execute(select(Asset).where(Asset.ref == ref)).scalar_one_or_none()
    if not a:
        a = Asset(ref=ref, kind=kind, name=name, connector=connector, is_mock=True)
        db.add(a)
    a.kind, a.name, a.connector = kind, name, connector
    if classification is not None:
        a.classification = classification
    if attributes is not None:
        a.attributes = attributes
    if status is not None:
        a.status = status
    db.flush()
    return a


def relate(db: Session, src: Asset, dst: Asset, kind: str, attributes: dict | None = None) -> None:
    r = db.execute(select(AssetRelationship).where(AssetRelationship.src_id == src.id, AssetRelationship.dst_id == dst.id,
                                                   AssetRelationship.kind == kind)).scalar_one_or_none()
    if not r:
        db.add(AssetRelationship(src_id=src.id, dst_id=dst.id, kind=kind, attributes=attributes or {}))
        db.flush()


def next_incident_ref(db: Session) -> str:
    n = db.execute(select(func.count()).select_from(Incident)).scalar_one()
    return f"INC-2026-{n + 1:04d}"
