"""Hash-chained evidence events (per incident).

event_hash = SHA256(canonical({metadata, payload_hash, previous_event_hash}))
metadata  = {incident_id, seq, ts, event_type, actor}
payload_hash = SHA256(canonical(payload))

Insertion, deletion, reordering or edits break the chain and are detected by verify_chain()
and by the standalone tools/mallya_verify.py.
"""
from __future__ import annotations

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from mallya_common.canonical import canonical, chain_hash, sha256_hex

from ..core.db import session_scope
from ..models import EvidenceEvent, now

GENESIS = "0" * 64


def event_metadata(e: EvidenceEvent) -> dict:
    return {"incident_id": e.incident_id, "seq": e.seq, "ts": e.ts.isoformat(), "event_type": e.event_type,
            "actor": e.actor}


def append(incident_id: str, event_type: str, actor: str, payload: dict, db: Session | None = None) -> EvidenceEvent:
    def _do(s: Session) -> EvidenceEvent:
        # serialise appends per incident (advisory lock keyed by incident)
        s.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"evidence:{incident_id}"})
        last = s.execute(select(EvidenceEvent).where(EvidenceEvent.incident_id == incident_id)
                         .order_by(EvidenceEvent.seq.desc()).limit(1)).scalar_one_or_none()
        seq = (last.seq + 1) if last else 1
        prev = last.event_hash if last else GENESIS
        ev = EvidenceEvent(incident_id=incident_id, seq=seq, ts=now().replace(microsecond=(now().microsecond // 1000) * 1000),
                           event_type=event_type, actor=actor, payload=payload)
        ev.payload_hash = sha256_hex(canonical(payload))
        ev.previous_event_hash = prev
        ev.metadata_ = event_metadata(ev)
        ev.event_hash = chain_hash(ev.metadata_, ev.payload_hash, prev)
        s.add(ev)
        s.flush()
        return ev

    if db is not None:
        return _do(db)
    with session_scope() as s:
        return _do(s)


def as_records(events: list[EvidenceEvent]) -> list[dict]:
    return [{"seq": e.seq, "metadata": e.metadata_, "payload": e.payload, "payload_hash": e.payload_hash,
             "previous_event_hash": e.previous_event_hash, "event_hash": e.event_hash} for e in events]


def verify_records(records: list[dict]) -> dict:
    """Pure verification of an ordered list of event records."""
    problems: list[str] = []
    prev = GENESIS
    for i, r in enumerate(records, start=1):
        if r["seq"] != i:
            problems.append(f"sequence gap or reorder at position {i} (found seq {r['seq']})")
        if sha256_hex(canonical(r["payload"])) != r["payload_hash"]:
            problems.append(f"event {r['seq']}: payload modified")
        if r["previous_event_hash"] != prev:
            problems.append(f"event {r['seq']}: previous_event_hash does not link to event {i - 1}")
        if chain_hash(r["metadata"], r["payload_hash"], r["previous_event_hash"]) != r["event_hash"]:
            problems.append(f"event {r['seq']}: event_hash mismatch (metadata or hash edited)")
        prev = r["event_hash"]
    return {"ok": not problems, "events": len(records), "head": prev, "problems": problems}


def load(db: Session, incident_id: str) -> list[EvidenceEvent]:
    return list(db.execute(select(EvidenceEvent).where(EvidenceEvent.incident_id == incident_id)
                           .order_by(EvidenceEvent.seq)).scalars())


def count(db: Session, incident_id: str) -> int:
    return db.execute(select(func.count()).select_from(EvidenceEvent)
                      .where(EvidenceEvent.incident_id == incident_id)).scalar_one()
