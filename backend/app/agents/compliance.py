"""Compliance Evidence Agent: drafts (never decisions) + the signed evidence pack.

Every draft is stamped DRAFT — REQUIRES LEGAL AND COMPLIANCE REVIEW. MALLYA never decides
that a law applies, never computes or invents deadlines, never submits anything. Deadline
timers exist only when a human records an obligation and its start time.
"""
from __future__ import annotations

from sqlalchemy import delete, select

from ..core.db import session_scope
from ..evidence import pack
from ..models import KV, BlastRadius, ComplianceDraft, Incident, Investigation
from .base import AgentOutput, Ctx

STAMP = "DRAFT — REQUIRES LEGAL AND COMPLIANCE REVIEW"
DEFAULT_CONTEXT = ["DPDP", "CERT-In", "RBI"]
REGIMES = {
    "DPDP": ("Digital Personal Data Protection Act, 2023 and Rules",
             "Draft intimation of a personal data breach to the Data Protection Board of India and affected Data Principals"),
    "CERT-In": ("CERT-In Directions (April 2022) under s.70B IT Act",
                "Draft cyber security incident report to CERT-In"),
    "RBI": ("RBI directions on cyber security incident reporting (where the entity is RBI-regulated)",
            "Draft cyber incident report to the Reserve Bank of India"),
}


def regulatory_context(db) -> list[str]:
    kv = db.get(KV, "settings:regulatory_context")
    return (kv.value.get("regimes") if kv else None) or DEFAULT_CONTEXT


def _body(regime: str, inc: Incident, inv: Investigation | None, br: BlastRadius | None) -> str:
    law, title = REGIMES[regime]
    lines = [
        STAMP, "", title, f"Regulatory context selected by the user: {law}.",
        "MALLYA has NOT determined whether this framework applies, which obligations arise, or any deadline. "
        "Applicability and timelines must be decided by legal and compliance staff.", "",
        f"Incident reference: {inc.ref}", f"Nature of incident: {inc.title}",
        f"Detected (UTC): {inc.detected_at.isoformat()}",
        f"Exposure window start (UTC, from policy-change event): {inc.exposure_started_at.isoformat() if inc.exposure_started_at else 'unknown'}",
        f"Current status: {inc.status}",
        f"Access assessment (from logs): {inv.verdict if inv else 'pending'} — {inv.summary if inv else ''}",
    ]
    if br:
        lines += [f"Records affected (fingerprint-matched): {br.record_count:,}",
                  f"Data categories: {', '.join(sorted(br.data_categories))}",
                  f"Consent state of affected principals: {br.consent}"]
    if inv and inv.root_cause:
        lines.append("Root cause: " + "; ".join(c["statement"] for c in inv.root_cause))
    lines += ["", "Containment and remediation: see evidence pack (actions, approvals, adversarial verification results).",
              "", "[Reviewer to complete: legal basis assessment, notification decision, contact details, submission channel.]",
              "", STAMP]
    return "\n".join(lines)


def draft(ctx: Ctx) -> AgentOutput:
    with session_scope() as db:
        inc = db.get(Incident, ctx.incident_id)
        inv = db.execute(select(Investigation).where(Investigation.incident_id == inc.id).order_by(Investigation.created_at.desc())).scalars().first()
        br = db.execute(select(BlastRadius).where(BlastRadius.incident_id == inc.id).order_by(BlastRadius.created_at.desc())).scalars().first()
        regimes = regulatory_context(db)
        db.execute(delete(ComplianceDraft).where(ComplianceDraft.incident_id == inc.id))
        for r in regimes:
            if r in REGIMES:
                db.add(ComplianceDraft(incident_id=inc.id, regime=r, title=f"{REGIMES[r][1]} — {inc.ref}",
                                       body=_body(r, inc, inv, br), stamp=STAMP))
    summary = ctx.summarise("compliance.summary", {"drafts": len(regimes)})
    return AgentOutput(summary=summary, confidence=None, data={"drafts": regimes})


def build_pack(ctx: Ctx) -> AgentOutput:
    with session_scope() as db:
        p = pack.build(db, ctx.incident_id)
        out = {"pack_id": p.id, "file": p.file_name, "events": p.event_count, "key_id": p.key_id, "built_ms": p.built_ms}
    return AgentOutput(summary=f"Signed evidence pack built: {out['events']} chained events, Ed25519 key {out['key_id']}.",
                       confidence=None, evidence_refs=[f"pack:{out['file']}"], data=out)
