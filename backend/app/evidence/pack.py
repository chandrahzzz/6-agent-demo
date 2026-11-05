"""Evidence pack: cryptographically tamper-evident and audit-oriented.

pack.zip
  manifest.json      authoritative, canonical JSON; signed (Ed25519) -> manifest.sig
  manifest.sig       base64 Ed25519 signature over manifest.json bytes
  public_key.pem     verification key (key id recorded in the manifest)
  events.jsonl       hash-chained evidence events (one canonical JSON record per line)
  timeline.csv       human-readable timeline
  report.pdf         human-readable report
  checksums.sha256   SHA-256 of every other file
Verify with: python tools/mallya_verify.py pack.zip
"""
from __future__ import annotations

import csv
import io
import time
import zipfile
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from mallya_common.canonical import canonical, sha256_hex

from ..core.config import settings
from ..models import (Approval, BlastRadius, ComplianceDraft, EvidencePack, Finding, Incident, Investigation,
                      RemediationAction, VerificationRun, AgentExecution, now)
from . import chain, signing
from .pdf import render_pdf

WORDING = ("This pack is cryptographically tamper-evident and audit-oriented: any edit, insertion, deletion or "
           "reordering of evidence events, and any change to a file, is detectable. It is not a statement of legal "
           "admissibility or regulatory compliance.")
LIMITATIONS = [
    "Sandbox prototype: all systems are local mocks/sandboxes and all data is synthetic.",
    "Access verdicts are bounded by log coverage (MinIO audit + CDN access log); requests outside those sources are not visible.",
    "Fingerprint search covers only locations known to MALLYA's inventory; unknown copies cannot be ruled out.",
    "Signing key in this environment is a development key labelled DEV-NON-PRODUCTION.",
]


def incident_record(db: Session, inc: Incident) -> dict:
    inv = db.execute(select(Investigation).where(Investigation.incident_id == inc.id).order_by(Investigation.created_at.desc())).scalars().first()
    br = db.execute(select(BlastRadius).where(BlastRadius.incident_id == inc.id).order_by(BlastRadius.created_at.desc())).scalars().first()
    actions = db.execute(select(RemediationAction).where(RemediationAction.incident_id == inc.id).order_by(RemediationAction.code)).scalars().all()
    approvals = db.execute(select(Approval).where(Approval.incident_id == inc.id).order_by(Approval.created_at)).scalars().all()
    runs = db.execute(select(VerificationRun).where(VerificationRun.incident_id == inc.id).order_by(VerificationRun.run_number)).scalars().all()
    drafts = db.execute(select(ComplianceDraft).where(ComplianceDraft.incident_id == inc.id)).scalars().all()
    findings = db.execute(select(Finding).where(Finding.incident_id == inc.id)).scalars().all()
    agents = db.execute(select(AgentExecution).where(AgentExecution.incident_id == inc.id).order_by(AgentExecution.started_at)).scalars().all()
    iso = lambda d: d.isoformat() if d else None  # noqa: E731
    return {
        "incident": {"ref": inc.ref, "title": inc.title, "summary": inc.summary, "status": inc.status,
                     "exposure_type": inc.exposure_type, "severity": inc.severity, "risk_score": inc.risk_score,
                     "risk_factors": inc.risk_factors, "detected_at": iso(inc.detected_at),
                     "exposure_started_at": iso(inc.exposure_started_at), "verified_fixed_at": iso(inc.verified_fixed_at),
                     "timings_ms": {k: v for k, v in (inc.timings or {}).items() if k.endswith("_ms")}},
        "findings": [{"asset": f.asset_ref, "type": f.finding_type, "title": f.title, "severity": f.severity,
                      "data_categories": f.data_categories, "record_count": f.record_count, "masked_samples": f.masked_samples}
                     for f in findings],
        "access_verdict": {"verdict": inv.verdict, "confidence": inv.confidence, "summary": inv.summary,
                           "reasons": inv.evidence.get("reasons"), "log_coverage": inv.log_coverage} if inv else None,
        "root_cause": [{k: c.get(k) for k in ("bucket", "kind", "statement", "commit", "confidence")} for c in (inv.root_cause if inv else [])],
        "timeline": inv.timeline if inv else [],
        "blast_radius": {"record_count": br.record_count, "data_categories": br.data_categories, "consent": br.consent,
                         "locations": br.locations, "unverified": br.unverified, "exposure_paths": br.exposure_paths,
                         "asset_graph": br.graph} if br else None,
        "actions": [{"code": a.code, "wave": a.wave, "type": a.action_type, "target": a.target, "change": a.change,
                     "approval_status": a.approval_status, "execution_status": a.execution_status,
                     "patch_diff": a.patch_diff, "safety": a.safety, "result": a.result,
                     "executed_at": iso(a.executed_at)} for a in actions],
        "approvals": [{"action_id": p.action_id, "decision": p.decision, "by": p.user_email, "role": p.role,
                       "presenter_auto_approve": p.presenter_auto, "reason": p.reason, "at": iso(p.created_at),
                       "params_sha256": p.params_sha256} for p in approvals],
        "verification_runs": [{"ref": r.ref, "verdict": r.verdict, "residual": r.residual, "reasons": r.reasons,
                               "origin": r.origin, "verifier_version": r.verifier_version, "requests": r.external_results,
                               "authorised": r.authorised_results, "copy_hunt": r.copy_hunt, "unverified": r.unverified,
                               "started_at": iso(r.started_at), "finished_at": iso(r.finished_at)} for r in runs],
        "compliance_drafts": [{"regime": d.regime, "title": d.title, "stamp": d.stamp, "body": d.body} for d in drafts],
        "agent_history": [{"agent": a.agent, "status": a.status, "summary": a.decision_summary, "confidence": a.confidence,
                           "duration_ms": a.duration_ms, "started_at": iso(a.started_at)} for a in agents],
        "final_status": inc.status,
        "limitations": LIMITATIONS,
    }


def build(db: Session, incident_id: str) -> EvidencePack:
    t0 = time.monotonic()
    inc = db.get(Incident, incident_id)
    chain.append(incident_id, "evidence.pack_requested", "agent:compliance_evidence", {"status": inc.status}, db=db)
    events = chain.load(db, incident_id)
    records = chain.as_records(events)
    check = chain.verify_records(records)
    if not check["ok"]:
        raise RuntimeError("evidence chain failed verification; refusing to sign: " + "; ".join(check["problems"][:3]))
    content = incident_record(db, inc)
    files: dict[str, bytes] = {}
    files["events.jsonl"] = b"".join(canonical(r) + b"\n" for r in records)
    tl = io.StringIO()
    w = csv.writer(tl, lineterminator="\n")
    w.writerow(["seq", "ts_utc", "event_type", "actor", "event_hash"])
    for r in records:
        w.writerow([r["seq"], r["metadata"]["ts"], r["metadata"]["event_type"], r["metadata"]["actor"], r["event_hash"]])
    files["timeline.csv"] = tl.getvalue().encode()
    files["report.pdf"] = render_pdf(content, check, signing.key_id(), WORDING)
    files["public_key.pem"] = signing.public_pem()
    manifest = {
        "pack_format": "mallya-evidence-pack/1",
        "generated_at": now().isoformat(),
        "product": "MALLYA (concept prototype)",
        "statement": WORDING,
        "signature": {"algorithm": signing.ALGORITHM, "key_id": signing.key_id(), "key_label": signing.label(),
                      "public_key_file": "public_key.pem"},
        "chain": {"incident_id": incident_id, "event_count": check["events"], "head_event_hash": check["head"],
                  "hash_rule": "event_hash = SHA256(canonical({metadata, payload_hash, previous_event_hash})); genesis = 64 zeros"},
        "files": {name: sha256_hex(data) for name, data in files.items()},
        "content": content,
    }
    files["manifest.json"] = canonical(manifest)
    files["manifest.sig"] = signing.sign(files["manifest.json"]).encode()
    files["checksums.sha256"] = "".join(f"{sha256_hex(d)}  {n}\n" for n, d in sorted(files.items())).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in sorted(files.items()):
            z.writestr(n, d)
    blob = buf.getvalue()
    out_dir = Path(settings().evidence_export_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"mallya-evidence-{inc.ref}-{now().strftime('%Y%m%dT%H%M%SZ')}.zip"
    (out_dir / name).write_bytes(blob)
    pack = EvidencePack(incident_id=incident_id, manifest_sha256=sha256_hex(files["manifest.json"]),
                        signature_b64=files["manifest.sig"].decode(), key_id=signing.key_id(), algorithm=signing.ALGORITHM,
                        event_count=check["events"], head_event_hash=check["head"], file_name=name, file_sha256=sha256_hex(blob),
                        files={n: sha256_hex(d) for n, d in files.items()}, built_ms=round((time.monotonic() - t0) * 1000, 1))
    db.add(pack)
    db.flush()
    return pack
