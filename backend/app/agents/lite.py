"""Lite scenarios: detection + investigation verdict + recommended fix. No live remediation.

The verdict comes from fixed rules over the metadata evidence a check produced:
  identifiers proven at a third party, or vendor training use   -> LIKELY_EXFILTRATED
  bytes left but the receiver keeps no payload to inspect       -> INSUFFICIENT_EVIDENCE
  data left, payload inspected, no personal data in it           -> FALSE_POSITIVE (no personal-data exposure)
  otherwise (a weakness with no evidence of access)              -> EXPOSED_NOT_ACCESSED
"""
from __future__ import annotations

from sqlalchemy import select

from ..core.db import session_scope
from ..models import Finding, Incident, Investigation, RemediationAction
from .base import AgentOutput, Ctx
from .registry import next_incident_ref

RECOMMEND: dict[str, tuple[str, str]] = {
    "UNENCRYPTED-STORAGE": ("Configure a KMS for object storage and enforce SSE on the bucket; re-encrypt existing objects",
                            "Objects rewritten; brief re-upload window"),
    "EXCESSIVE-DB-PERMISSIONS": ("REVOKE INSERT, UPDATE, DELETE on the table from the read-only role", "Jobs that wrongly write via this role fail"),
    "EXPOSED-POSTGRES": ("Rotate the role's credential, require scram-sha-256 with a strong secret, restrict pg_hba to known hosts",
                         "Legacy reports must be reconfigured with the new secret"),
    "DATABASE-BACKUP-DRIFT": ("Delete the undeclared dump or declare the bucket in infra-config with pii classification and retention",
                              "Ad-hoc restore workflows lose their copy"),
    "PAN-DISCOVERY": ("Catalogue the table in data_inventory, restrict access and map it to a ROPA entry", "None"),
    "AADHAAR-DISCOVERY": ("Move the file to a pii-classified bucket (or delete it) and record the processing purpose", "None"),
    "HEALTH-DATA-EXPOSURE": ("REVOKE SELECT ON health_claims FROM PUBLIC; grant to the claims service role only", "Ad-hoc readers lose access"),
    "UNAPPROVED-API": ("Block egress to the API until a vendor review and DPA exist, or register it", "SMS notifications pause"),
    "VENDOR-OVERPERMISSION": ("Reduce the vendor's scopes to the required set", "None if scopes are truly unused"),
    "VENDOR-CREDENTIAL-EXPIRY": ("Rotate the vendor credential and alert the owner 14 days before expiry", "Brief credential swap"),
    "MISSING-ROPA-ENTRY": ("Create a ROPA entry (purpose, lawful basis, retention) before further processing", "None"),
    "UNREVIEWED-DATA-RETENTION": ("Review the records past retention; delete or document a legal hold", "Deletion is irreversible"),
    "UNAPPROVED-AI-VENDOR": ("Route the use case through vendor review or block the tool", "Users lose the tool"),
    "AI-TRAINING-DATA-LEAK": ("Turn off training use in the vendor account and file a deletion request for the uploaded data",
                              "Vendor features that rely on training may degrade"),
    "SHARED-DRIVE-EXPOSURE": ("Move the file to a restricted location and remove the all-staff grant on it", "Branch teams need targeted access"),
}


def lite_verdict(ev: dict) -> tuple[str, list[str]]:
    if ev.get("identifiers_proven", 0) > 0 or ev.get("training_use"):
        return "LIKELY_EXFILTRATED", ["identifiable data is held by a third party" + (" that may train on it" if ev.get("training_use") else "")]
    if ev.get("bytes_out", 0) > 0 and not ev.get("payload_retained"):
        return "INSUFFICIENT_EVIDENCE", [f"{ev['bytes_out']:,} bytes left, but the receiver keeps no payload MALLYA can inspect"]
    if ev.get("bytes_out", 0) > 0 and ev.get("payload_retained") and ev.get("identifiers_proven", 0) == 0:
        return "FALSE_POSITIVE", ["data left to the vendor, but the inspected payload contains no personal data"]
    return "EXPOSED_NOT_ACCESSED", ["a weakness exists; no evidence that anyone used it"]


def create_incidents(ctx: Ctx, found: list[dict]) -> list[str]:
    ids = []
    with session_scope() as db:
        open_incs = db.execute(select(Incident).where(Incident.status != "CLOSED")).scalars().all()
        open_keys = {(i.scope or {}).get("key") for i in open_incs if i.exposure_type.startswith("LITE:")}
        covered = {f"s3://{o}": i for i in open_incs if not i.exposure_type.startswith("LITE:")
                   for o in (i.scope or {}).get("objects", [])}
        for f in found:
            key = f"{f['check']}|{f['asset_ref']}"
            if key in open_keys:
                continue
            if f["asset_ref"] in covered:
                # Correlate, don't duplicate: the object is already part of an open (deep) incident.
                db.add(Finding(incident_id=covered[f["asset_ref"]].id, drill_id=ctx.drill_id, asset_ref=f["asset_ref"],
                               detector=f"lite:{f['check']}", finding_type=f"RELATED:{f['check']}", title=f["title"],
                               severity="Info", suppressed=False, data_categories=f["data_categories"],
                               record_count=sum(f["data_categories"].values()) or None, masked_samples={}, details=f["evidence"],
                               confidence=0.95))
                continue
            inc = Incident(ref=next_incident_ref(db), drill_id=ctx.drill_id, exposure_type=f"LITE:{f['check']}", severity=f["severity"],
                           title=f"{f['check'].replace('-', ' ').title()}: {f['title']}", summary=f["title"],
                           scope={"key": key, "check": f["check"], "asset": f["asset_ref"], "tier": "lite"})
            db.add(inc)
            db.flush()
            db.add(Finding(incident_id=inc.id, drill_id=ctx.drill_id, asset_ref=f["asset_ref"], detector=f"lite:{f['check']}",
                           finding_type=f["check"], title=f["title"], severity=f["severity"], suppressed=False,
                           data_categories=f["data_categories"], record_count=sum(f["data_categories"].values()) or None,
                           masked_samples=f["evidence"].get("masked_samples", {}), details=f["evidence"], confidence=0.95))
            ids.append(inc.id)
    return ids


def investigate(ctx: Ctx) -> AgentOutput:
    with session_scope() as db:
        inc = db.get(Incident, ctx.incident_id)
        f = db.execute(select(Finding).where(Finding.incident_id == inc.id)).scalars().first()
        ev, check = dict(f.details), inc.scope["check"]
        v, reasons = lite_verdict(ev)
        summary = ctx.summarise("investigation.summary", {"verdict": v, "external": {}, "root_cause": f.title})
        db.add(Investigation(incident_id=inc.id, verdict=v, confidence=0.85, summary=summary,
                             evidence={"external_attempts": [], "external_success": [], "internal": [], "partner": [],
                                       "probe_requests_excluded": 0, "events_by_source": {}, "window_start": inc.detected_at.isoformat(),
                                       "reasons": reasons, "check_evidence": {k: v2 for k, v2 in ev.items() if k != "masked_samples"}},
                             root_cause=[{"bucket": inc.scope["asset"], "kind": "LITE_CHECK", "statement": f.title, "confidence": 0.85,
                                          "commit": None, "diff": None, "policy_change_event": None, "audit_corroboration": []}],
                             timeline=[{"ts": inc.detected_at.isoformat(), "kind": "detected", "label": f"Detected by lite check {check}"}],
                             log_coverage={}))
        inc.access_verdict = v
    return AgentOutput(summary=summary, confidence=0.85, data={"verdict": v, "reasons": reasons})


def recommend(ctx: Ctx) -> AgentOutput:
    with session_scope() as db:
        inc = db.get(Incident, ctx.incident_id)
        check = inc.scope["check"]
        change, side = RECOMMEND[check]
        db.add(RemediationAction(incident_id=inc.id, code="REC-01", wave=1, action_type=f"recommendation:{check}", target=inc.scope["asset"],
                                 problem=inc.summary, change=change, risk="Not executed by MALLYA (Lite scenario)", side_effects=side,
                                 expected_outcome=f"Lite check {check} no longer fires", rollback_plan="n/a",
                                 verification_requirement=f"Re-run the {check} check", params={}, approval_status="RECOMMENDATION",
                                 execution_status="NOT_APPLICABLE", safety={"result": "N/A (recommendation only)"}))
        inc.status = "DETECTED"
    return AgentOutput(summary=f"Recommended fix: {change}. Lite scenarios are not remediated live.", confidence=None,
                       data={"recommendation": change})
