"""MALLYA control-plane schema. Metadata only: no table stores raw customer identifiers.

Every table carries org_id for future multi-tenancy (single tenant today).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

ORG = "meridian-bank"


def now() -> datetime:
    return datetime.now(timezone.utc)


def uid() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    type_annotation_map = {dict: JSONB, list: JSONB}


class OrgMixin:
    org_id: Mapped[str] = mapped_column(String(64), default=ORG, index=True)


TS = DateTime(timezone=True)


class User(OrgMixin, Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    name: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32))
    password_hash: Mapped[str] = mapped_column(String(255))
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(TS, default=now)


class UserSession(OrgMixin, Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # sha256 of the cookie token
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(TS, default=now)
    expires_at: Mapped[datetime] = mapped_column(TS)
    ip: Mapped[str | None] = mapped_column(String(64))


class AuditLog(OrgMixin, Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(TS, default=now, index=True)
    actor: Mapped[str] = mapped_column(String(255))
    actor_role: Mapped[str | None] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(128), index=True)
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(64))
    ip: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict] = mapped_column(default=dict)


class Asset(OrgMixin, Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("org_id", "ref"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    ref: Mapped[str] = mapped_column(String(512))  # s3://bucket, db://meridian/table, vendor://..., cdn://...
    kind: Mapped[str] = mapped_column(String(32))  # bucket | object | table | vendor | ai_tool | cdn | integration
    name: Mapped[str] = mapped_column(String(255))
    connector: Mapped[str] = mapped_column(String(64))  # MOCK/SANDBOX connector name
    is_mock: Mapped[bool] = mapped_column(Boolean, default=True)
    classification: Mapped[str | None] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), default="OK")
    attributes: Mapped[dict] = mapped_column(default=dict)
    discovered_at: Mapped[datetime] = mapped_column(TS, default=now)
    updated_at: Mapped[datetime] = mapped_column(TS, default=now, onupdate=now)


class AssetRelationship(OrgMixin, Base):
    __tablename__ = "asset_relationships"
    __table_args__ = (UniqueConstraint("src_id", "dst_id", "kind"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    src_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    dst_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(32))  # replicates_to | fronted_by | synced_to | backed_up_to | contains
    attributes: Mapped[dict] = mapped_column(default=dict)


class AccessEvent(OrgMixin, Base):
    __tablename__ = "access_events"
    __table_args__ = (UniqueConstraint("source", "request_id"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(32), index=True)  # minio_audit | nginx | synthetic
    request_id: Mapped[str] = mapped_column(String(128))
    ts: Mapped[datetime] = mapped_column(TS, index=True)
    bucket: Mapped[str | None] = mapped_column(String(255), index=True)
    object_key: Mapped[str | None] = mapped_column(String(1024))
    api: Mapped[str | None] = mapped_column(String(64))
    method: Mapped[str | None] = mapped_column(String(16))
    status: Mapped[int | None] = mapped_column(Integer)
    bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    remote_ip: Mapped[str | None] = mapped_column(String(64))
    principal: Mapped[str | None] = mapped_column(String(128))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    cache_status: Mapped[str | None] = mapped_column(String(16))
    probe_run_id: Mapped[str | None] = mapped_column(String(64))
    authenticated: Mapped[bool] = mapped_column(Boolean, default=False)
    synthetic_history: Mapped[bool] = mapped_column(Boolean, default=False)
    raw: Mapped[dict] = mapped_column(default=dict)  # sanitised (no headers with secrets)


class Drill(OrgMixin, Base):
    __tablename__ = "drills"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    scenario_id: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), default="CREATED")
    seed: Mapped[int] = mapped_column(Integer, default=42)
    params: Mapped[dict] = mapped_column(default=dict)
    harness: Mapped[dict] = mapped_column(default=dict)  # harness-only record; agents never read this
    incident_id: Mapped[str | None] = mapped_column(String(32))
    auto_approve: Mapped[bool] = mapped_column(Boolean, default=False)
    demo: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(TS, default=now)
    started_at: Mapped[datetime | None] = mapped_column(TS)
    finished_at: Mapped[datetime | None] = mapped_column(TS)
    error: Mapped[str | None] = mapped_column(Text)


class Incident(OrgMixin, Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    ref: Mapped[str] = mapped_column(String(32), unique=True)
    scenario_id: Mapped[str | None] = mapped_column(String(64))
    drill_id: Mapped[str | None] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(512))
    summary: Mapped[str] = mapped_column(Text, default="")
    exposure_type: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="DETECTED", index=True)
    severity: Mapped[str] = mapped_column(String(16), default="Moderate")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_factors: Mapped[list] = mapped_column(default=list)
    access_verdict: Mapped[str | None] = mapped_column(String(64))
    latest_verification: Mapped[str | None] = mapped_column(String(32))
    detected_at: Mapped[datetime] = mapped_column(TS, default=now)
    exposure_started_at: Mapped[datetime | None] = mapped_column(TS)
    verified_fixed_at: Mapped[datetime | None] = mapped_column(TS)
    closed_at: Mapped[datetime | None] = mapped_column(TS)
    closed_by: Mapped[str | None] = mapped_column(String(255))
    timings: Mapped[dict] = mapped_column(default=dict)  # monotonic-clock durations in ms
    scope: Mapped[dict] = mapped_column(default=dict)  # e.g. {"buckets": [...]} assets the incident covers
    created_at: Mapped[datetime] = mapped_column(TS, default=now)
    updated_at: Mapped[datetime] = mapped_column(TS, default=now, onupdate=now)


class Finding(OrgMixin, Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    drill_id: Mapped[str | None] = mapped_column(String(32), index=True)
    asset_ref: Mapped[str] = mapped_column(String(512))
    detector: Mapped[str] = mapped_column(String(64))
    finding_type: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(16))
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False)  # e.g. decoy rejected by context
    data_categories: Mapped[dict] = mapped_column(default=dict)
    record_count: Mapped[int | None] = mapped_column(Integer)
    masked_samples: Mapped[dict] = mapped_column(default=dict)
    details: Mapped[dict] = mapped_column(default=dict)
    confidence: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(TS, default=now)


class SubjectSet(OrgMixin, Base):
    """Keyed fingerprints (HMAC-SHA256:v1:...) of affected subjects. Not raw identifiers."""
    __tablename__ = "subject_sets"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    label: Mapped[str] = mapped_column(String(512))
    fingerprints: Mapped[list] = mapped_column(default=list)
    created_at: Mapped[datetime] = mapped_column(TS, default=now)


class Investigation(OrgMixin, Base):
    __tablename__ = "investigations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    verdict: Mapped[str] = mapped_column(String(64))
    confidence: Mapped[float] = mapped_column(Float)
    summary: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(default=dict)
    root_cause: Mapped[list] = mapped_column(default=list)
    timeline: Mapped[list] = mapped_column(default=list)
    log_coverage: Mapped[dict] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(TS, default=now)


class BlastRadius(OrgMixin, Base):
    __tablename__ = "blast_radius"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    record_count: Mapped[int] = mapped_column(Integer)
    data_categories: Mapped[dict] = mapped_column(default=dict)
    locations: Mapped[list] = mapped_column(default=list)
    unverified: Mapped[list] = mapped_column(default=list)
    exposure_paths: Mapped[list] = mapped_column(default=list)
    consent: Mapped[dict] = mapped_column(default=dict)
    graph: Mapped[dict] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(TS, default=now)


class RemediationAction(OrgMixin, Base):
    __tablename__ = "remediation_actions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    code: Mapped[str] = mapped_column(String(16))  # ACT-01
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    wave: Mapped[int] = mapped_column(Integer, default=1)
    action_type: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(512))
    problem: Mapped[str] = mapped_column(Text)
    change: Mapped[str] = mapped_column(Text)
    risk: Mapped[str] = mapped_column(Text)
    side_effects: Mapped[str] = mapped_column(Text)
    expected_outcome: Mapped[str] = mapped_column(Text)
    rollback_plan: Mapped[str] = mapped_column(Text)
    verification_requirement: Mapped[str] = mapped_column(Text)
    params: Mapped[dict] = mapped_column(default=dict)
    patch_diff: Mapped[str | None] = mapped_column(Text)
    safety: Mapped[dict] = mapped_column(default=dict)
    depends_on: Mapped[list] = mapped_column(default=list)
    approval_status: Mapped[str] = mapped_column(String(16), default="PENDING")  # PENDING|HELD|APPROVED|REJECTED
    execution_status: Mapped[str] = mapped_column(String(16), default="NOT_STARTED")
    result: Mapped[dict] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(TS, default=now)
    executed_at: Mapped[datetime | None] = mapped_column(TS)


class Approval(OrgMixin, Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    action_id: Mapped[str] = mapped_column(ForeignKey("remediation_actions.id", ondelete="CASCADE"), index=True)
    incident_id: Mapped[str] = mapped_column(String(32), index=True)
    decision: Mapped[str] = mapped_column(String(16))  # APPROVED | REJECTED
    user_id: Mapped[str] = mapped_column(String(32))
    user_email: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text, default="")
    presenter_auto: Mapped[bool] = mapped_column(Boolean, default=False)
    params_sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(TS, default=now)


class VerificationRun(OrgMixin, Base):
    __tablename__ = "verification_runs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    ref: Mapped[str] = mapped_column(String(32))
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    run_number: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), default="RUNNING")
    verdict: Mapped[str | None] = mapped_column(String(32))
    reasons: Mapped[list] = mapped_column(default=list)
    residual: Mapped[list] = mapped_column(default=list)
    targets: Mapped[list] = mapped_column(default=list)
    origin: Mapped[dict] = mapped_column(default=dict)
    external_results: Mapped[list] = mapped_column(default=list)
    authorised_results: Mapped[list] = mapped_column(default=list)
    copy_hunt: Mapped[list] = mapped_column(default=list)
    unverified: Mapped[list] = mapped_column(default=list)
    verifier_version: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(TS, default=now)
    finished_at: Mapped[datetime | None] = mapped_column(TS)


class AgentExecution(OrgMixin, Base):
    __tablename__ = "agent_executions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    incident_id: Mapped[str | None] = mapped_column(String(32), index=True)
    drill_id: Mapped[str | None] = mapped_column(String(32), index=True)
    agent: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="RUNNING")
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    started_at: Mapped[datetime] = mapped_column(TS, default=now)
    finished_at: Mapped[datetime | None] = mapped_column(TS)
    duration_ms: Mapped[float | None] = mapped_column(Float)
    confidence: Mapped[float | None] = mapped_column(Float)
    decision_summary: Mapped[str | None] = mapped_column(Text)
    input: Mapped[dict] = mapped_column(default=dict)
    output: Mapped[dict] = mapped_column(default=dict)
    evidence_refs: Mapped[list] = mapped_column(default=list)
    error: Mapped[str | None] = mapped_column(Text)


class AgentEvent(OrgMixin, Base):
    __tablename__ = "agent_events"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(TS, default=now)
    drill_id: Mapped[str | None] = mapped_column(String(32), index=True)
    incident_id: Mapped[str | None] = mapped_column(String(32), index=True)
    execution_id: Mapped[str | None] = mapped_column(String(32))
    agent: Mapped[str | None] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(32))  # agent.started | agent.step | agent.completed | agent.failed | drill.* | beat
    message: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(default=dict)


class EvidenceEvent(OrgMixin, Base):
    __tablename__ = "evidence_events"
    __table_args__ = (UniqueConstraint("incident_id", "seq"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(32), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    ts: Mapped[datetime] = mapped_column(TS, default=now)
    event_type: Mapped[str] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(255))
    metadata_: Mapped[dict] = mapped_column("metadata", default=dict)
    payload: Mapped[dict] = mapped_column(default=dict)
    payload_hash: Mapped[str] = mapped_column(String(64))
    previous_event_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64))


class EvidencePack(OrgMixin, Base):
    __tablename__ = "evidence_packs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    incident_id: Mapped[str] = mapped_column(String(32), index=True)
    created_at: Mapped[datetime] = mapped_column(TS, default=now)
    manifest_sha256: Mapped[str] = mapped_column(String(64))
    signature_b64: Mapped[str] = mapped_column(Text)
    key_id: Mapped[str] = mapped_column(String(64))
    algorithm: Mapped[str] = mapped_column(String(32), default="Ed25519")
    event_count: Mapped[int] = mapped_column(Integer)
    head_event_hash: Mapped[str] = mapped_column(String(64))
    file_name: Mapped[str] = mapped_column(String(255))
    file_sha256: Mapped[str] = mapped_column(String(64))
    files: Mapped[dict] = mapped_column(default=dict)
    built_ms: Mapped[float | None] = mapped_column(Float)


class ComplianceDraft(OrgMixin, Base):
    __tablename__ = "compliance_drafts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    incident_id: Mapped[str] = mapped_column(String(32), index=True)
    regime: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(512))
    body: Mapped[str] = mapped_column(Text)
    stamp: Mapped[str] = mapped_column(String(128), default="DRAFT — REQUIRES LEGAL AND COMPLIANCE REVIEW")
    status: Mapped[str] = mapped_column(String(32), default="DRAFT")
    created_at: Mapped[datetime] = mapped_column(TS, default=now)


class Obligation(OrgMixin, Base):
    """Set only by a human. MALLYA never decides an obligation applies or invents a deadline."""
    __tablename__ = "obligations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    incident_id: Mapped[str] = mapped_column(String(32), index=True)
    regime: Mapped[str] = mapped_column(String(64))
    label: Mapped[str] = mapped_column(String(255))
    start_time: Mapped[datetime] = mapped_column(TS)
    deadline_hours: Mapped[float] = mapped_column(Float)
    set_by: Mapped[str] = mapped_column(String(255))
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(TS, default=now)


class LLMCall(OrgMixin, Base):
    __tablename__ = "llm_calls"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    ts: Mapped[datetime] = mapped_column(TS, default=now, index=True)
    agent: Mapped[str] = mapped_column(String(64))
    incident_id: Mapped[str | None] = mapped_column(String(32))
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str | None] = mapped_column(String(128))
    purpose: Mapped[str] = mapped_column(String(128))
    shared_fields: Mapped[list] = mapped_column(default=list)
    payload_bytes: Mapped[int] = mapped_column(Integer)
    payload_sha256: Mapped[str] = mapped_column(String(64))
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    dlp_findings: Mapped[dict] = mapped_column(default=dict)  # types and counts only
    raw_identifiers_sent: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[float | None] = mapped_column(Float)
    fallback: Mapped[bool] = mapped_column(Boolean, default=False)
    is_test: Mapped[bool] = mapped_column(Boolean, default=False)


class PrivacyViolation(OrgMixin, Base):
    __tablename__ = "privacy_violations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    ts: Mapped[datetime] = mapped_column(TS, default=now)
    agent: Mapped[str] = mapped_column(String(64))
    incident_id: Mapped[str | None] = mapped_column(String(32))
    rule: Mapped[str] = mapped_column(String(64))
    detectors: Mapped[dict] = mapped_column(default=dict)  # e.g. {"pan": 2} - never the value
    field_paths: Mapped[list] = mapped_column(default=list)
    action: Mapped[str] = mapped_column(String(32), default="BLOCKED")
    is_test: Mapped[bool] = mapped_column(Boolean, default=False)


class PrivacyTestRun(OrgMixin, Base):
    __tablename__ = "privacy_test_runs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    ts: Mapped[datetime] = mapped_column(TS, default=now)
    passed: Mapped[int] = mapped_column(Integer)
    total: Mapped[int] = mapped_column(Integer)
    results: Mapped[list] = mapped_column(default=list)
    source: Mapped[str] = mapped_column(String(64), default="pytest")


class KV(OrgMixin, Base):
    __tablename__ = "kv"
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[dict] = mapped_column(default=dict)
    updated_at: Mapped[datetime] = mapped_column(TS, default=now, onupdate=now)


class BenchmarkRun(OrgMixin, Base):
    __tablename__ = "benchmark_runs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    created_at: Mapped[datetime] = mapped_column(TS, default=now)
    finished_at: Mapped[datetime | None] = mapped_column(TS)
    mode: Mapped[str] = mapped_column(String(32))
    config: Mapped[dict] = mapped_column(default=dict)
    status: Mapped[str] = mapped_column(String(16), default="RUNNING")
    runs: Mapped[list] = mapped_column(default=list)
    metrics: Mapped[dict] = mapped_column(default=dict)
    error: Mapped[str | None] = mapped_column(Text)
