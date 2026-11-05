"""Meridian Bank customer-side database (synthetic). Only the worker connects to it."""
from __future__ import annotations

from functools import lru_cache

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from .config import settings
from .synth import Customer

SCHEMA = """
DROP TABLE IF EXISTS customers, consent_records, retention_records, synthetic_registry, qa_fixture_cases,
  marketing_campaign_members, integration_registry, integration_jobs, ropa_entries, health_claims,
  worker_stats, scan_log, executed_actions CASCADE;

CREATE TABLE customers (
  customer_id TEXT PRIMARY KEY, account_id TEXT NOT NULL, full_name TEXT NOT NULL, pan_number TEXT NOT NULL,
  aadhaar TEXT NOT NULL, phone TEXT NOT NULL, email TEXT NOT NULL, segment TEXT NOT NULL, created_at DATE NOT NULL);
CREATE TABLE consent_records (
  customer_id TEXT NOT NULL, purpose TEXT NOT NULL, state TEXT NOT NULL, changed_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (customer_id, purpose));
CREATE TABLE retention_records (
  customer_id TEXT PRIMARY KEY, retention_class TEXT NOT NULL, retain_until DATE NOT NULL, last_reviewed DATE);
-- fingerprints of values the sandbox generated itself (for CONFIRMED_SYNTHETIC_TEST_VALUE)
CREATE TABLE synthetic_registry (fingerprint TEXT PRIMARY KEY, category TEXT NOT NULL);
-- DECOY: PAN-shaped strings in a non-PII column
CREATE TABLE qa_fixture_cases (test_case_id TEXT PRIMARY KEY, label_code TEXT NOT NULL, expected_result TEXT NOT NULL);
CREATE TABLE marketing_campaign_members (
  campaign_id TEXT NOT NULL, customer_id TEXT NOT NULL, email TEXT NOT NULL, phone TEXT NOT NULL,
  added_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (campaign_id, customer_id));
CREATE TABLE integration_registry (
  integration_id TEXT PRIMARY KEY, vendor TEXT NOT NULL, purpose TEXT NOT NULL, endpoint TEXT NOT NULL,
  approved BOOLEAN NOT NULL, is_ai_tool BOOLEAN NOT NULL DEFAULT FALSE, data_categories TEXT NOT NULL,
  granted_scopes TEXT NOT NULL, required_scopes TEXT NOT NULL, credential_expires_at TIMESTAMPTZ,
  ropa_ref TEXT, blocked BOOLEAN NOT NULL DEFAULT FALSE);
CREATE TABLE integration_jobs (
  job_id TEXT PRIMARY KEY, integration_id TEXT NOT NULL, source_table TEXT NOT NULL, enabled BOOLEAN NOT NULL,
  last_run_at TIMESTAMPTZ, filter_withdrawn_consent BOOLEAN NOT NULL DEFAULT FALSE);
CREATE TABLE ropa_entries (ropa_ref TEXT PRIMARY KEY, activity TEXT NOT NULL, purpose TEXT NOT NULL, lawful_basis TEXT NOT NULL);
CREATE TABLE health_claims (claim_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, diagnosis_code TEXT NOT NULL, amount_inr INTEGER NOT NULL);
CREATE TABLE worker_stats (k TEXT PRIMARY KEY, v BIGINT NOT NULL DEFAULT 0);
"""


@lru_cache
def engine() -> Engine:
    return create_engine(settings().meridian_db_url, pool_pre_ping=True, future=True)


def reset_schema() -> None:
    with engine().begin() as con:
        for stmt in SCHEMA.split(";"):
            if stmt.strip():
                con.execute(text(stmt))
        con.execute(text("INSERT INTO worker_stats (k, v) VALUES ('detected',0),('masked',0),('fingerprinted',0),('scans',0)"))


def load_customers(rows: list[Customer], fp) -> None:
    with engine().begin() as con:
        con.execute(text(
            "INSERT INTO customers VALUES (:customer_id,:account_id,:full_name,:pan,:aadhaar,:phone,:email,:segment,:created_at)"),
            [c.__dict__ for c in rows])
        consent = []
        for c in rows:
            consent += [
                {"customer_id": c.customer_id, "purpose": "marketing", "state": c.marketing_consent, "changed_at": c.marketing_consent_changed_at},
                {"customer_id": c.customer_id, "purpose": "analytics", "state": c.analytics_consent, "changed_at": c.marketing_consent_changed_at},
                {"customer_id": c.customer_id, "purpose": "third_party_sharing", "state": c.third_party_consent, "changed_at": c.marketing_consent_changed_at},
            ]
        con.execute(text("INSERT INTO consent_records VALUES (:customer_id,:purpose,:state,:changed_at)"), consent)
        con.execute(text("INSERT INTO retention_records VALUES (:customer_id,:retention_class,:retain_until,:retention_last_reviewed)"),
                    [c.__dict__ for c in rows])
        reg = []
        for c in rows:
            reg += [{"f": fp("pan", c.pan), "c": "pan"}, {"f": fp("aadhaar", c.aadhaar), "c": "aadhaar"}]
        con.execute(text("INSERT INTO synthetic_registry VALUES (:f, :c) ON CONFLICT DO NOTHING"), reg)


def bump(**counts: int) -> None:
    with engine().begin() as con:
        for k, v in counts.items():
            con.execute(text("UPDATE worker_stats SET v = v + :v WHERE k = :k"), {"k": k, "v": v})


def stats() -> dict:
    with engine().connect() as con:
        return {r.k: int(r.v) for r in con.execute(text("SELECT k, v FROM worker_stats"))}


def synthetic_registry() -> set[str]:
    with engine().connect() as con:
        return {r[0] for r in con.execute(text("SELECT fingerprint FROM synthetic_registry"))}


def query(sql: str, **params) -> list[dict]:
    with engine().connect() as con:
        return [dict(r._mapping) for r in con.execute(text(sql), params)]


def execute(sql: str, **params) -> int:
    with engine().begin() as con:
        return con.execute(text(sql), params).rowcount
