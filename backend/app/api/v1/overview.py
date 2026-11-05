"""Dashboard, assets, agents, privacy, audit, settings, health. Every number is computed from stored runs."""
from __future__ import annotations

from statistics import mean

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ... import connectors
from ...agents.base import AGENTS
from ...audit.log import audit
from ...core.db import get_db
from ...core.security import ANY_USER, require_roles
from ...models import (KV, AgentExecution, Asset, AssetRelationship, AuditLog, BenchmarkRun, Incident, LLMCall,
                       PrivacyTestRun, PrivacyViolation, User, VerificationRun)
from ..util import Page, paginate, row

router = APIRouter(tags=["overview"], dependencies=[Depends(ANY_USER)])
public = APIRouter(tags=["health"])
ACTIVE = ("DETECTED", "INVESTIGATING", "AWAITING_APPROVAL", "REMEDIATING", "VERIFYING", "PARTIALLY_FIXED",
          "STILL_EXPOSED", "UNVERIFIED")


@public.get("/health")
def health(db: Session = Depends(get_db)) -> dict:
    db.execute(select(1))
    checks = {"database": True}
    try:
        connectors.worker("GET", "/health", timeout=3)
        checks["worker"] = True
    except connectors.ConnectorError:
        checks["worker"] = False
    return {"ok": all(checks.values()), "checks": checks, "environment": "SANDBOX", "org": "Meridian Bank (fictional)"}


def privacy_summary(db: Session) -> dict:
    calls = db.execute(select(LLMCall)).scalars().all()
    try:
        worker_stats = connectors.worker("GET", "/stats", timeout=5)
    except connectors.ConnectorError:
        worker_stats = None
    tests = db.execute(select(PrivacyTestRun).order_by(PrivacyTestRun.ts.desc())).scalars().first()
    violations = db.execute(select(func.count()).select_from(PrivacyViolation).where(PrivacyViolation.is_test.is_(False))).scalar_one()
    raw_sent = sum(c.raw_identifiers_sent for c in calls if not c.blocked)
    return {
        "detected_locally": worker_stats.get("detected") if worker_stats else None,
        "masked": worker_stats.get("masked") if worker_stats else None,
        "fingerprinted": worker_stats.get("fingerprinted") if worker_stats else None,
        "worker_available": worker_stats is not None,
        "llm_calls": sum(1 for c in calls if not c.blocked),
        "llm_calls_by_provider": {p: sum(1 for c in calls if c.provider == p and not c.blocked) for p in {c.provider for c in calls}},
        "payloads_blocked": sum(1 for c in calls if c.blocked),
        "violations": violations,
        "raw_identifiers_sent_to_ai": raw_sent,
        # Computed: outbound payloads that passed DLP contained zero identifier candidates by construction;
        # blocked payloads never left. The headline is only shown when at least one call was audited.
        "headline_ok": raw_sent == 0,
        "tests": {"passed": tests.passed, "total": tests.total, "ts": tests.ts.isoformat()} if tests else None,
    }


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db)) -> dict:
    incs = db.execute(select(Incident)).scalars().all()
    runs = db.execute(select(VerificationRun)).scalars().all()
    active = [i for i in incs if i.status in ACTIVE]
    detect = [i.timings.get("detect_ms") for i in incs if (i.timings or {}).get("detect_ms")]
    fixed = [i.timings.get("detect_to_verified_fix_wall_ms") for i in incs if (i.timings or {}).get("detect_to_verified_fix_wall_ms")]
    bench = db.execute(select(BenchmarkRun).where(BenchmarkRun.status == "COMPLETED").order_by(BenchmarkRun.created_at.desc())).scalars().first()
    return {
        "active_incidents": len(active),
        "critical_exposures": sum(1 for i in active if i.severity == "Critical"),
        "assets": db.execute(select(func.count()).select_from(Asset)).scalar_one(),
        "assets_exposed": db.execute(select(func.count()).select_from(Asset).where(Asset.status == "EXPOSED")).scalar_one(),
        "verified_fixes": sum(1 for i in incs if i.verified_fixed_at),
        "open_verification_checks": sum(1 for i in incs if i.latest_verification in ("PARTIALLY_FIXED", "STILL_EXPOSED", "UNVERIFIED")
                                        and i.status != "CLOSED"),
        "verification_runs": len(runs),
        "mean_time_to_detect_ms": round(mean(detect), 1) if detect else None,
        "mean_time_to_verified_fix_ms": round(mean(fixed), 1) if fixed else None,
        "samples": {"detect": len(detect), "verified_fix": len(fixed)},
        "benchmark": {"composite": bench.metrics.get("composite"), "run_id": bench.id, "at": bench.created_at.isoformat()} if bench else None,
        "privacy": privacy_summary(db),
        "recent_incidents": [row(i, {"risk_factors"}) for i in sorted(incs, key=lambda x: x.detected_at, reverse=True)[:6]],
    }


@router.get("/assets")
def assets(page: Page = Depends(), kind: str | None = None, db: Session = Depends(get_db)) -> dict:
    q = select(Asset).order_by(Asset.kind, Asset.name)
    if kind:
        q = q.where(Asset.kind == kind)
    return paginate(db, q, page)


@router.get("/assets/relationships")
def relationships(db: Session = Depends(get_db)) -> dict:
    return {"items": [row(r) for r in db.execute(select(AssetRelationship)).scalars()]}


@router.get("/connectors")
def connectors_list() -> dict:
    return {"items": connectors.CONNECTORS}


@router.get("/agents")
def agents(db: Session = Depends(get_db)) -> dict:
    out = []
    for key, label in AGENTS.items():
        ex = db.execute(select(AgentExecution).where(AgentExecution.agent == key)).scalars().all()
        done = [e for e in ex if e.duration_ms is not None]
        out.append({"agent": key, "label": label, "executions": len(ex),
                    "failed": sum(1 for e in ex if e.status == "FAILED"),
                    "mean_duration_ms": round(mean(e.duration_ms for e in done), 1) if done else None,
                    "last": row(max(ex, key=lambda e: e.started_at), {"input", "output"}) if ex else None})
    return {"items": out}


@router.get("/agents/executions")
def executions(page: Page = Depends(), agent: str | None = None, db: Session = Depends(get_db)) -> dict:
    q = select(AgentExecution).order_by(AgentExecution.started_at.desc())
    if agent:
        q = q.where(AgentExecution.agent == agent)
    return paginate(db, q, page, exclude={"input"})


@router.get("/privacy/summary")
def privacy(db: Session = Depends(get_db)) -> dict:
    return privacy_summary(db)


@router.get("/privacy/tests")
def privacy_tests(db: Session = Depends(get_db)) -> dict:
    t = db.execute(select(PrivacyTestRun).order_by(PrivacyTestRun.ts.desc())).scalars().first()
    return row(t) if t else {}


@router.get("/privacy/violations")
def violations(page: Page = Depends(), db: Session = Depends(get_db)) -> dict:
    return paginate(db, select(PrivacyViolation).order_by(PrivacyViolation.ts.desc()), page)


@router.get("/privacy/llm-calls")
def llm_calls(page: Page = Depends(), db: Session = Depends(get_db)) -> dict:
    return paginate(db, select(LLMCall).order_by(LLMCall.ts.desc()), page)


@router.get("/audit-logs")
def audit_logs(page: Page = Depends(), db: Session = Depends(get_db)) -> dict:
    return paginate(db, select(AuditLog).order_by(AuditLog.ts.desc()), page)


class RegContext(BaseModel):
    regimes: list[str] = Field(max_length=5)


@router.get("/settings")
def get_settings(db: Session = Depends(get_db)) -> dict:
    from ...agents.compliance import REGIMES, regulatory_context
    from ...core.config import settings as cfg
    return {"regulatory_context": regulatory_context(db), "available_regimes": {k: v[0] for k, v in REGIMES.items()},
            "llm_provider": cfg().llm_provider, "environment": "SANDBOX", "demo_mode": cfg().demo_mode}


@router.put("/settings/regulatory-context")
def put_reg(body: RegContext, user: User = Depends(require_roles("ADMIN", "SECURITY_ANALYST")), db: Session = Depends(get_db)) -> dict:
    from ...agents.compliance import REGIMES
    regimes = [r for r in body.regimes if r in REGIMES]
    db.merge(KV(key="settings:regulatory_context", value={"regimes": regimes}))
    db.commit()
    audit("settings.regulatory_context", actor=user.email, actor_role=user.role, details={"regimes": regimes})
    return {"regulatory_context": regimes}
