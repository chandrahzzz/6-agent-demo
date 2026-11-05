"""Benchmark runs (harness lives in benchmark/; this module only starts runs and serves results)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...audit.log import audit
from ...core import jobs
from ...core.db import get_db, session_scope
from ...core.errors import ApiError
from ...core.security import ANY_USER, require_roles
from ...drills import catalog
from ...models import BenchmarkRun, Drill, User
from ..util import get_or_404, row

router = APIRouter(prefix="/benchmarks", tags=["benchmarks"], dependencies=[Depends(ANY_USER)])


class RunIn(BaseModel):
    mode: str = Field(default="all", pattern="^(all|single)$")
    scenario: str | None = Field(default=None, max_length=64)
    repeats: int = Field(default=1, ge=1, le=5)
    holdout: bool = True
    compare_llm: bool = False
    per_deep: int = Field(default=2, ge=1, le=4)


@router.post("/run", status_code=202)
def start(body: RunIn, user: User = Depends(require_roles("ADMIN", "SECURITY_ANALYST"))) -> dict:
    from benchmark.evaluation import run as bench

    if body.mode == "single" and not catalog.get(body.scenario or ""):
        raise ApiError(422, "scenario_required", "Single mode needs a valid scenario id.")
    with session_scope() as db:
        if db.execute(select(BenchmarkRun).where(BenchmarkRun.status == "RUNNING")).scalars().first() or \
                db.execute(select(Drill).where(Drill.status == "RUNNING")).scalars().first():
            raise ApiError(409, "busy", "A benchmark or drill is already running.")
        b = BenchmarkRun(mode=body.mode, config=body.model_dump(), status="RUNNING")
        db.add(b)
        db.flush()
        bid = b.id
    jobs.submit(f"benchmark:{bid}", bench.run, body.mode, body.repeats, body.scenario if body.mode == "single" else None,
                body.holdout and body.mode == "all", body.compare_llm, 42, bid, body.per_deep)
    audit("benchmark.started", actor=user.email, actor_role=user.role, target_type="benchmark", target_id=bid, details=body.model_dump())
    return {"id": bid}


@router.get("")
def list_runs(db: Session = Depends(get_db)) -> dict:
    rs = db.execute(select(BenchmarkRun).order_by(BenchmarkRun.created_at.desc()).limit(20)).scalars().all()
    return {"items": [{**row(b, {"runs"}), "run_count": len(b.runs)} for b in rs]}


@router.get("/{bench_id}")
def get_run(bench_id: str, db: Session = Depends(get_db)) -> dict:
    return row(get_or_404(db, BenchmarkRun, bench_id, "Benchmark run"))


@router.get("/{bench_id}/export.{fmt}")
def export(bench_id: str, fmt: str, db: Session = Depends(get_db)) -> Response:
    from benchmark.evaluation import report

    b = get_or_404(db, BenchmarkRun, bench_id, "Benchmark run")
    if fmt == "csv":
        data, mt = report.csv_bytes(b), "text/csv"
    elif fmt == "json":
        data, mt = report.json_bytes(b), "application/json"
    elif fmt == "pdf":
        data, mt = report.pdf_bytes(b), "application/pdf"
    else:
        raise ApiError(404, "not_found", "Unknown export format.")
    return Response(data, media_type=mt, headers={"Content-Disposition": f'attachment; filename="mallya-benchmark-{bench_id}.{fmt}"'})
