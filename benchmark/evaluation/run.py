"""Benchmark runner. Every number comes from a real drill against the sandbox.

    python -m benchmark.evaluation.run --mode all [--repeats N] [--scenario HERO-01] [--holdout] [--compare-llm]

Modes: single scenario, all scenarios, N repeats, deterministic vs LLM-assisted comparison.
Failed runs are recorded and counted (a crashed run counts as a missed detection), never dropped.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import time
import traceback

from app.core.db import session_scope
from app.drills import engine
from app.models import BenchmarkRun, Drill, now
from app.privacy import provider

from ..holdout import generator as holdout
from ..scenarios import generator
from . import metrics, report

ROOT = pathlib.Path(__file__).resolve().parent.parent
GT_DIR = ROOT / "ground_truth"
RESULTS = ROOT / "results"
FROZEN = ROOT / "holdout" / "FROZEN_DETECTORS.json"
DETECTOR_FILES = ["/app/shared/mallya_common/detectors.py", "/app/shared/mallya_common/verhoeff.py",
                  "/app/shared/mallya_common/masking.py", "/app/shared/mallya_common/fingerprint.py"]


def detector_hashes() -> dict:
    return {pathlib.Path(f).name: hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest() for f in DETECTOR_FILES}


def frozen_status() -> dict:
    if not FROZEN.exists():
        return {"frozen": False, "reason": "FROZEN_DETECTORS.json missing"}
    want = json.loads(FROZEN.read_text())
    have = detector_hashes()
    changed = [k for k, v in want["sha256"].items() if have.get(k) != v]
    return {"frozen": not changed, "tag": want["tag"], "changed": changed}


def run_one(bench_id: str, idx: int, sid: str, params: dict, label: str) -> dict:
    truth = generator.truth_for(sid, params)
    gt_path = GT_DIR / bench_id / f"{idx:03d}-{sid}.json"
    gt_path.parent.mkdir(parents=True, exist_ok=True)
    gt_path.write_text(json.dumps({"scenario": sid, "params": params, "truth": truth}, default=sorted, indent=1))
    rec: dict = {"idx": idx, "set": label, "scenario": sid, "params": params}
    t0 = time.monotonic()
    try:
        with session_scope() as db:
            d = Drill(scenario_id=sid, seed=generator.DATA_SEED, auto_approve=True, demo=False, created_by="benchmark",
                      params={**params, "reset": True})
            db.add(d)
            db.flush()
            rec["drill_id"] = d.id
        engine.run_drill(rec["drill_id"])
        rec["score"] = metrics.score_run(rec["drill_id"], truth)
    except Exception as exc:  # noqa: BLE001 - failures are results too
        rec["error"] = f"{type(exc).__name__}: {exc}"[:500]
        rec["trace"] = traceback.format_exc()[-1500:]
    rec["duration_ms"] = round((time.monotonic() - t0) * 1000, 1)
    rec["failures"] = failures_of(rec)
    return rec


def failures_of(rec: dict) -> list[str]:
    if rec.get("error"):
        return [f"run crashed: {rec['error']}"]
    s, out = rec["score"], []
    d = s["detection"]
    if d["fn"]:
        out.append(f"missed {d['fn']} expected incident(s)")
    if d["fp"]:
        out.append(f"{d['fp']} false positive(s)")
    for k in ("verdict", "root_cause", "blast_radius"):
        if k in s and not s[k]["correct"]:
            out.append(f"{k.replace('_', ' ')} wrong: expected {s[k].get('expected', s[k].get('expected_records'))}, "
                       f"got {s[k].get('got', s[k].get('got_records'))}")
    if "blast_radius" in s and not s["blast_radius"]["fingerprint_locations_correct"]:
        out.append("fingerprint match count at a known copy location is wrong")
    if "remediation" in s:
        r = s["remediation"]
        if not r["correct"]:
            out.append(f"remediation incomplete: expected {r['expected_actions']}, executed {r['executed']}")
        if not r["approval_compliance"]:
            out.append("an action executed without a prior approval")
        if r["idempotent"] is False:
            out.append("replaying an approval acted twice")
    if "verification" in s:
        v = s["verification"]
        if not v["first_correct"]:
            out.append(f"first verification {v['first_got']}, expected {v['first_expected']}")
        if not v["final_correct"]:
            out.append(f"final verification {v['final_got']}, expected {v['final_expected']}")
        if not v["residual_detected"]:
            out.append(f"residual exposure missed: expected {v['residual_expected']}, got {v['residual_got']}")
    return out


def run(mode: str = "all", repeats: int = 1, scenario: str | None = None, include_holdout: bool = True,
        compare_llm: bool = False, seed: int = 42, bench_id: str | None = None, per_deep: int = 2) -> str:
    config = {"mode": mode, "repeats": repeats, "scenario": scenario, "holdout": include_holdout, "compare_llm": compare_llm,
              "benchmark_seed": seed, "data_seed": generator.DATA_SEED, "per_deep_variants": per_deep,
              "llm_provider": provider.active_name(), "detector_sha256": detector_hashes(),
              "disclosure": "The same author wrote the scenarios, the ground-truth generator and MALLYA's detectors."}
    with session_scope() as db:
        if bench_id:
            b = db.get(BenchmarkRun, bench_id)
            b.config = config
        else:
            b = BenchmarkRun(mode=mode, config=config, status="RUNNING")
            db.add(b)
            db.flush()
        bench_id = b.id
    plan: list[tuple[str, str, dict]] = []
    main = [(s, p) for s, p in generator.variants(seed, per_deep=per_deep) if not scenario or s == scenario]
    for _ in range(max(1, repeats)):
        plan += [("main", s, p) for s, p in main]
    frozen = frozen_status()
    if include_holdout and not scenario:
        plan += [("holdout", s, p) for s, p in holdout.variants()]
    runs: list[dict] = []
    try:
        for i, (label, sid, params) in enumerate(plan, start=1):
            runs.append(run_one(bench_id, i, sid, params, label))
            _save(bench_id, runs, plan, frozen, done=False)
        if compare_llm:
            runs += _llm_comparison(bench_id, main, len(plan))
        _save(bench_id, runs, plan, frozen, done=True)
    except Exception as exc:  # noqa: BLE001
        with session_scope() as db:
            b = db.get(BenchmarkRun, bench_id)
            b.status, b.error, b.finished_at = "FAILED", f"{type(exc).__name__}: {exc}"[:1000], now()
        raise
    return bench_id


def _llm_comparison(bench_id: str, main: list, offset: int) -> list[dict]:
    from app.core.config import settings
    s = settings()
    if not (s.anthropic_api_key or s.openai_api_key):
        return [{"set": "llm_assisted", "scenario": "*", "skipped": True,
                 "reason": "LLM-assisted run not executed: no ANTHROPIC_API_KEY or OPENAI_API_KEY configured"}]
    provider.OVERRIDE = "anthropic" if s.anthropic_api_key else "openai"
    try:
        return [run_one(bench_id, offset + i, sid, p, "llm_assisted") for i, (sid, p) in enumerate(main[:5], start=1)]
    finally:
        provider.OVERRIDE = None


def _save(bench_id: str, runs: list[dict], plan: list, frozen: dict, done: bool) -> None:
    sets = {}
    for label in ("main", "holdout", "llm_assisted"):
        sub = [r for r in runs if r.get("set") == label and not r.get("skipped")]
        if sub:
            sets[label] = metrics.aggregate(sub)
    sets["holdout_frozen_detectors"] = frozen
    sets["planned_runs"] = len(plan)
    sets["composite"] = (sets.get("main") or {}).get("composite", {}).get("value")
    with session_scope() as db:
        b = db.get(BenchmarkRun, bench_id)
        b.runs = [{k: v for k, v in r.items() if k != "trace"} for r in runs]
        b.metrics = sets
        if done:
            b.status, b.finished_at = "COMPLETED", now()
    if done:
        report.write_all(bench_id)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="all", choices=["all", "single"])
    ap.add_argument("--scenario")
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--no-holdout", action="store_true")
    ap.add_argument("--compare-llm", action="store_true")
    ap.add_argument("--per-deep", type=int, default=2)
    a = ap.parse_args()
    bid = run(a.mode, a.repeats, a.scenario, not a.no_holdout, a.compare_llm, per_deep=a.per_deep)
    print(json.dumps({"benchmark_id": bid, "results_dir": str(RESULTS / bid)}))
