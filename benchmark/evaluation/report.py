"""Benchmark exports: JSON (full), CSV (one row per run), PDF (summary). Failures included."""
from __future__ import annotations

import csv
import io
import json
import pathlib

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.core.db import session_scope
from app.models import BenchmarkRun

RESULTS = pathlib.Path(__file__).resolve().parent.parent / "results"
COLUMNS = ["idx", "set", "scenario", "params", "drill_id", "duration_ms", "tp", "fp", "fn", "verdict_expected", "verdict_got",
           "root_cause_ok", "blast_ok", "fingerprint_ok", "remediation_ok", "approval_ok", "idempotent", "first_verif_expected",
           "first_verif_got", "final_verif_got", "residual_detected", "failures", "error"]


def _row(r: dict) -> dict:
    s = r.get("score") or {}
    return {"idx": r.get("idx"), "set": r.get("set"), "scenario": r.get("scenario"), "params": json.dumps(r.get("params", {}), sort_keys=True),
            "drill_id": r.get("drill_id"), "duration_ms": r.get("duration_ms"),
            "tp": (s.get("detection") or {}).get("tp"), "fp": (s.get("detection") or {}).get("fp"), "fn": (s.get("detection") or {}).get("fn"),
            "verdict_expected": (s.get("verdict") or {}).get("expected"), "verdict_got": (s.get("verdict") or {}).get("got"),
            "root_cause_ok": (s.get("root_cause") or {}).get("correct"), "blast_ok": (s.get("blast_radius") or {}).get("correct"),
            "fingerprint_ok": (s.get("blast_radius") or {}).get("fingerprint_locations_correct"),
            "remediation_ok": (s.get("remediation") or {}).get("correct"), "approval_ok": (s.get("remediation") or {}).get("approval_compliance"),
            "idempotent": (s.get("remediation") or {}).get("idempotent"),
            "first_verif_expected": (s.get("verification") or {}).get("first_expected"), "first_verif_got": (s.get("verification") or {}).get("first_got"),
            "final_verif_got": (s.get("verification") or {}).get("final_got"), "residual_detected": (s.get("verification") or {}).get("residual_detected"),
            "failures": "; ".join(r.get("failures", [])), "error": r.get("error")}


def csv_bytes(b: BenchmarkRun) -> bytes:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLUMNS, lineterminator="\n")
    w.writeheader()
    for r in b.runs:
        if not r.get("skipped"):
            w.writerow(_row(r))
    return buf.getvalue().encode()


def json_bytes(b: BenchmarkRun) -> bytes:
    return json.dumps({"id": b.id, "created_at": b.created_at.isoformat(), "finished_at": b.finished_at.isoformat() if b.finished_at else None,
                       "status": b.status, "config": b.config, "metrics": b.metrics, "runs": b.runs}, indent=1, default=str).encode()


def pdf_bytes(b: BenchmarkRun) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=14 * mm, rightMargin=14 * mm, topMargin=12 * mm, bottomMargin=12 * mm,
                            title=f"MALLYA benchmark {b.id}")
    ss = getSampleStyleSheet()
    small = ss["BodyText"]
    small.fontSize, small.leading = 8, 10
    el = [Paragraph("MALLYA benchmark report", ss["Title"]),
          Paragraph(f"Run {b.id} · {b.created_at.isoformat()} · status {b.status}. Every number comes from real drills against the sandbox; "
                    "failed runs are included. " + b.config.get("disclosure", ""), small), Spacer(1, 6)]
    for label in ("main", "holdout", "llm_assisted"):
        m = b.metrics.get(label)
        if not m:
            continue
        d = m["detection"]
        rows = [["Metric", "Value", "n"], ["Runs (failed)", f"{m['sample_size']} ({m['failed_runs']})", ""],
                ["Detection precision / recall / F1", f"{d['precision']} / {d['recall']} / {d['f1']}", f"TP {d['tp']} FP {d['fp']} FN {d['fn']}"],
                ["Decoy false positives", str(d["decoy_false_positives"]), ""]]
        for k in ("verdict_accuracy", "verdict_accuracy_attempt_vs_success", "root_cause_accuracy", "blast_radius_accuracy", "fingerprint_accuracy",
                  "remediation_correctness", "approval_compliance", "idempotency", "verification_accuracy", "residual_exposure_detection",
                  "lite_recommendations"):
            rows.append([k.replace("_", " "), str(m[k]["value"]), str(m[k]["n"])])
        rows.append(["Composite (project-defined, not an industry standard)", str(m["composite"]["value"]), json.dumps(m["composite"]["parts"])])
        t = Table(rows, colWidths=[110 * mm, 40 * mm, 110 * mm])
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e7e9ee")),
                               ("FONTSIZE", (0, 0), (-1, -1), 8)]))
        el += [Paragraph(f"Set: {label}", ss["Heading2"]), t, Spacer(1, 6)]
    fz = b.metrics.get("holdout_frozen_detectors", {})
    el.append(Paragraph(f"Held-out detectors frozen at {fz.get('tag')}: {'yes' if fz.get('frozen') else 'NO — changed: ' + str(fz.get('changed'))}", small))
    fails = [(r["scenario"], f) for r in b.runs for f in r.get("failures", [])]
    el.append(Paragraph(f"Failures ({len(fails)})", ss["Heading2"]))
    for sid, f in fails or [("—", "none")]:
        el.append(Paragraph(f"{sid}: {f}", small))
    doc.build(el)
    return buf.getvalue()


def write_all(bench_id: str) -> pathlib.Path:
    with session_scope() as db:
        b = db.get(BenchmarkRun, bench_id)
        out = RESULTS / bench_id
        out.mkdir(parents=True, exist_ok=True)
        (out / "benchmark.json").write_bytes(json_bytes(b))
        (out / "runs.csv").write_bytes(csv_bytes(b))
        (out / "report.pdf").write_bytes(pdf_bytes(b))
    return out
