"""Benchmark scenario generator: seeded variants + hidden ground truth.

Ground truth is computed from what the harness PLANTS (scenario parameters + the deterministic
synthetic-data generator), never from anything an agent produced. It is written to
benchmark/ground_truth/ and read only by benchmark/evaluation.

Disclosure: the same author wrote these scenarios and MALLYA's detectors.
"""
from __future__ import annotations

import pathlib
import random
import sys
from functools import lru_cache

import yaml

sys.path.insert(0, "/app/bench_support")
import synth  # noqa: E402  (deterministic generator, mounted read-only for the harness only)

ROOT = pathlib.Path(__file__).resolve().parent.parent
LITE_TRUTH = yaml.safe_load((ROOT / "ground_truth" / "static" / "lite_default_seed.yaml").read_text())
DATA_SEED = 42  # the sandbox's data seed (customers); variants vary the planted scenario, not the bank
ARCHIVE_ROWS = 4870


@lru_cache
def people():
    return synth.customers(DATA_SEED)


def _withdrawn_ids() -> set[str]:
    return {c.customer_id for c in people() if c.marketing_consent == "withdrawn"}


def hero_truth(p: dict) -> dict:
    # The edge cache ends up holding a copy if: the prefetch job warmed it, the attacker's variant-B download
    # pulled it through, or Northwind's nightly pull fetched the (public) replica through the CDN.
    cached = p.get("cdn_cached", True) or p["access_variant"] == "B" or p.get("replica_public", True)
    residual = (["CDN cache"] if cached else []) + (["replica bucket"] if p.get("replica_public", True) else [])
    return {
        "incidents": [{"type": "PUBLIC_STORAGE", "key": "meridian-customer-backups"}],
        "verdict": "LIKELY_EXFILTRATED" if p["access_variant"] == "B" else "ACCESS_ATTEMPTED_NOT_SUCCESSFUL",
        "root_cause": {"kind": "CONFIG_COMMIT", "author": "dev.rahul", "subject": "share backups with vendor"},
        "record_count": 5000, "location_counts": {"s3://meridian-archive/archive/2026-10/customers_full_2026-10-01.csv": ARCHIVE_ROWS},
        "expected_actions": {"bucket.set_private", "infra.patch_bucket_private", "infra.enable_policy_gate"}
                            | ({"cdn.purge"} if cached else set()) | ({"partner.presigned_handoff"} if p.get("replica_public", True) else set()),
        "first_verification": "PARTIALLY_FIXED" if residual else "VERIFIED_FIXED", "residual": residual,
        "final_verification": "VERIFIED_FIXED",
    }


def d02_truth(p: dict) -> dict:
    r = random.Random(f"d02-{p.get('variant_seed', 0)}")
    ids = set()
    for _ in range(int(p.get("n_sensitive", 3))):
        ids |= {c.customer_id for c in r.sample(people(), int(p.get("rows_per_doc", 25)))}
    cached = p["access_variant"] == "B"
    return {
        "incidents": [{"type": "PUBLIC_STORAGE", "key": "meridian-internal-docs"}],
        "verdict": "LIKELY_EXFILTRATED" if cached else "ACCESS_ATTEMPTED_NOT_SUCCESSFUL",
        "root_cause": {"kind": "CONFIG_COMMIT", "author": "meera.s", "subject": "open internal docs for contractor onboarding"},
        "record_count": len(ids), "sensitive_objects": int(p.get("n_sensitive", 3)),
        "expected_actions": {"bucket.set_private", "infra.patch_bucket_private", "infra.enable_policy_gate"} | ({"cdn.purge"} if cached else set()),
        "first_verification": "PARTIALLY_FIXED" if cached else "VERIFIED_FIXED", "residual": ["CDN cache"] if cached else [],
        "final_verification": "VERIFIED_FIXED",
    }


def d03_truth(p: dict) -> dict:
    lo = int(p.get("start", 1000))
    # The plant slices people[lo:lo+rows]; only 5,000 customers exist, so the export holds at most 5000 - lo rows.
    # (Bug found by held-out run 1: the generator assumed the full requested row count.)
    n = max(0, min(lo + int(p.get("rows", 800)), len(people())) - lo)
    cached = p["access_variant"] == "B"
    in_archive = max(0, min(lo + n, ARCHIVE_ROWS) - lo)
    return {
        "incidents": [{"type": "PUBLIC_EXPORT_LINK", "key": "meridian-exports"}],
        "verdict": "LIKELY_EXFILTRATED" if cached else "ACCESS_ATTEMPTED_NOT_SUCCESSFUL",
        "root_cause": {"kind": "OUT_OF_BAND_CHANGE", "principal": "finance-analyst"},
        "record_count": n, "location_counts": {"s3://meridian-archive/archive/2026-10/customers_full_2026-10-01.csv": in_archive},
        "expected_actions": {"bucket.set_private"} | ({"cdn.purge"} if cached else set()),
        "first_verification": "PARTIALLY_FIXED" if cached else "VERIFIED_FIXED", "residual": ["CDN cache"] if cached else [],
        "final_verification": "VERIFIED_FIXED",
    }


def d04_truth(p: dict) -> dict:
    r = random.Random(f"d04-{p.get('variant_seed', 0)}")
    members = r.sample(people(), int(p.get("members", 1200)))
    wd = _withdrawn_ids()
    n = sum(1 for c in members if c.customer_id in wd)
    return {
        "incidents": [{"type": "CONSENT_MISMATCH", "key": "JOB-NW-SYNC"}] if n else [],
        "verdict": "ACCESSED_INTERNAL_ONLY", "root_cause": {"kind": "INTEGRATION_CONFIG", "principal": "meera.s"},
        "record_count": n,
        "expected_actions": {"integration.disable_sync", "vendor.delete_subjects", "integration.enable_consent_filter"},
        "first_verification": "VERIFIED_FIXED", "residual": [], "final_verification": "VERIFIED_FIXED",
    }


def d05_truth(p: dict) -> dict:
    return {
        "incidents": [{"type": "SHADOW_AI_UPLOAD", "key": "quicksummarize"}],
        "verdict": "LIKELY_EXFILTRATED", "root_cause": {"kind": "SHADOW_IT", "principal": "arjun.k"},
        "record_count": int(p.get("rows", 150)),
        "expected_actions": {"vendor.ai_delete_uploads", "integration.block_vendor"},
        "first_verification": "VERIFIED_FIXED", "residual": [], "final_verification": "VERIFIED_FIXED",
    }


def lite_truth(sid: str) -> dict:
    t = LITE_TRUTH[sid]
    return {"incidents": [{"type": f"LITE:{sid}", "key": t["asset"]}], "verdict": t["verdict"], "lite": True}


TRUTH = {"HERO-01": hero_truth, "D-02": d02_truth, "D-03": d03_truth, "D-04": d04_truth, "D-05": d05_truth}


def variants(seed: int, *, per_deep: int = 2) -> list[tuple[str, dict]]:
    """Main benchmark set."""
    r = random.Random(f"benchmark-{seed}")
    out: list[tuple[str, dict]] = []
    for i in range(per_deep):
        v = "A" if i % 2 == 0 else "B"
        out.append(("HERO-01", {"access_variant": v, "replica_public": r.random() < 0.8, "cdn_cached": r.random() < 0.8}))
        out.append(("D-02", {"access_variant": v, "n_sensitive": r.randint(2, 4), "rows_per_doc": r.randint(10, 40),
                             "variant_seed": r.randint(1, 10_000)}))
        out.append(("D-03", {"access_variant": v, "rows": r.randint(200, 1200), "start": r.randint(0, 3500)}))
        out.append(("D-04", {"members": r.randint(400, 2000), "variant_seed": r.randint(1, 10_000)}))
        out.append(("D-05", {"rows": r.randint(40, 300), "variant_seed": r.randint(1, 10_000)}))
    for sid in sorted(LITE_TRUTH):
        out.append((sid, {"variant_seed": r.randint(1, 10_000)}))
    return out


def truth_for(sid: str, params: dict) -> dict:
    return lite_truth(sid) if sid in LITE_TRUTH else TRUTH[sid](params)
