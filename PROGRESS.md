# MALLYA — Progress (final)

## Milestones

| Milestone | Status | Evidence |
|---|---|---|
| M0 Foundation | Done | 13-service compose; Alembic (2 revisions, 26 tables); Argon2 + cookie sessions; 4 roles; console shell |
| M1 Hero slice | Done | `tests/test_e2e_hero.py` 2/2 from a clean reset. Variant A: full loop with manual approvals, PARTIALLY_FIXED (real CDN cache + held replica), then VERIFIED_FIXED. Variant B: LIKELY_EXFILTRATED. |
| M2 Evidence | Done | `tests/test_evidence_tamper.py` 9/9; standalone `tools/mallya_verify.py` |
| M3 Privacy boundary | Done | `tools/privacy_suite.py` 13/13, including the leak scan of logs, DB, telemetry, exports and API, with a positive control |
| M4 Deep scenarios | Done | `tests/test_e2e_deep.py` 4/4 (D-02…D-05) |
| M5 Lite scenarios | Done | `tests/test_lite.py` 15/15: exactly one incident of the planted type, correct verdict, recommendation only |
| M6 Benchmark | Done | 3 recorded runs (below), failures kept |
| M7 Frontend polish | Done | 48 screenshots in `docs/screenshots/` (1440/390 × dark/light × 12 screens); baseline-ui, fixing-accessibility and fixing-motion-performance applied |
| M8 Demo + docs | Done | Demo Mode; `docs/demo-script.md`; architecture, privacy, evidence, security, threat model, limitations, setup, API, benchmark methodology |

## Test results (final pass, 2026-11-05)

| Suite | Result |
|---|---|
| Backend: unit, boundary, privacy, tamper, HERO E2E, Deep E2E (`pytest`, without lite) | **44 passed** (194 s) |
| Backend: Lite E2E (`tests/test_lite.py`) | **15 passed** (158 s) |
| Worker (`pytest`, including the live policy-gate block of the re-applied bad commit) | **3 passed** |
| Privacy suite (`python tools/privacy_suite.py`) | **13/13** (387 artefacts, 0 raw identifiers, positive control 4/4) |
| Frontend: Vitest | **5 passed** |
| Frontend: `tsc --noEmit` | clean |

Definition-of-Done proofs: verifier cannot reach MinIO except via nginx (`test_verifier_cannot_reach_minio_except_via_nginx`); a cached copy or exposed replica prevents VERIFIED_FIXED (HERO E2E plus unit tests); the re-applied bad commit is blocked (worker live test, and the regression check inside every gate action); ground-truth import boundary (`test_ground_truth_import_boundary`); tampering detected (9 tamper tests); closing is refused unless the latest verification is VERIFIED_FIXED (HERO E2E).

## Benchmark results (all runs kept)

| Run | Set | Runs | Failed | P / R / F1 | Composite* | Notes |
|---|---|---|---|---|---|---|
| `d5c194f9` (run 1) | main | 25 | 0 | 0.862 / 1.0 / 0.926 | 97.8 | 4 FP: Lite AADHAAR-DISCOVERY duplicated D-02's deep incident |
| | held-out | 9 | 0 | 0.692 / 1.0 / 0.818 | 93.1 | + blast radius 83%: **ground-truth bug** (export past end of data) |
| `0d75b6e2` (run 2) | — | 28 of 34 | — | main 1.0 / 1.0 / 1.0 | — | **Incomplete**: harness process died after a transient Docker Desktop bind-mount I/O error (EIO). Marked FAILED; runs kept. |
| `a6dba76e` (run 3) | main | 25 | 0 | 1.0 / 1.0 / 1.0 | 100.0 | every metric 100% (verdict n=25, attempt-vs-download n=9, root cause/blast/fingerprint/remediation/approval/idempotency/verification n=10, residual n=4, lite n=15) |
| | held-out | 9 | 0 | 1.0 / 1.0 / 1.0 | 100.0 | detectors frozen at `detectors-v1` (hashes match) |

\* Composite is project-defined (Detection 30 / Investigation 25 / Remediation 25 / Verification 20), not an industry standard.

**Read these numbers with care:**
- **Same author.** One author wrote the scenarios, the ground-truth generator and the detectors, so perfect scores show internal consistency, not generalisation.
- **Fixes between runs 1 and 3:**
  1. A real MALLYA defect: Lite findings on objects already inside an open incident are now correlated instead of duplicated.
  2. A ground-truth generator bug: the export size wasn't capped at the 5,000 existing customers.
  The detectors did not change, as the held-out hash check confirms.
- **Small held-out set:** 9 runs.
- **LLM comparison:** the LLM-assisted mode needs an API key and was not run.

Mean timings (run 3, main set):

| Stage | Mean |
|---|---|
| Detect | 1.8 s |
| Verdict | 0.6 s |
| Blast radius | 1.7 s |
| Remediation | 0.5 s |
| Verification | 12.2 s |
| Evidence pack | 0.2 s |
| Detect → verified fix | 23.4 s (wall clock, presenter auto-approve) |

Exports: `benchmark/results/<id>/{benchmark.json, runs.csv, report.pdf}`.

## Decisions
- **One shared Python image** for every Python service (the dev machine's disk was nearly full). Code is bind-mounted per service; ground truth is never mounted into the worker. The benchmark harness alone gets the data generator (`synth.py`, read-only) to compute ground truth.
- **MinIO image:** `bitnamilegacy/minio:2025.7.23`, because the Docker Hub and Quay MinIO images can no longer be pulled anonymously.
- **Control plane holds no customer-data credentials.** All storage, DB and vendor access goes through the customer-side worker, which alone holds `FINGERPRINT_KEY`.
- **Probe gateway:** the backend reaches the external probes through an nginx block (`:9100`) that accepts only customer_net clients.
- **Why the first HERO-01 verification is PARTIALLY_FIXED (not staged):** the safety check holds the replica fix because Northwind depends on anonymous reads, and blast radius treats the CDN as a path, not a store. The verifier then measures both residuals for real. See `docs/architecture.md`.
- **Origin vs edge probes:** every sensitive path is requested twice, once through the cache like an attacker and once with a query string nginx never serves from cache. MALLYA's own probes never populate the cache.
- **Infra sync is incremental**, so manual drift on the replica survives a config fix.
- **Policy-gate regression test** re-applies only the bad commit's change on top of the fixed config. An earlier `cherry-pick -X theirs` silently undid the fix's reclassification; D-02's E2E caught that.
- **Prefix-scoped grants** (public links) are evaluated per object, because the bucket-level policy reads `custom`.
- **Lite/Deep correlation:** a Lite finding on an object already in an open incident is attached to that incident (found by benchmark run 1).
- **Frontend dev server** uses webpack with polling. Turbopack and inotify don't see changes on Windows bind mounts.
- **Port 3100** for the console, because port 3000 was taken by another project's container on this machine.

## Known issues / limitations
See [docs/limitations.md](docs/limitations.md). In short:
- The MinIO "download" policy allows LIST (200 with key names, no object bytes).
- No KMS, so no encryption at rest.
- Verdicts are bounded by the log sources.
- Fingerprint search covers known locations only.
- Lite scenarios are recommendation-only.
- Vendor deletion is a mock.
- The evidence key is a dev key.
- Bucket names are fixed in benchmark variants.
- `make dev` from empty volumes was exercised at M0. It was not re-run after the final changes, because `down -v` would erase the recorded benchmark history.
- Docker Desktop on Windows produced one transient bind-mount I/O error during benchmark run 2.
