# Benchmark methodology

**Rule: every number comes from a real drill against the sandbox. Failed runs are shown, never dropped.** A crashed run counts as a missed detection.

## Sets
- **Main set** (`benchmark/scenarios/generator.py`, seed 42): 2 seeded variants of each Deep scenario, plus all 15 Lite scenarios. That's 25 runs. Variants change:
  - the attacker variant (A attempts / B download);
  - whether the replica is public;
  - whether the CDN is warm;
  - the number of sensitive documents and rows per document;
  - the export size and offset;
  - the campaign size and member sample;
  - the upload size.
- **Decoys in every run:** PAN-shaped SKUs, Verhoeff-failing invoice numbers and a PAN-shaped QA table. Any finding or incident on them counts as a false positive.
- **Held-out set** (`benchmark/holdout/generator.py`, seed 7919): a separate generator with different ranges and edge cases:
  - replica private with a cold cache;
  - an export that runs past the end of the archive, so the fingerprint match count is partial;
  - the largest campaigns and uploads.

  It runs against the detectors frozen at git tag **`detectors-v1`**. The runner compares SHA-256 hashes of the detector files with `benchmark/holdout/FROZEN_DETECTORS.json` and labels the set NOT frozen if they differ.

## Ground truth
- **Source:** computed from what the harness plants (scenario parameters plus the deterministic data generator), never from agent output.
- **Storage:** written per run to `benchmark/ground_truth/<benchmark_id>/`.
- **Isolation:** not mounted into the worker. `tests/test_boundaries.py` fails if any agent package imports or opens it.
- **Disclosure:** the same author wrote the scenarios, the ground-truth generator and the detectors.

## Metrics
| Group | Metrics |
|---|---|
| Detection | TP / FP / FN per expected incident, precision, recall, F1, decoy false positives |
| Investigation | Verdict accuracy (and the attempt-vs-download subset), root-cause accuracy (commit author and message, or principal), blast-radius record-count accuracy |
| Remediation | Expected actions executed, approval compliance (approval recorded before execution), idempotency (a replayed approval token must not act twice) |
| Verification | First and final verdict accuracy, residual-exposure detection (CDN cache / replica found when present), fingerprint accuracy at known copies (e.g. archive matches) |
| Timings | Detect, verdict, blast radius, remediation, verification, evidence pack, drafts (monotonic clock per stage); detect→verified fix (UTC wall clock, includes approval) |

**Composite** (project-defined, not an industry standard) = Detection 30 + Investigation 25 + Remediation 25 + Verification 20.
- Each part is the mean of its metrics that have samples. A metric with n = 0 is excluded, not scored as 0.
- The underlying metrics are always shown next to it.

## Modes and exports
- **Modes:** `--mode all` | `--mode single --scenario ID` | `--repeats N` | `--compare-llm` (the LLM-assisted run is skipped, and reported as skipped, without an API key) | `--no-holdout`.
- **Exports:** `benchmark/results/<id>/benchmark.json`, `runs.csv`, `report.pdf`. The same files can be downloaded from the Benchmarks page.

Results: see [PROGRESS.md](../PROGRESS.md).
