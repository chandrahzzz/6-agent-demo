# MALLYA — Progress

## Milestones

| Milestone | Status | Evidence |
|---|---|---|
| M0 Foundation | Backend done; frontend shell pending | compose stack (13 services), Alembic migration (26 tables), Argon2 + cookie sessions, 4 roles |
| M1 Hero slice | **Done** | `tests/test_e2e_hero.py` 2/2 pass from clean reset (variant A full loop with manual approvals; variant B exfiltration) |
| M2 Evidence | Core done (chain, Ed25519, manifest, zip, standalone verifier); tamper tests pending | pack verifies 5/5 via `tools/mallya_verify.py` |
| M3 Privacy boundary | Gateway + DLP + detectors done; test suite + UI pending | |
| M4 Deep scenarios | Not started | |
| M5 Lite scenarios | Not started | |
| M6 Benchmark | Not started | |
| M7 Frontend polish | Not started | |
| M8 Demo + docs | Not started | |

## Test results (latest)
- 2026-11-05: backend unit `tests/test_verdicts_unit.py` 16 passed.
- 2026-11-05: `tests/test_e2e_hero.py` 2 passed (117 s).

## Decisions
- **One shared Python image** for every Python service (disk on the dev machine is nearly full). Code is bind-mounted per service, so each container only sees what it should (ground truth is never mounted into the worker).
- **MinIO image**: Docker Hub / Quay MinIO images are no longer pullable; using `bitnamilegacy/minio:2025.7.23` (contains both `minio` and `mc`).
- **Control plane holds no customer-data credentials.** All storage/DB/vendor access goes through the customer-side worker, which alone holds `FINGERPRINT_KEY` and returns metadata only.
- **Probe gateway**: backend reaches the external probes through an nginx server block (port 9100) that only accepts customer_net clients; probes themselves stay on external_net only.
- **Why the first HERO-01 verification is PARTIALLY_FIXED (not staged):**
  1. The replica was opened by hand for the Northwind partner, who pulls it anonymously. The Remediation Agent's safety check finds this real dependency in the access log and HOLDS the replica action, proposing a presigned-URL handoff instead. Presenter auto-approve never approves HELD actions.
  2. Blast radius treats the CDN as an exposure path, not a data store (it has no cache-inspection capability), so it marks the cache UNVERIFIED. The verifier's external GET then gets a real `200 HIT` from nginx even though the origin returns 403.
  Wave 2 is planned from the verifier's evidence (presigned handoff + purge), after which verification is VERIFIED_FIXED.
- **Origin vs edge probes**: the verifier sends each sensitive path twice — as an attacker would (through the cache) and with a query string (nginx never caches/serves those), so origin state and cache state are measured separately.
- **MALLYA's own probes never populate the cache** (`proxy_no_cache` on `X-Mallya-Probe` / `X-Mallya-Inspect`), so verification cannot create the residual it is looking for.
- **Infra sync is incremental** (applies buckets changed since the last applied commit), which is why manual drift on the replica survives a config fix.

## Known issues / limitations
- `mc anonymous set download` is MinIO's read-only policy and **includes ListBucket**, so the attacker's anonymous LIST returns 200 with key names (not object bytes). Spec 4.3 expected 403/404; we report real behaviour. Verdict logic counts it as an attempt (no object bytes served).
- Verification takes ~20 s, dominated by the verifier's network self-test (DNS lookups of unreachable names time out).
- MinIO has no KMS configured, so objects are not encrypted at rest; the risk score reflects this as a fact.
