# MALLYA

**Detect. Investigate. Remediate. Prove.**

MALLYA is an autonomous data privacy engineer, built as a working prototype against a fully local, synthetic bank (Meridian Bank). It doesn't stop at "you have a data exposure":

- **Detect.** It finds the exposure with deterministic detectors that run on the customer side.
- **Investigate.** It works out from real CDN and object-storage logs whether anyone actually took the data, and traces the root cause to the git commit or manual change that caused it.
- **Remediate.** It fixes the cause, only with recorded human approval.
- **Verify.** It attacks its own fix from outside the network and hunts down leftover copies by keyed fingerprint.
- **Prove.** It hands auditors an Ed25519-signed, hash-chained evidence pack.

Its AI never sees a raw customer identifier.

> A concept prototype built for Redacto. Not affiliated with or endorsed by Redacto. Sandbox only: all data is synthetic and every "attack" targets local containers. Not production-ready, and it makes no claim of regulatory compliance.

## What is real here

| Claim | How it is real |
|---|---|
| The exposure | `buckets.yaml` in a real git repo is applied to MinIO with the real `mc` client. Buckets really become anonymously readable. |
| The residual exposure | nginx `proxy_cache` really keeps serving a cached backup after the origin returns 403. The verifier gets `200 HIT` from outside. |
| "No successful download" | The verdict is computed from ingested nginx access logs and the MinIO audit webhook. If either log source has a gap, the verdict is INSUFFICIENT_EVIDENCE. |
| The fix | Approved actions change real state (bucket policy, a git commit plus sync, a policy gate, a cache purge, vendor deletions). The worker independently verifies a signed approval token for each action. |
| "Verified fixed" | Real unauthenticated requests from a container that sits only on `external_net`. Only a genuine 403 counts as blocked. The authorised consumer must still get 200. |
| Privacy boundary | The leak scan pipes every control-plane artefact into the customer-side worker, which counts raw identifiers. A positive control proves the scanner works. |
| Benchmark | Every number comes from a real drill. Failed runs are included. |

## Quick start

Requirements: Docker Desktop (about 3 GB free for images), Python 3.10+ on the host (for the env generator and the privacy suite).

```bash
python tools/gen_env.py          # writes .env with fresh random secrets (never committed)
docker compose up -d --build     # or: make dev   |   Windows: ./mallya.ps1 dev
```

- UI: http://localhost:3100 (set `FRONTEND_PORT` in `.env` to change it)
- API docs: http://localhost:8000/docs

**Demo credentials (demo-only, sandbox use).** Every account uses the password `mallya-demo-2026`.

| Account | Role |
|---|---|
| `analyst@meridian.demo` | SECURITY_ANALYST (approves remediation) |
| `engineer@meridian.demo` | IMPLEMENTATION_ENGINEER |
| `admin@meridian.demo` | ADMIN |
| `viewer@meridian.demo` | VIEWER |

### Demo Mode
1. Sign in as the analyst.
2. Click **Demo Mode** in the top bar. It resets the sandbox from its seed and runs HERO-01 end to end.
3. It pauses for your approval. The **presenter auto-approve** toggle approves pending actions as `analyst@meridian.demo` and records that in the evidence. It never approves actions held by the safety check.

The spoken script is in [docs/demo-script.md](docs/demo-script.md).

### Common commands

| Task | Make | Windows |
|---|---|---|
| Reset the sandbox to a clean state | `make reset-demo` | `./mallya.ps1 reset-demo` |
| Unit and boundary tests | `make test-unit` | `./mallya.ps1 test-unit` |
| E2E tests (all 20 scenarios) | `make test-e2e` | `./mallya.ps1 test-e2e` |
| Privacy suite (13 tests, leak scan) | `make test-privacy` | `python tools/privacy_suite.py` |
| Benchmark | `make benchmark` | `./mallya.ps1 benchmark` |
| Verify an evidence pack | `python tools/mallya_verify.py pack.zip` | same |

## Scenarios
- **Deep** (live remediation plus adversarial verification): HERO-01 public backup, D-02 public docs bucket, D-03 sensitive export link, D-04 consent-withdrawal mismatch, D-05 shadow-AI upload.
- **Lite** (detection plus verdict plus recommendation): 15 governance checks, from unencrypted storage to AI training-data leaks.

## Repository
```
frontend/   Next.js 16 console (Tailwind v4 OKLCH tokens, shadcn/ui)
backend/    FastAPI control plane: agents, LangGraph orchestration, evidence, privacy gateway, risk
worker/     customer-side worker: detectors, fingerprints, scans, approval-gated actions, scenario plants
shared/     detectors, masking, Verhoeff, canonical JSON (used by worker and control plane)
sandbox/    nginx CDN, cdn-admin, mock IAM, mock vendor, attacker, verifier, postgres init
policies/   no_public_pii_buckets policy gate
benchmark/  generators, hidden ground truth, held-out set, evaluation
tools/      mallya_verify.py, privacy_suite.py, gen_env.py
docs/       architecture, privacy, evidence, benchmark, threat model, limitations, setup, demo script
```

## Read next
[Architecture](docs/architecture.md) · [Privacy model](docs/privacy-model.md) · [Evidence integrity](docs/evidence-integrity.md) · [Benchmark methodology](docs/benchmark-methodology.md) · [Security model](docs/security-model.md) · [Threat model](docs/threat-model.md) · [Limitations](docs/limitations.md) · [API](docs/api.md) · [Setup](docs/setup.md) · [Progress and results](PROGRESS.md)
