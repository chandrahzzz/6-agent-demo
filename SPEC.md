# MALLYA — Specification

You are a principal engineer (full-stack, security, AI) and a senior product designer. Build MALLYA: a working, full-stack prototype of an autonomous data privacy engineer.

**Tagline:** Detect. Investigate. Remediate. Prove.

**One-line pitch:** MALLYA doesn't just say "you have a data exposure." It finds out whether anyone actually took the data, traces the root cause, fixes it with human approval, attacks its own fix from outside to prove it worked, hunts down leftover copies, and hands auditors a cryptographically signed evidence pack — without ever showing a raw customer identifier to its AI.

**Branding rule:** Product name is MALLYA. Footer and README say "A concept prototype built for Redacto." Never use Redacto's logo, colours or name in headers, and never imply official affiliation.

**Golden rule:** A small number of features that work for real beats a large number that are faked. Never fake a result, a metric, or a state change. If something can't be done properly, document it as a limitation.

## 1. SCOPE

### 1.1 What is in scope
- Single tenant (one fictional organisation: Meridian Bank). Keep an org_id column on tables for future multi-tenancy, but do not build tenant management.
- Five Deep scenarios with real sandbox behaviour, live remediation and adversarial verification.
- Fifteen Lite scenarios: real detection + investigation verdict + recommended fix, no live remediation.
- Six agents, evidence pack, privacy boundary, benchmark, clean frontend, demo mode.

### 1.2 Explicitly out of scope (document as future work)
Multi-tenancy, SSO, real cloud accounts, real customer data, auto-submitting any notification, production hardening.

### 1.3 Safety rules (non-negotiable)
- All data is synthetic. Never use real PAN, Aadhaar, names, phones or emails.
- All "attacks" target only the local sandbox. No internet scanning, no third-party targets.
- No remediation without explicit human approval.
- The LLM never executes commands and never receives raw identifiers.

## 2. TECH STACK (keep it lean)
- **Frontend:** Next.js (App Router), TypeScript, Tailwind CSS v4, shadcn/ui, Lucide icons, TanStack Query, React Hook Form + Zod, Recharts, React Flow (asset graph), Server-Sent Events for live agent runs.
- **Backend:** Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, PostgreSQL, Redis (pub/sub for live events only), LangGraph for agent orchestration. Use FastAPI background tasks / an asyncio job runner — no Celery.
- **LLM:** Provider abstraction (Anthropic / OpenAI / local). Default LLM_PROVIDER=local = deterministic reasoning templates. Everything must work with no API key.
- **Sandbox (Docker Compose):** MinIO, nginx caching proxy (the "CDN"), a small cdn-admin sidecar, mock IAM, mock vendor API, an attacker container, a verifier container, a local git repo of infrastructure config.
- **Testing:** Pytest, HTTPX, Vitest, Playwright.

## 3. BUILD ORDER — VERTICAL SLICE FIRST
Build one complete story end to end before widening. Never build a whole layer for all scenarios before the hero scenario works.

| Milestone | Goal | Exit check |
|---|---|---|
| M0 Foundation | Repo, Docker Compose, DB + migrations, auth with 4 roles, design tokens + app shell | make dev starts everything; login works; empty dashboard renders cleanly |
| M1 Hero slice | Scenario HERO-01 fully working: plant → detect → investigate → blast radius → approve → remediate → verify (PARTIALLY_FIXED) → fix residual → VERIFIED_FIXED. Ugly UI allowed | E2E test passes from a clean reset |
| M2 Evidence | Hash chain, Ed25519 signing, manifest, exports, standalone verify script, tamper test | Tampering a record makes verification fail |
| M3 Privacy boundary | Detectors, masking, HMAC fingerprints, LLM privacy gateway, privacy test suite + UI page | All 12 privacy tests pass |
| M4 Deep scenarios | The other 4 Deep scenarios | Each has a passing E2E test |
| M5 Lite scenarios | 15 Lite scenarios | Each detected with correct verdict on default seed |
| M6 Benchmark | Variants, decoys, held-out set, metrics, reports | Benchmark runs and reports honest numbers incl. failures |
| M7 Frontend polish | Full design pass + visual QA loop (section 12) | Screenshots reviewed at desktop + mobile widths; a11y checks pass |
| M8 Demo + docs | Demo Mode, demo script, all docs, final report | Definition of Done met |

Maintain PROGRESS.md: milestone status, test results, known issues, decisions.

## 4. THE SANDBOX (MERIDIAN BANK)

### 4.1 Networks (be exact)
- customer_net: backend, worker, Postgres, Redis, MinIO, mock IAM, mock vendor API, cdn-admin, nginx (internal side).
- external_net: nginx (public side), attacker, verifier.
- attacker and verifier are attached only to external_net. They can reach MinIO only through nginx's public endpoint. Add a test proving verifier cannot reach MinIO directly.

### 4.2 Storage layout
- Buckets: meridian-customer-backups (primary), meridian-backups-replica (replica), meridian-archive (backup storage), meridian-exports, meridian-internal-docs (shared-drive stand-in).
- Anonymous access is set with `mc anonymous set download <bucket>` and removed with `mc anonymous set none <bucket>`.
- nginx proxy_cache in front of MinIO with a long TTL. Real behaviour required: after the origin bucket is made private, nginx keeps serving the cached copy until purged. This produces a genuine residual exposure.
- cdn-admin exposes `POST /purge?key=` and `GET /cache/inspect?key=` (lists whether an object is cached), so remediation and verification can act on the cache through approved actions.

### 4.3 Real access logs
- Enable MinIO audit webhook → backend endpoint /internal/minio-audit, stored in an access_events table.
- The attacker container runs scripted requests per scenario variant:
  - Variant A (attempts, no download): anonymous LIST and GETs on wrong keys / HEAD only → 403/404, zero bytes of the real object served.
  - Variant B (confirmed download): anonymous GET of the real object → 200 with bytes transferred.
- nginx access logs are also ingested (the CDN can serve data even when MinIO logs show nothing — the Investigation Agent must check both).
- Synthetic historical logs are allowed only for the period before the scenario starts, and must be labelled synthetic_history=true.

### 4.4 Authorised consumer
Mock IAM has a reporting-service principal with legitimate read access to the primary bucket. Verification must prove this principal still gets 200 after the fix while anonymous gets 403.

### 4.5 Root-cause repo
sandbox/infra-config/ is a real git repo with buckets.yaml describing bucket policies. Seed a commit history including one commit by dev.rahul titled "share backups with vendor" that sets public: true. A sync script applies buckets.yaml to MinIO, so the config truly caused the exposure.

### 4.6 Synthetic data
- 5,000 customers: name, synthetic PAN-shaped value, synthetic Aadhaar-shaped value (see 7.2), phone, email, account ID, segment, consent records, retention records.
- Decoys (mandatory): a products.csv with SKU codes shaped like PANs (e.g. ABCDE1234F), invoice numbers that are 12 digits but fail Verhoeff, and a test table where PAN-shaped strings sit in a non-PII column. Detectors must use column context and checksums to avoid flagging these as customer identifiers.
- make seed and make reset-demo rebuild everything deterministically from a seed value.

## 5. SCENARIOS
Each scenario has: ID, description, setup function, teardown, variant parameters, expected outputs, and hidden ground truth.

### 5.1 Deep scenarios (full real behaviour)
| ID | Story | What makes it hard |
|---|---|---|
| HERO-01 PUBLIC-BACKUP | buckets.yaml commit made the primary backup bucket public; replica bucket also public; nginx has cached the backup file | First verification must return PARTIALLY_FIXED because the CDN cache and the replica still serve data. Only after purge + replica fix → VERIFIED_FIXED |
| D-02 PUBLIC-S3-BUCKET | Internal docs bucket public with a few files containing identifiers among many harmless files | Blast radius must identify only the sensitive objects |
| D-03 SENSITIVE-EXPORT | A CSV export with identifiers left in meridian-exports with a public link | Fingerprint search finds the same records also in the archive |
| D-04 CONSENT-WITHDRAWAL-MISMATCH | Customers who withdrew marketing consent are still present in a marketing-campaign table synced to the mock vendor API | Remediation = stop sync + remove those rows at the vendor mock; verification re-queries the vendor |
| D-05 SHADOW-AI-UPLOAD | A file with identifiers was sent to an unapproved "AI tool" endpoint (mock vendor API logs the upload) | Investigation proves which records left via fingerprints in the vendor's received-payload store |

### 5.2 Lite scenarios (detect + verdict + recommendation only)
UNENCRYPTED-STORAGE, EXCESSIVE-DB-PERMISSIONS, EXPOSED-POSTGRES, DATABASE-BACKUP-DRIFT, PAN-DISCOVERY, AADHAAR-DISCOVERY, HEALTH-DATA-EXPOSURE, UNAPPROVED-API, VENDOR-OVERPERMISSION, VENDOR-CREDENTIAL-EXPIRY, MISSING-ROPA-ENTRY, UNREVIEWED-DATA-RETENTION, UNAPPROVED-AI-VENDOR, AI-TRAINING-DATA-LEAK, SHARED-DRIVE-EXPOSURE.

### 5.3 Ground truth must be truly hidden
- Store in benchmark/ground_truth/. Only benchmark/evaluation/ may read it.
- Not mounted into the worker container.
- Add an import-boundary test that fails if anything under backend/app/agents, detection, investigation, remediation or verification imports ground truth.

## 6. THE SIX AGENTS
Every agent: typed input/output schemas, timestamps, status, confidence where meaningful, evidence references, retries, errors, audit events, and a short visible decision summary (never raw chain-of-thought). Agents orchestrated with LangGraph; each step emits SSE events.

### 6.1 Exposure Hunter
Discovers assets, inspects bucket/DB permissions, runs deterministic detectors in the worker, flags unapproved integrations and AI tools, emits findings. The LLM is never the detector.

### 6.2 Investigation Agent
- Correlates MinIO audit + nginx logs + IAM events + git history.
- Access verdict: EXPOSED_NOT_ACCESSED, ACCESS_ATTEMPTED_NOT_SUCCESSFUL, ACCESSED_INTERNAL_ONLY, LIKELY_EXFILTRATED (bytes of the real object served to an external origin), FALSE_POSITIVE, INSUFFICIENT_EVIDENCE.
- Never claims exfiltration just because something was public.
- Root cause: finds the git commit in infra-config that introduced the bad policy, its author and time, and correlates it with the policy-change event.
- Produces a timeline.

### 6.3 Blast Radius Agent
Builds the asset graph (React Flow in UI), searches every known location with HMAC fingerprints, lists affected and related assets, data categories, record counts, exposure paths, and UNVERIFIED locations it couldn't inspect. Maps affected records to consent state (e.g. "5,000 records affected; 312 had withdrawn marketing consent").

### 6.4 Remediation Agent
Proposes actions, each with: Action ID, target, problem, change, risk, side effects, expected outcome, approval status, execution status, rollback plan, verification requirement.
- Fix the cause, not just the symptom: for config-caused issues, output a real patch to buckets.yaml (unified diff) in addition to the live fix, and add a policy check (policies/no_public_pii_buckets — OPA/Conftest or an equivalent Python rule) that rejects the bad config if reintroduced. Show a test where re-applying the bad commit is blocked.
- Safety check before fixing: read the last N access events; if a legitimate principal depends on the access being removed, flag it and propose a safer alternative (e.g. scoped credentials / presigned URLs).
- Executes only approved actions; idempotent; real sandbox state changes.

### 6.5 Adversarial Verification Agent (the star — do not build a permission checker)
Independent from the Remediation Agent. It ignores remediation's success message and attacks the fix.

**A. External attack test (from verifier on external_net):**
- Unauthenticated GET of the exact exposed paths, through nginx, as an attacker would.
- Uses a seeded canary object for download tests.
- Records request, response code, bytes, headers, timestamp.
- Distinguishes genuine denial (403) from DNS failure, connection refused, timeout and 5xx — only a genuine denial counts as blocked.
- Confirms reporting-service still gets 200.

**B. Copy and replica hunt:**
- Checks replica bucket, archive, exports, CDN cache (via cdn-admin inspect and via an external fetch), vendor mock stores.
- Uses HMAC fingerprints to find the same records anywhere they exist.
- A fingerprint match = data present. Accessibility is checked separately. Both are reported.
- Any location that couldn't be checked = UNVERIFIED.

**C. Verdict:** VERIFIED_FIXED only if: external access blocked on all known paths, original protected, all known copies checked, all fingerprint matches accounted for, authorised access preserved, evidence recorded. Otherwise PARTIALLY_FIXED, STILL_EXPOSED, UNVERIFIED or VERIFICATION_FAILED.

**D. Records:** run ID, targets, test origin, requests/responses, access decisions, fingerprint results per location, replica results, unavailable checks, timestamp, verifier version, verdict.

### 6.6 Compliance Evidence Agent
Builds the timeline, collects approvals, remediation, verification, root cause and blast radius into the evidence pack. Drafts notifications with a configurable regulatory context (DPDP Act 2023 + Rules, CERT-In directions, RBI where relevant). Every draft is stamped "DRAFT — REQUIRES LEGAL AND COMPLIANCE REVIEW". Never decides that a law applies, never invents deadlines, never auto-submits. Deadline timers in the UI are only started when a human sets the applicable obligation and its start time.

## 7. PRIVACY BOUNDARY — ZERO RAW IDENTIFIERS TO THE LLM

### 7.1 Architecture
Worker (customer side) reads data → detects locally → validates → masks → fingerprints → sends metadata only to the control plane. Raw identifiers never leave the worker, never hit logs, traces, errors, DB tables or exports.

### 7.2 Detectors
- PAN: regex `^[A-Z]{5}[0-9]{4}[A-Z]$` + 4th-character holder type (P, C, H, F, A, T, B, L, J, G) + column context. Outcomes: FORMAT_MATCH, STRUCTURAL_MATCH, CONFIRMED_SYNTHETIC_TEST_VALUE. Pattern match ≠ real PAN.
- Aadhaar: 12 digits, formatting/exclusion rules (first digit not 0 or 1), Verhoeff checksum. Passing checksum ≠ issued Aadhaar. Use only synthetic fixtures.
- Phone / email: standard deterministic detectors.
- Column-context scoring to handle the decoys in 4.6.

### 7.3 Fingerprints
HMAC-SHA-256, versioned key (FINGERPRINT_KEY, separate from all other secrets, never stored in the DB), normalise before hashing, store as `HMAC-SHA256:v1:<hex>`. No plain hashes.

### 7.4 LLM privacy gateway
Before every model call: strip identifiers, keep only masked samples (e.g. ABCDE*****), remove names/full phones/emails/raw rows, validate schema, run a deterministic outbound DLP check; if any unmasked PAN/Aadhaar candidate is found, block the call and log a PrivacyPolicyViolation without the raw value. Record exactly which metadata fields were shared.

### 7.5 Privacy tests (all must pass)
PAN detection; PAN structure; Verhoeff; decoys not flagged; masking; fingerprint match across datasets; different IDs → different fingerprints; no raw PAN in LLM payload; no raw Aadhaar in LLM payload; no raw IDs in logs; no raw IDs in telemetry; no raw IDs in evidence exports; gateway blocks unsafe payloads.

UI page Privacy Boundary shows counts only: detected locally, masked, fingerprinted, LLM calls made, payloads blocked, violations, tests passed — and a headline: "0 raw identifiers sent to the AI." (computed, not hardcoded).

## 8. EVIDENCE PACK — TAMPER-EVIDENT AND SIGNED
- Hash-chained events: canonical JSON (sorted keys, UTF-8, no whitespace) → event_hash = SHA256(canonical(metadata + payload_hash + previous_event_hash)). Insertion, deletion, reordering or edits must be detectable.
- Ed25519 signature over the final manifest. Signing key loaded from EVIDENCE_SIGNING_KEY_PATH, never in DB, frontend or git. Dev key labelled DEV-NON-PRODUCTION. Key ID + algorithm recorded; versioned key IDs for rotation. Public key exported with the pack.
- Pack contents: incident summary, detection time, access verdict, root cause (commit), affected assets, data categories, blast radius, asset graph, proposed and approved actions, execution records, external test results, replica/fingerprint results, unverified locations, limitations, compliance drafts, agent history, final status.
- Exports: signed JSON manifest (authoritative), PDF report (human-readable), CSV timeline, SHA-256 checksums file.
- Standalone verifier: `tools/mallya_verify.py pack.zip` checks checksums, hash chain, signature, missing/modified records, and prints PASS/FAIL per check. Include a test that edits one event and proves FAIL.
- Wording: "cryptographically tamper-evident and audit-oriented." Never "legally admissible" or "regulator-compliant".

## 9. RISK SCORE
Deterministic, explainable 0–100 from: exposure type, data sensitivity, public accessibility, record count, asset count, access verdict, encryption, replication, third-party involvement. Bands: 0–24 Low, 25–49 Moderate, 50–74 High, 75–100 Critical. UI shows each factor's contribution. Never call it a breach probability.

## 10. INCIDENTS
Statuses: DETECTED → INVESTIGATING → AWAITING_APPROVAL → REMEDIATING → VERIFYING → VERIFIED_FIXED / PARTIALLY_FIXED / STILL_EXPOSED / UNVERIFIED → CLOSED. Incident tabs: Overview, Findings, Investigation & Root Cause, Asset Graph, Remediation, Verification, Evidence, Timeline, Compliance Drafts. An incident cannot be closed as fixed unless the latest verification is VERIFIED_FIXED (enforced in the backend, not just the UI).

## 11. BENCHMARK — HONEST BY DESIGN
- Variants: each scenario runs with seeded random variations (bucket names, record counts, replica layouts, access variant A/B).
- Decoys: included in every run; false positives counted.
- Held-out set: benchmark/holdout/ scenarios produced by a separate generator with a different seed, run against detectors frozen at git tag detectors-v1. Disclose in the report that the same author wrote scenarios and detectors.
- Metrics: detection TP/FP/FN, precision, recall, F1; verdict accuracy (incl. attempted vs successful access); root-cause accuracy; blast-radius accuracy; remediation correctness, approval compliance, idempotency; verification verdict accuracy, residual-exposure detection, fingerprint accuracy; timings (detect, verdict, blast radius, remediation, verified fix, evidence pack, draft) via monotonic clocks, UTC for audit.
- Rules: every number comes from real runs; failed runs are shown, never dropped; show sample size and config; optional composite score (Detection 30 / Investigation 25 / Remediation 25 / Verification 20) labelled "project-defined, not an industry standard", with underlying metrics always visible.
- Modes: single scenario, all scenarios, N repeats, deterministic vs LLM-assisted comparison.
- Exports: CSV, JSON, PDF.

## 12. FRONTEND — CLEAN, PREMIUM, NOT "AI-GENERATED"

### 12.1 Design direction
"Calm control room." A dark, quiet, precise security operations interface — the feeling of a serious tool used by experts, not a flashy demo.
- Typography: IBM Plex Sans for UI, IBM Plex Mono for IDs, hashes, fingerprints, HTTP responses and timestamps. Clear scale (12 / 13 / 14 / 16 / 20 / 24 / 32). Tabular numbers for all metrics.
- Colour: OKLCH design tokens in a Tailwind v4 @theme block driven by one --brand-hue. Brand-tinted neutrals (no pure black or white). One accent colour. Semantic status colours used only for meaning: Critical / Still exposed → red; High / Partially fixed → amber; Verified fixed → green; Unverified → neutral grey with dashed border; Info → blue.
- Spacing: 4px grid. Generous padding, dense-but-readable tables.
- Surfaces: subtle 1px borders, small radius (6–8px), very soft or no shadows.
- Motion: minimal and purposeful — status changes, live agent steps, verdict reveal. Respect prefers-reduced-motion.
- Banned: purple gradients, glassmorphism, neon glows, emoji in UI, generic hero sections, stock "AI sparkle" icons, chatbot layouts, fake numbers, lorem ipsum.
- Also ship a light theme from the same tokens.

### 12.2 Layout
- Left sidebar (collapsible): Dashboard, Incidents, Breach Drill Lab, Assets, Benchmarks, Evidence Vault, Privacy Boundary, Agents, Settings.
- Top bar: environment badge (SANDBOX · Meridian Bank), Demo Mode button, user + role.
- Every MOCK/SANDBOX connector visibly labelled.

### 12.3 Key screens (design these with the most care)
- **Dashboard:** real metrics only (active incidents, critical exposures, assets, verified fixes, open verification checks, mean time to detect, mean time to verified fix, benchmark score, privacy status). Proper empty states when no runs exist.
- **Live Agent Run:** vertical timeline of the six agents with live SSE updates; each step shows status, duration, decision summary, evidence links.
- **Verification screen (signature screen):** split view — left: external attack attempts as terminal-style rows (`GET /meridian-customer-backups/backup.csv → 200 OK · PUBLICLY ACCESSIBLE` then `→ 403 Forbidden · BLOCKED`), in IBM Plex Mono; right: copy hunt table — location, fingerprint match, accessible?, status chip; bottom: big verdict banner (PARTIALLY_FIXED amber with "Residual exposure: CDN cache, replica bucket" → later VERIFIED_FIXED green).
- **Asset Graph:** React Flow; nodes coloured by status; exposure paths highlighted.
- **Root Cause panel:** the offending commit, author, time, diff, and the proposed patch diff side by side.
- **Evidence Vault:** chain status, signature status, key ID, file integrity, export buttons, copyable verify command.
- **Privacy Boundary:** counters, test results, "0 raw identifiers sent to the AI".
- **Benchmark:** per-scenario table, metric cards, charts, failure list, held-out results separate.

### 12.4 Quality rules
- Every data view has loading (skeleton), empty, and error states.
- Fully keyboard navigable, visible focus rings, labelled controls, WCAG AA contrast.
- Responsive down to 390px (tables become stacked cards; graph becomes a list).
- Use shadcn/ui components consistently — no duplicate custom versions of the same component.
- Use Context7 for current Next.js / Tailwind v4 / shadcn APIs rather than memory.

### 12.5 Visual QA loop (mandatory in M7)
- Run the app and use Playwright to screenshot every key screen at 1440px and 390px, in dark and light themes, with real seeded data.
- Review each screenshot critically against 12.1–12.4: alignment, spacing rhythm, hierarchy, contrast, overflow, truncation, consistency.
- Run /baseline-ui, then /fixing-accessibility, then /fixing-motion-performance.
- Fix and re-screenshot until clean. Save final screenshots in docs/screenshots/.

## 13. SECURITY OF MALLYA ITSELF
Roles: ADMIN, SECURITY_ANALYST (approves remediation), IMPLEMENTATION_ENGINEER, VIEWER. Argon2 password hashing, secure httpOnly session cookies, restricted CORS, input validation, basic rate limiting on auth and action endpoints, secrets only from env/files, no plaintext secrets in repo, no arbitrary shell or SQL from any agent, no LLM-initiated actions, full audit log. Demo credentials clearly labelled demo-only.

## 14. API (REST, /api/v1)
health, dashboard, incidents (+ investigation, remediation, verification, evidence, timeline, drafts), assets (+ relationships), scenarios, drills (create, start, events via SSE, reset), approvals (approve/reject), verification (run), evidence (get, verify, export), benchmarks (run, get), agents (executions), privacy (tests, violations), audit-logs. Pydantic schemas, correct status codes, pagination, consistent error format. Plus internal /internal/minio-audit (network-restricted).

## 15. DEMO MODE
- A Demo Mode button: resets the sandbox and runs HERO-01 end to end in about 3 minutes.
- Pauses at the approval step for a human click. Optional "presenter auto-approve" toggle, visibly labelled, that approves as analyst@meridian.demo and records that in the evidence.
- Story beats on screen: exposure detected → "3 anonymous attempts, no successful download" (variant A) → root-cause commit shown → 5,000 records / consent breakdown → approval → fix applied → verification attacks the fix → PARTIALLY_FIXED (CDN cache + replica still serving) → purge + replica fix → VERIFIED_FIXED → signed evidence pack → real measured timings.
- Write docs/demo-script.md: a 3-minute spoken script matching these beats, for recording the Devpost video.

## 16. DEFINITION OF DONE
- make dev brings up the full stack from scratch; make reset-demo restores a clean state.
- HERO-01 and all 4 other Deep scenarios pass E2E tests with real sandbox state changes.
- All 15 Lite scenarios detect and produce correct verdicts on the default seed.
- First HERO-01 verification genuinely returns PARTIALLY_FIXED due to the real nginx cache; final returns VERIFIED_FIXED.
- A test proves an exposed replica or cached copy prevents VERIFIED_FIXED.
- A test proves verifier cannot reach MinIO except via nginx.
- A test proves re-applying the bad commit is blocked by the policy check.
- Privacy test suite passes; gateway blocks unsafe payloads; "0 raw identifiers sent to the AI" is computed.
- Evidence chain + Ed25519 signature verify; tampering is detected by the standalone verifier.
- Ground-truth import-boundary test passes.
- Benchmark runs with variants, decoys and held-out set and reports real numbers including failures.
- Frontend passes the visual QA loop; screenshots saved.
- Docs written; PROGRESS.md final.
- Never claim production readiness or guaranteed regulatory compliance.

## 17. REPO LAYOUT (refine if needed)
```
mallya/
├── frontend/            # Next.js app (app/, components/, lib/, styles/tokens.css, tests/)
├── backend/app/         # api, core, models, schemas, agents, orchestration, detection,
│                        # investigation, remediation, verification, privacy, evidence,
│                        # compliance, connectors, audit, risk
├── backend/migrations/
├── backend/tests/
├── worker/              # customer-side detection + fingerprinting
├── sandbox/             # nginx, cdn-admin, mock-iam, mock-vendor, attacker, verifier, infra-config (git)
├── policies/            # no_public_pii_buckets policy
├── benchmark/           # scenarios, variants, holdout, ground_truth (hidden), evaluation
├── tools/mallya_verify.py
├── docs/                # architecture, api, security-model, privacy-model, evidence-integrity,
│                        # benchmark-methodology, threat-model, limitations, setup, demo-script, screenshots/
├── docker-compose.yml
├── Makefile             # install, dev, migrate, seed, test, benchmark, reset-demo, lint, build
├── .env.example
├── PROGRESS.md
└── README.md
```

.env.example: DATABASE_URL, REDIS_URL, LLM_PROVIDER=local, LLM_MODEL, ANTHROPIC_API_KEY, OPENAI_API_KEY, MINIO_ENDPOINT, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, SECRET_KEY, FINGERPRINT_KEY, EVIDENCE_SIGNING_KEY_PATH, APP_ENV=development, DEMO_MODE=true. Fingerprint key and signing key are separate. No real secrets committed.

## 18. DOCUMENTATION MUST EXPLAIN THESE DISTINCTIONS
Detection vs investigation · exposure vs confirmed exfiltration · access attempt vs successful download · a remediation action vs a verified fix · a fingerprint match vs an accessible copy · tamper-evident evidence vs legal admissibility · deterministic detection vs LLM reasoning.

## 19. FINAL REPORT (when done)
Repo structure · setup and start commands · demo credentials · how to run Demo Mode · how to run all scenarios and the benchmark · how to run privacy tests · how to verify an evidence pack · actual test results · actual benchmark results (incl. failures and held-out) · screenshots · known limitations · production-hardening roadmap.
