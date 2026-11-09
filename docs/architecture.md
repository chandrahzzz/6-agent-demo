# Architecture

## Components and networks

```
                     external_net (172.29.0.0/24)
   attacker ──┐      verifier ──┐
              └──────────────────┴──► nginx :8080  ("CDN", proxy_cache 30d)
                                       │      ▲ probe gateway :9100 (customer_net clients only)
   ─────────────────────────────────── │ ─────┼────────────────────── customer_net (172.28.0.0/24)
                                       ▼      │
   MinIO ◄──── mc / SDK ──── worker ───┼──────┘          mock IAM   mock vendor   cdn-admin
     │  audit webhook                  │  (only holder of FINGERPRINT_KEY,
     ▼                                 │   customer DB credentials, MinIO principals)
   backend (control plane) ◄───────────┘ metadata only
     │  ui_net
   frontend (Next.js)
```

- **attacker and verifier live only on `external_net`.** They can reach nothing but the CDN edge. `tests/test_boundaries.py` proves the verifier can't reach MinIO, Postgres or the worker directly.
- **The control plane holds no customer-data credentials.** Storage, database and vendor access all go through the customer-side worker, which returns counts, masked samples and keyed fingerprints.
- **The backend talks to the external probes through an nginx server block (`:9100`).** It accepts only customer_net clients, so the probes never need an inbound path to the customer network.

## The six agents (LangGraph)

```
drill/plant ─► Exposure Hunter ─► [triage graph] Investigation ─► Blast Radius ─► Risk ─► Remediation plan ─► Compliance drafts
                                                                                                    │
                                                         human approval (or labelled presenter auto-approve)
                                                                                                    ▼
                         [fix graph] execute approved ─► Adversarial Verification ─┬─ VERIFIED_FIXED ─► drafts + signed pack
                                                                                    └─ otherwise ─► replan (wave N+1) ─► approval …
```

Lite scenarios use a third graph: investigation verdict, then risk, then recommendation. There is no live remediation.

| Agent | Does | Never does |
|---|---|---|
| Exposure Hunter | Inventory; per-object anonymous grants including prefix grants; detectors in the worker; consent-sync, egress and 15 lite checks | Use an LLM to detect |
| Investigation | Correlates nginx and MinIO audit logs (deduplicated), IAM policy events, git history and vendor call logs; checks log coverage; returns a verdict, root cause and timeline | Treat "was public" as exfiltration |
| Blast Radius | Keyed-fingerprint search of every known location; consent mapping; asset graph; marks UNVERIFIED anything it can't inspect (the CDN cache) | Claim a fingerprint match means the data is accessible |
| Remediation | Fixes the cause (live fix, config patch, policy gate plus a regression test); runs a safety check on real access events; re-plans from verifier evidence | Execute without an approval token the worker accepts |
| Adversarial Verification | Real external requests (edge and origin-bypass), canaries, the authorised consumer, a fingerprint copy hunt, a forced re-sync for vendor cases | Trust remediation's success message |
| Compliance Evidence | Drafts stamped "DRAFT — REQUIRES LEGAL AND COMPLIANCE REVIEW"; builds the hash-chained, Ed25519-signed pack | Decide a law applies, set deadlines, submit anything |

## Why the first HERO-01 verification is PARTIALLY_FIXED, without staging

1. **The replica.** It was opened by hand for the Northwind partner, which reads it anonymously (the sandbox simulates one such pull). The safety check reads that dependency from the access log and HOLDS the replica action, proposing a presigned-URL handoff instead.
2. **The CDN cache.** Blast radius models the CDN as a path, not a store, and marks it UNVERIFIED. The verifier's external GET then gets a real `200 HIT` while the origin request gets 403.

Wave 2 is planned from that evidence (handoff plus purge), and the next verification is VERIFIED_FIXED. If an analyst overrides the hold in wave 1, the cached copy still makes the first verification PARTIALLY_FIXED. Both residuals are facts the system measures.

## Distinctions the system keeps

- **Detection vs investigation.** Detection says something sensitive is reachable. Investigation asks whether anyone reached it, according to the logs.
- **Exposure vs confirmed exfiltration.** Being public is an exposure. LIKELY_EXFILTRATED requires bytes of the real object served to an external origin, or proven at an unapproved third party.
- **Access attempt vs successful download.** A LIST, a HEAD, wrong keys and 403/404 responses are attempts. Only a 200/206 with object bytes counts as a download.
- **A remediation action vs a verified fix.** An action changes state. A fix is verified only when an outside attack fails everywhere and every copy is accounted for.
- **A fingerprint match vs an accessible copy.** A match means the data is present. Accessibility is tested separately, by a real request.
- **Tamper-evident evidence vs legal admissibility.** The pack detects any edit. It makes no admissibility claim.
- **Deterministic detection vs LLM reasoning.** Detectors, verdicts, scores and actions are deterministic code. The LLM, behind the privacy gateway, only phrases summaries and drafts.
