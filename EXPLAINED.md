# MALLYA, explained from the start

This file explains MALLYA in plain English: what it is, why it exists, what you see on screen, what happens behind the screen, and how every part fits together. Read it top to bottom the first time. Later you can jump to any section.

> **Ground rules of the project, up front.**
> - Everything runs on one laptop, inside Docker. Nothing touches the internet.
> - The "bank" is fictional and every customer record is synthetic (generated). There are no real PAN numbers, Aadhaar numbers, names, phones or emails anywhere.
> - The "attacks" only hit containers on the same laptop.
> - It is a **concept prototype**, not a production product. It makes no claim of legal or regulatory compliance.
> - Footer line: *"A concept prototype built for Redacto."* It is not affiliated with or endorsed by Redacto.

---

## Contents

1. [The one-paragraph version](#1-the-one-paragraph-version)
2. [The problem it solves](#2-the-problem-it-solves)
3. [The pretend world: Meridian Bank](#3-the-pretend-world-meridian-bank)
4. [The five words: Detect, Investigate, Remediate, Verify, Prove](#4-the-five-words)
5. [The hero story (HERO-01), step by step](#5-the-hero-story-hero-01-step-by-step)
6. [What runs on the laptop: the 12 containers](#6-what-runs-on-the-laptop-the-12-containers)
7. [The three networks, and why they matter](#7-the-three-networks-and-why-they-matter)
8. [The six agents](#8-the-six-agents)
9. [How the agents are wired together (LangGraph)](#9-how-the-agents-are-wired-together-langgraph)
10. [Detection: finding sensitive data without being fooled](#10-detection-finding-sensitive-data-without-being-fooled)
11. [Fingerprints: tracking records without seeing them](#11-fingerprints-tracking-records-without-seeing-them)
12. [Investigation: was the data actually taken?](#12-investigation-was-the-data-actually-taken)
13. [Blast radius: how far did it spread?](#13-blast-radius-how-far-did-it-spread)
14. [The risk score](#14-the-risk-score)
15. [Remediation and human approval](#15-remediation-and-human-approval)
16. [Adversarial verification: attacking its own fix](#16-adversarial-verification-attacking-its-own-fix)
17. [Evidence packs: proof nobody can quietly edit](#17-evidence-packs-proof-nobody-can-quietly-edit)
18. [The privacy boundary: the AI never sees raw identifiers](#18-the-privacy-boundary-the-ai-never-sees-raw-identifiers)
19. [Compliance drafts](#19-compliance-drafts)
20. [All 20 scenarios](#20-all-20-scenarios)
21. [Every screen in the console](#21-every-screen-in-the-console)
22. [Users, roles and login](#22-users-roles-and-login)
23. [The backend, file by file](#23-the-backend-file-by-file)
24. [The worker, file by file](#24-the-worker-file-by-file)
25. [The sandbox services, one by one](#25-the-sandbox-services-one-by-one)
26. [The frontend, file by file](#26-the-frontend-file-by-file)
27. [The database](#27-the-database)
28. [Live updates (how the screen moves by itself)](#28-live-updates)
29. [Tests: how we know it works](#29-tests-how-we-know-it-works)
30. [The benchmark: how good is it, honestly](#30-the-benchmark-how-good-is-it-honestly)
31. [How to run it yourself](#31-how-to-run-it-yourself)
32. [Secrets and keys](#32-secrets-and-keys)
33. [What it does NOT do (limitations)](#33-what-it-does-not-do-limitations)
34. [What a real product would need](#34-what-a-real-product-would-need)
35. [Glossary](#35-glossary)
36. [Questions your friend might ask](#36-questions-your-friend-might-ask)

---

## 1. The one-paragraph version

MALLYA is a pretend "privacy engineer" robot for a pretend bank. When the bank accidentally leaves customer data exposed (for example, a backup file anyone on the internet can download), MALLYA:
1. **finds** it;
2. reads the real server logs to work out **whether anyone actually downloaded it**;
3. finds **who or what caused** it (down to the exact git commit);
4. proposes **fixes**, but only runs them after a human clicks **Approve**;
5. **attacks its own fix** from outside the network to check it really worked;
6. produces a **signed evidence pack** that shows if anyone edits it afterwards.

Throughout all of this, the AI language model it uses for writing summaries **never sees a real customer identifier**.

---

## 2. The problem it solves

Most data-security tools stop at one sentence: *"Warning: this bucket is public."* That leaves the hard questions to a tired human at 2 a.m.:

| Question | Why it's hard |
|---|---|
| Did anyone actually take the data? | "Public" is not the same as "stolen". You have to read access logs from several systems and line them up. |
| What caused it? | Could be a config change, a manual click, a vendor integration. You have to dig through history. |
| How many people are affected? | The same records may be copied in backups, replicas, exports, caches, vendor systems. |
| Is it really fixed? | Changing a permission doesn't mean the data is gone. A CDN can keep serving a cached copy for days. |
| Can we prove what we did? | Auditors want a record that can't be quietly edited later. |

MALLYA answers all five with real measurements, not with guesses.

A key idea: **a fix isn't a fix until an outside attack fails.** MALLYA's best moment in the demo is when it reports its own first fix as **PARTIALLY_FIXED**, because the CDN is still handing out a cached copy of the backup. A simple permission checker would have said "fixed".

---

## 3. The pretend world: Meridian Bank

Inside Docker there's a small, fake, but *working* bank IT setup:

- **A customer database** (Postgres, database name `meridian`): 5,000 synthetic customers with names, emails, phones, PAN-format and Aadhaar-format identifiers, consent flags (for example "withdrew marketing consent"), health claims, retention dates, and a data catalogue.
- **Object storage** (MinIO, which works like Amazon S3): buckets such as the customer backup, its replica, an archive, internal docs, exports and a shared drive.
- **A CDN in front of storage** (nginx): it caches files for 30 days, exactly like a real content delivery network.
- **An infrastructure-as-code repo** (`infra-config`, a real git repository): a `buckets.yaml` file decides which buckets are public. A sync job applies it to MinIO with the real `mc` command-line client.
- **Identity and access** (mock IAM): staff and service accounts (for example `dev-rahul`, `infra-sync`, `finance-analyst`, `reporting-service`), policy-change events and network ranges.
- **Vendors** (mock vendor): "Northwind", a marketing partner that receives customer contacts, and "QuickSummarize", an unapproved AI tool that someone uploaded a file to.
- **An attacker** container that pokes at the CDN like a stranger on the internet would.
- **A verifier** container that sits *outside* the bank's network and is used by MALLYA to test fixes.

Because these are real programs, every "exposure" is real: a bucket really becomes downloadable, the CDN really caches the file, and the logs really record each request.

---

## 4. The five words

The tagline is **"Detect. Investigate. Remediate. Prove."** with a verification step in between:

| Word | What MALLYA does | What it refuses to do |
|---|---|---|
| **Detect** | Scans every bucket, table and vendor feed with deterministic detectors (plain code, not AI). | Use an AI to decide what's sensitive. |
| **Investigate** | Lines up CDN logs, storage audit logs, IAM events, git history and vendor logs. Decides if data was downloaded. | Treat "was public" as "was stolen". |
| **Remediate** | Plans fixes for the *cause* (not just the symptom), each with risk, rollback and a verification requirement. | Run anything without a recorded human approval. |
| **Verify** | Attacks the fix from outside, checks every copy, and confirms legitimate users still work. | Trust the fix's own "success" message. |
| **Prove** | Builds a hash-chained, Ed25519-signed evidence pack and a standalone verify script. | Claim it is "legally admissible" or "regulator-compliant". |

---

## 5. The hero story (HERO-01), step by step

This is what you see when you click **Demo Mode**. It's the main story, so it's worth understanding in detail.

### 5.1 The setup (the "plant")
When the drill starts, the sandbox is reset and a real incident is created:

1. A developer, `dev.rahul`, commits a change to `buckets.yaml` titled **"share backups with vendor"**. It makes the primary customer-backup bucket public.
2. The `infra-sync` pipeline applies that commit to MinIO. The bucket is now really downloadable without a password.
3. Separately, someone had opened the **replica** bucket by hand for the **Northwind** partner, whose connector downloads it anonymously (the sandbox simulates one such pull).
4. A request through the CDN has already pulled the backup file into the **nginx cache**.
5. The attacker container then makes **three anonymous attempts**: a LIST (asking for file names), a GET with a wrong file name, and a HEAD (asking for file info without the body). None of them downloads the actual backup bytes. (Variant B of the scenario does download it, see below.)

### 5.2 Exposure Hunter runs
It goes through every bucket through the customer-side worker, and finds:
- the backup bucket and the replica are anonymously readable;
- the files contain PAN-format and Aadhaar-format identifiers;
- **decoys** (product SKUs that look like PANs, 12-digit invoice numbers that fail the Aadhaar checksum, and a QA fixture table) are correctly **rejected**.

### 5.3 Investigation runs
It reads the nginx access log and the MinIO audit log and lines them up:
- **Verdict:** `ACCESS_ATTEMPTED_NOT_SUCCESSFUL`, meaning three anonymous attempts, zero bytes of the real file served.
- **Log coverage:** both log sources were present for the whole exposure window; 5 of 5 requests that reached storage matched between the two logs. If a log had a gap, the verdict would be `INSUFFICIENT_EVIDENCE` instead.
- **Root cause:** commit "share backups with vendor" by dev.rahul, applied by infra-sync. The screen shows the offending diff and MALLYA's proposed patch.

### 5.4 Blast radius runs
- Uses keyed fingerprints (see section 11) to count affected people: **5,000 records**, of which **306 had withdrawn marketing consent**.
- Finds the same records in the **archive** too.
- Marks the **CDN cache** as **UNVERIFIED**, because this agent can't look inside the cache. It's honest about what it didn't check.

### 5.5 Risk score
A 0–100 number with a line-by-line explanation (section 14). HERO-01 lands in the Critical/High range because it's public storage with PAN and Aadhaar data across several copies.

### 5.6 Remediation plan (wave 1)
Proposed actions, each with risk, rollback and "how we'll verify it":
- make the backup bucket private right now (`bucket.set_private`);
- patch `buckets.yaml` back to private, and reclassify the bucket, through a real git commit and sync (`infra.patch_bucket_private`);
- turn on a **policy gate** so a commit like this is blocked in future (`infra.enable_policy_gate`). The gate is tested by replaying the bad commit and checking it gets blocked;
- make the replica private, but this one is **HELD**. The **safety check** read the access log, saw that Northwind reads the replica anonymously, and warns that closing it would break a legitimate partner. It proposes a **presigned link** (a private, expiring download URL) instead.

### 5.7 Human approval
The analyst ticks the pending actions and clicks **Approve**, then **Execute approved**. Each approval becomes a signed token. The worker checks the signature itself before doing anything, and each approval can run only once.

There's a **presenter auto-approve** toggle for demos. It approves as `analyst@meridian.demo`, records that it was an auto-approval in the evidence, and **never** approves a held action.

### 5.8 Verification run 1: PARTIALLY_FIXED
The verifier container (outside the bank network) attacks:
- **Origin request** (bypassing the cache): **403**, so the storage is now closed.
- **Edge request** (through the CDN like a normal visitor): **200, cache HIT**. The CDN is still serving the old backup from its cache.
- The replica is still open (because it was held).

Verdict: **PARTIALLY_FIXED**. Nothing here is staged. These are real HTTP responses from real nginx and MinIO.

### 5.9 Wave 2
MALLYA re-plans from what the verifier found:
- give Northwind a presigned link (`partner.presigned_handoff`);
- close the replica (it was held, so the human must give an **override with a reason**);
- **purge the CDN cache** (`cdn.purge`).

### 5.10 Verification run 2: VERIFIED_FIXED
- Every path, edge and origin, now returns a genuine **403**.
- Every fingerprinted copy is accounted for.
- The legitimate `reporting-service` account still gets **200**, so the fix didn't break the business.

Verdict: **VERIFIED_FIXED**. Only now can the incident be closed. The system refuses to close an incident whose latest verification isn't VERIFIED_FIXED.

### 5.11 Evidence pack
Every step above was written into a hash chain. MALLYA builds a signed ZIP. Clicking **Verify now** runs five checks, all PASS. Changing a single byte in it makes it FAIL.

### Variant B
Same setup, but the attacker really downloads the backup. The verdict becomes `LIKELY_EXFILTRATED`. The point: the verdict follows the logs, not the script.

---

## 6. What runs on the laptop: the 12 containers

All started by `docker-compose.yml`. All Python services share **one** image (`mallya-py:dev`) to save disk space; each mounts only its own code.

| Container | Technology | Job |
|---|---|---|
| `postgres` | Postgres 16 | Two databases: `mallya` (MALLYA's own records) and `meridian` (the fake bank's customers). |
| `redis` | Redis 7 | Message bus for live updates to the browser. |
| `minio` | MinIO (S3-compatible storage) | The bank's buckets. Sends an **audit webhook** for every request to the backend. |
| `nginx` | nginx 1.27 | The **CDN**. Caches files for 30 days. Writes access logs. Also has a small "probe gateway" (port 9100). |
| `cdn-admin` | Python | Reads nginx's cache files on disk to list what's cached; can purge or prefetch. |
| `mock-iam` | Python | Fake identity system: principals, policy events, network ranges, presigned URLs. |
| `mock-vendor` | Python | Fake Northwind API and fake QuickSummarize AI tool, with call logs and deletion endpoints. |
| `attacker` | Python | Plays the stranger on the internet who probes the CDN. |
| `verifier` | Python | MALLYA's outside tester. Classifies each response (DENIED, ACCESSIBLE, DNS_FAILURE, …). |
| `worker` | Python (FastAPI) | The **customer-side worker**. The only thing allowed to read raw customer data. Runs detectors, fingerprints, scans and approved actions. |
| `backend` | Python (FastAPI) | The **control plane**: agents, orchestration, evidence, privacy gateway, risk, API. |
| `frontend` | Next.js 16 on Node 22 | The web console you click on, at http://localhost:3100. |

---

## 7. The three networks, and why they matter

```
               external_net (172.29.0.0/24)
   attacker ──┐   verifier ──┐
              └──────────────┴──► nginx (the CDN)
                                    │
   ──────────────────────────────── │ ─────────────────── customer_net (172.28.0.0/24)
                                    ▼
   MinIO ◄── worker ── mock IAM ── mock vendor ── cdn-admin ── postgres ── redis
     │ audit webhook      │
     ▼                    │ metadata only (counts, masked samples, fingerprints)
   backend ◄──────────────┘
     │  ui_net (172.30.0.0/24)
   frontend
```

- **external_net** is "the internet". Only the attacker, the verifier and nginx's public side are on it. The attacker and verifier can reach **nothing except the CDN**. A test (`test_verifier_cannot_reach_minio_except_via_nginx`) proves the verifier can't reach MinIO, Postgres or the worker directly. So when the verifier gets 403, that's what a real outsider would get.
- **customer_net** is "inside the bank". Storage, database, worker, mocks and backend.
- **ui_net** connects only the browser app to the backend, so the web app never sits on the bank's internal network.

Containers have fixed IP addresses (for example attacker `172.29.0.66`, verifier `172.29.0.77`). That's how the investigation can tell "external stranger" from "known partner" from "internal service" in the logs.

---

## 8. The six agents

An "agent" here is a Python module with typed inputs and outputs, retries, timings and a short decision summary. **They are deterministic code.** The language model only helps phrase text summaries, and only through the privacy gateway.

| # | Agent | What it does | What it never does |
|---|---|---|---|
| 1 | **Exposure Hunter** (`hunter.py`) | Lists all assets; checks anonymous grants per object (including prefix-only grants); runs detectors through the worker; runs consent-sync, egress and the 15 Lite checks. | Use an LLM to detect. |
| 2 | **Investigation** (`investigation.py`) | Ingests and deduplicates nginx logs + MinIO audit + IAM events + git history + vendor call logs; checks log coverage; decides the access verdict, root cause and timeline. | Treat "was public" as exfiltration. |
| 3 | **Blast Radius** (`blast_radius.py`) | Keyed-fingerprint search of every known location; counts records and consent status; builds the asset graph; marks UNVERIFIED anything it couldn't inspect. | Claim a fingerprint match means the data is accessible. |
| 4 | **Remediation** (`remediation.py`) | Plans fixes for the cause; runs a **safety check** on real access events (who depends on this?); executes approved actions; re-plans from verifier evidence. | Execute without an approval token the worker accepts. |
| 5 | **Adversarial Verification** (`verification.py`, `verification_vendor.py`) | Real outside requests (edge + origin), the authorised-consumer check, a fingerprint copy hunt, forced re-syncs for vendor cases. | Trust remediation's own success message. |
| 6 | **Compliance Evidence** (`compliance.py`) | Writes drafts stamped "DRAFT — REQUIRES LEGAL AND COMPLIANCE REVIEW"; builds the signed pack. | Decide that a law applies, set deadlines, or submit anything. |

---

## 9. How the agents are wired together (LangGraph)

`backend/app/orchestration/graph.py` uses **LangGraph** (a library for wiring steps into a graph with conditional branches). There are four graphs:

```
triage_graph:   Hunter ─► Investigation ─► Blast Radius ─► Risk ─► Remediation plan ─► Compliance drafts
                                                                       │
                                                         (stops and waits for a human)
                                                                       ▼
fix_graph:      execute approved ─► Verification ─┬─ VERIFIED_FIXED ─► drafts + signed pack
                                                   └─ anything else  ─► re-plan (wave N+1) ─► wait for approval again
verify_only_graph:  run Verification again on demand
lite_graph:     Investigation verdict ─► Risk ─► Recommendation   (no live fixes for Lite scenarios)
```

The **drill engine** (`backend/app/drills/engine.py`) runs a scenario: reset the sandbox, plant the incident, start the triage graph, pause for approval, continue after approval, loop until verified.

---

## 10. Detection: finding sensitive data without being fooled

Code: `shared/mallya_common/detectors.py`, `verhoeff.py`. It runs **inside the worker**, next to the data.

### PAN (Indian tax ID format, e.g. `ABCDE1234F`)
1. **Pattern:** 5 letters, 4 digits, 1 letter → `FORMAT_MATCH`.
2. **Structure:** the 4th letter must be a valid holder type (P for person, C for company, …) → `STRUCTURAL_MATCH`.
3. **Column context:** a column named `pan` in a `customers` table scores high; a column named `sku` in `products` scores 0.
4. If it's a known synthetic test value → `CONFIRMED_SYNTHETIC_TEST_VALUE`.

A pattern match is never claimed to be a "real PAN".

### Aadhaar (12-digit Indian ID)
12 digits, first digit not 0 or 1, and the **Verhoeff checksum** must pass (an error-detecting check digit algorithm). Passing the checksum doesn't mean the number was ever issued.

### Email and phone
Standard deterministic patterns.

### Decoys planted in every run
- product SKUs shaped like PANs (rejected: context 0.0);
- 12-digit invoice numbers that fail Verhoeff (rejected);
- a QA fixture table with structurally valid PAN-shaped labels (rejected by context).

The incident's **Findings** tab shows these under "Decoys correctly rejected", so you can see the detector isn't just grepping for patterns.

---

## 11. Fingerprints: tracking records without seeing them

Problem: MALLYA needs to say "the same 5,000 people are in the backup *and* the archive" without the control plane ever holding raw identifiers.

Solution: a **keyed fingerprint**.
```
fingerprint = HMAC-SHA256(FINGERPRINT_KEY, normalise(value))   →  stored as  HMAC-SHA256:v1:<hex>
```
- The key exists **only** inside the worker's environment. Not in the database, not in the backend, not in git.
- Without the key, nobody can reverse a fingerprint or build a lookup table of all possible PANs (which a plain hash would allow).
- `v1` is the key version, so the key can be rotated later.
- Matching fingerprints in two places means "the same record is present in both". Whether that copy is *accessible* is tested separately by a real request.

---

## 12. Investigation: was the data actually taken?

Code: `backend/app/investigation/ingest.py`, `verdict.py`, `rootcause.py`.

### The log sources
1. **nginx access log**: every request to the CDN, with client IP, status, bytes, and cache status (HIT, MISS, BYPASS).
2. **MinIO audit webhook**: every request that reached storage, posted to the backend at `/internal/minio-audit`.
3. **Mock IAM events**: who changed policies when.
4. **Git history** of `infra-config`: who committed what.
5. **Vendor call logs**: what was sent to Northwind or QuickSummarize.

Records are deduplicated (one request appears in both nginx and MinIO). **Coverage** is checked: if a source is missing for part of the exposure window, MALLYA can't honestly say "nobody downloaded it", so the verdict becomes INSUFFICIENT_EVIDENCE.

### The important distinctions
- **Attempt vs download.** LIST, HEAD, wrong file names, 403 and 404 are *attempts*. Only a 200/206 response carrying the real object's bytes counts as a *download*.
- **Who asked.** External stranger vs known partner (Northwind's IP) vs internal service.

### The verdicts
| Verdict | Meaning |
|---|---|
| `EXPOSED_NOT_ACCESSED` | It was open but nobody touched it. |
| `ACCESSED_INTERNAL_ONLY` | Only internal services read it. |
| `ACCESS_ATTEMPTED_NOT_SUCCESSFUL` | Outsiders tried; no real bytes left. |
| `LIKELY_EXFILTRATED` | Real object bytes went to an outsider, or were proven at an unapproved third party. |
| `INSUFFICIENT_EVIDENCE` | Logs have gaps, so MALLYA won't guess. |
| `FALSE_POSITIVE` | The finding wasn't real sensitive data. |

### Root cause
`rootcause.py` walks git history and IAM events for the change that opened the asset: a commit (with author, message and diff), a manual policy change, or a vendor integration. Prefix-only grants (a public link to just one folder) are handled too.

---

## 13. Blast radius: how far did it spread?

- Takes the fingerprints of the exposed records.
- Searches every known location (buckets, tables, vendor stores) for matching fingerprints, through the worker.
- Maps consent: how many affected people withdrew marketing consent (306 in HERO-01).
- Builds the **asset graph** (shown in the console): internet → CDN → bucket → objects, plus replicas and archives.
- Lists **UNVERIFIED** locations it couldn't inspect (for HERO-01, the CDN cache). This honesty matters, because that's exactly where the leftover copy turns out to be.

---

## 14. The risk score

Code: `backend/app/risk/score.py`. A fixed-rules score from 0 to 100, with a line for each factor. It is a **prioritisation aid, not a breach probability**.

| Factor | Max points | How |
|---|---|---|
| Exposure type | 14 | Public storage 14, public export link 13, shadow-AI upload 13, consent mismatch 10, config drift 8, permissions 7, governance 4 |
| Data sensitivity | 20 | Aadhaar 11, health 11, PAN 9, email 3, phone 3 (summed, capped at 20) |
| Public accessibility | 15 | 15 if anonymous internet access, otherwise 2 |
| Record count | 15 | Logarithmic; 100,000 records reaches the maximum |
| Asset count | 6 | 2 per asset |
| Access verdict | 16 | Likely exfiltrated 16, insufficient evidence 9, attempted 7, internal 3, not accessed 2, false positive 0 |
| Encryption at rest | 4 | 0 if encrypted, 4 if not or unknown |
| Replication | 4 | 4 if copies exist |
| Third party | 6 | 6 if a vendor is involved |

Bands: **Critical** ≥ 75, **High** ≥ 50, **Moderate** ≥ 25, otherwise **Low**.

---

## 15. Remediation and human approval

### The actions the worker knows how to do
| Action | What it really changes |
|---|---|
| `bucket.set_private` | Removes the anonymous policy on a bucket or prefix in MinIO. |
| `infra.patch_bucket_private` | Commits a fix to `buckets.yaml` (and reclassifies the bucket), then runs the sync. |
| `infra.enable_policy_gate` | Turns on the `no_public_pii_buckets` gate and proves it by replaying the bad commit, which must be blocked. |
| `cdn.purge` | Deletes the cached file from nginx's cache. |
| `partner.presigned_handoff` | Gives a partner a private, expiring link instead of public access. |
| `integration.disable_sync` | Stops a vendor sync job. |
| `integration.enable_consent_filter` | Makes the sync skip people who withdrew consent. |
| `integration.block_vendor` | Blocks an unapproved vendor. |
| `vendor.delete_subjects` | Asks the vendor (mock) to delete specific people's records. |
| `vendor.ai_delete_uploads` | Asks the AI tool (mock) to delete uploaded files. |
| `object.delete` | Deletes a leftover file. |

Each action card shows: **risk**, **rollback plan**, and **verification requirement**.

### The safety check
Before an action is approved, MALLYA reads real access events to see who depends on the thing it's about to close. If a legitimate party would break (like Northwind and the replica), the action is **HELD**, and an alternative is proposed. Overriding a hold needs a written reason, which goes into the evidence.

### How approval is enforced
1. An analyst (role `SECURITY_ANALYST` or `ADMIN`) clicks Approve.
2. The backend records the approval and creates an **HMAC-signed approval token** (key `APPROVAL_SIGNING_KEY`).
3. The worker **verifies the token itself** before doing anything. A backend bug can't bypass it.
4. An `executed_actions` ledger makes each approval run **only once**; replaying it does nothing.

---

## 16. Adversarial verification: attacking its own fix

Code: `backend/app/agents/verification.py`, `backend/app/verification/verdict.py`, `sandbox/verifier/app.py`.

### What it does
- **Edge probe:** an anonymous GET of every exposed path, through the CDN, like an attacker. The cache answers if it can.
- **Origin probe:** the same path with a query string added. nginx never serves query-string requests from cache, so this tests the storage itself.
- **Authorised consumer:** a legitimate account (picked per bucket, e.g. `reporting-service`) must still get 200. If none applies, it's shown as "not applicable".
- **Copy hunt:** fingerprint search of every known location; each copy found must be shown to be not externally accessible.
- **Vendor cases:** force a re-sync and re-query the vendor to confirm records are gone.

MALLYA's own probes carry special headers so they never put files into the cache themselves.

### How responses are classified
`DENIED` (401/403) is the only answer that counts as blocked. `ACCESSIBLE` means it got data. `DNS_FAILURE`, `CONNECTION_REFUSED`, `TIMEOUT`, `SERVER_ERROR`, `NOT_FOUND` and similar are **inconclusive**: a broken network is not proof of a fix.

### The verdict
**VERIFIED_FIXED** only if **all** of these hold:
- every outside probe of a known exposed path got a genuine 401/403;
- the original object is protected;
- every known copy location was checked (none UNVERIFIED);
- every fingerprint match is accounted for;
- the authorised consumer still gets 200;
- evidence was recorded.

Otherwise: **PARTIALLY_FIXED**, **STILL_EXPOSED**, or **VERIFICATION_FAILED** (the verifier itself was unavailable, so nothing was tested).

---

## 17. Evidence packs: proof nobody can quietly edit

Code: `backend/app/evidence/chain.py`, `signing.py`, `pack.py`, `pdf.py`, and `tools/mallya_verify.py`.

### The hash chain
Every event in an incident is stored like a block in a chain:
```
payload_hash = SHA-256(canonical JSON of the payload)
event_hash   = SHA-256(canonical JSON of {metadata, payload_hash, previous_event_hash})
```
The first event's "previous hash" is 64 zeros. Changing, deleting, inserting or reordering any event breaks every link after it. A Postgres advisory lock makes sure two events can't be appended at the same moment.

"Canonical JSON" means keys sorted, UTF-8, no extra spaces, so the same data always gives the same bytes and the same hash.

### The signature
`manifest.json` is signed with **Ed25519** (a modern digital-signature scheme). The private key lives in a secrets volume (`EVIDENCE_SIGNING_KEY_PATH`), never in the database, the browser or git. In this prototype it's a dev key labelled `DEV-NON-PRODUCTION`.

### What's inside the ZIP
| File | Purpose |
|---|---|
| `manifest.json` | The full incident record plus the hash of every file and the chain head. |
| `manifest.sig` | The Ed25519 signature. |
| `public_key.pem` | The key to check the signature. |
| `events.jsonl` | All chained events. |
| `report.pdf` | A human-readable report. |
| `timeline.csv` | The timeline as a spreadsheet. |
| `checksums.sha256` | SHA-256 of every other file. |

### Verifying it
```bash
python tools/mallya_verify.py mallya-evidence-INC-....zip
```
Five checks: **checksums, manifest-files, hash-chain, chain-head, signature**. Each prints PASS or FAIL. The script needs only Python's standard library plus `cryptography`. The **Verify now** button in the console runs the same script.

Nine tamper tests prove it catches an edited event, a deleted event, reordered events, an inserted event, a fully re-hashed fake chain, an edited manifest, and an attacker re-signing with their own key.

Wording rule: the pack is **"cryptographically tamper-evident and audit-oriented"**. MALLYA never calls it "legally admissible".

---

## 18. The privacy boundary: the AI never sees raw identifiers

### Where raw data is allowed
Only in the bank's database, the bank's storage, and the vendor mocks. Only the **worker** reads it. The worker sends the backend only **counts, masked samples** (like `ABCPK*****`) and **fingerprints**.

### The LLM privacy gateway (`backend/app/privacy/gateway.py`)
Every language-model call goes through four steps, even with the default local template "model":
1. **Schema check:** only allow-listed fields are allowed. Field names like `rows`, `email`, `pan` are rejected outright.
2. **Outbound DLP:** scans the payload for unmasked PANs, Verhoeff-valid Aadhaar numbers, full emails, full phones.
3. **Block on any hit:** the payload doesn't leave. A `PrivacyPolicyViolation` is recorded with detector type, count and field path, **never the value**.
4. **Audit:** every allowed call records exactly which field paths were shared (`llm_calls.shared_fields`).

The headline **"0 raw identifiers sent to the AI"** on the Privacy Boundary screen is computed from these audit records, not typed in.

### Proving it (`tools/privacy_suite.py`, 13 tests)
- **10 unit tests** for detectors, Verhoeff, decoys, masking, fingerprints, and the gateway blocking each kind of identifier.
- **3 leak scans:** collect all container logs, a full dump of MALLYA's database, every evidence pack (PDFs decompressed) and every API response. Pipe them into the worker, which counts occurrences of all 20,000 raw identifiers in the sandbox. Result: **0 across 387 artefacts**.
- **Positive control:** plant one real identifier of each kind and make sure the scanner finds all 4. Otherwise a broken scanner could "pass" by finding nothing.

### Where an LLM is (and isn't) used
- Detection, verdicts, scores, plans and actions: **plain code**, no AI.
- The LLM only phrases summaries and compliance drafts.
- By default the "provider" is a local template engine (`backend/app/privacy/templates.py`), so the whole thing runs with no API key.

---

## 19. Compliance drafts

The Compliance Evidence agent writes drafts (for example an internal incident summary, or a notice to affected customers), each stamped **"DRAFT — REQUIRES LEGAL AND COMPLIANCE REVIEW"**.

The **Drafts** tab also has **Obligations and timers**: MALLYA never decides a law applies or sets a deadline. A timer only starts when a person records an obligation. Settings has a "Regulatory context for drafts" section for that context.

---

## 20. All 20 scenarios

### Deep scenarios (live fix + outside attack + signed pack)
| ID | Name | Story | The hard part |
|---|---|---|---|
| HERO-01 | PUBLIC-BACKUP | A `buckets.yaml` commit made the customer backup public; the replica was opened by hand for a partner; the CDN cached the backup. | First verification must find the CDN cache and the replica still serving data. Variants A (attempts only) and B (real download). |
| D-02 | PUBLIC-S3-BUCKET | The internal-docs bucket is public; a few files contain identifiers among many harmless ones. | Blast radius must flag only the sensitive files. |
| D-03 | SENSITIVE-EXPORT | A CSV export with identifiers left behind a public link in `meridian-exports`. | Fingerprint search finds the same records in the archive too. |
| D-04 | CONSENT-WITHDRAWAL-MISMATCH | People who withdrew marketing consent are still synced to Northwind. | Stop the sync, delete those people at the vendor, then re-query the vendor to prove it. |
| D-05 | SHADOW-AI-UPLOAD | A file with identifiers was uploaded to an unapproved AI tool, QuickSummarize. | Prove exactly which records left, by fingerprints in the vendor's received-payload store. |

### Lite scenarios (detect + verdict + recommendation, no live fix)
| ID | What's planted |
|---|---|
| UNENCRYPTED-STORAGE | A bucket claims encryption but customer files are stored unencrypted. |
| EXCESSIVE-DB-PERMISSIONS | A read-only analytics role can write to the customer table. |
| EXPOSED-POSTGRES | A legacy database login still accepts its default password. |
| DATABASE-BACKUP-DRIFT | A customer dump sits in a bucket the infra config doesn't know about. |
| PAN-DISCOVERY | A new table outside the data catalogue holds PAN-format IDs. |
| AADHAAR-DISCOVERY | Aadhaar-format IDs in a bucket not classified for personal data. |
| HEALTH-DATA-EXPOSURE | Health claims with ICD-10 diagnosis codes readable by every database role. |
| UNAPPROVED-API | Customer phones sent to an unregistered SMS API that keeps no inspectable payload. |
| VENDOR-OVERPERMISSION | A vendor integration has scopes it doesn't need. |
| VENDOR-CREDENTIAL-EXPIRY | A vendor credential expired but the integration is still active. |
| MISSING-ROPA-ENTRY | An approved integration processes personal data with no "record of processing activities". |
| UNREVIEWED-DATA-RETENTION | Customer records past their retention date, never reviewed. |
| UNAPPROVED-AI-VENDOR | An unapproved AI tool is in use (but the upload has no personal data). |
| AI-TRAINING-DATA-LEAK | An approved AI vendor may train on uploaded customer data (training opt-in is on). |
| SHARED-DRIVE-EXPOSURE | A file with identifiers on the shared drive is readable by an all-staff group. |

The "expected answers" for every scenario live in a **hidden ground-truth folder** (`benchmark/ground_truth/`). Agents are forbidden from reading it, and a test enforces that.

---

## 21. Every screen in the console

Open http://localhost:3100. Look and feel: a dark-first "calm control room". Colour is used only for meaning: **red** = still exposed / critical, **amber** = partial / warning, **green** = verified / OK, **grey** = unverified. IBM Plex Sans for text, IBM Plex Mono for IDs, hashes, HTTP responses and timestamps. There's a light theme too, and it works on a phone-sized screen (390px).

### The frame around every page (`components/shell/app-shell.tsx`)
- **Left sidebar** (collapsible, with tooltips when collapsed): Dashboard, Incidents, Breach Drill Lab, Assets, Benchmarks, Evidence Vault, Privacy Boundary, Agents, Settings. On a phone it becomes a slide-out menu.
- **Top bar:** **Demo Mode** button (opens a confirm dialog: "Reset sandbox and run"), theme toggle (dark/light), signed-in user and sign out.
- **Footer:** "A concept prototype built for Redacto."
- A "skip to content" link for keyboard users.
- Every view has a **loading**, **empty** and **error** state, so you never see a blank screen or fake numbers.

### Login (`/login`)
Email and password form with validation. Demo accounts are listed in section 22.

### Dashboard (`/`)
"Every number on this page is computed from stored incident, verification and benchmark runs." Tiles: **Active incidents**, **Critical exposures**, **Verified fixes**, **Open verification checks**, **Assets monitored**, **Mean time to detect**, **Mean time to verified fix**, **Benchmark composite**. Below: **Recent incidents** and **Privacy status**.

### Incidents (`/incidents`)
A table of every incident with columns **Incident** (reference like `INC-2026-0001` and title), **Status**, **Access verdict**, **Risk**, **Type** and **Detected** (time). Click a row to open it. The Dashboard's "Recent incidents" uses a compact version of the same table.

### Incident detail (`/incidents/[id]`): 9 tabs
1. **Overview:** summary, **Risk score** (with every factor's points and reason), **Measured timings** (per stage, monotonic clock; UTC for audit), and the **Agent run** (short decision summaries; no chain-of-thought is stored or shown).
2. **Findings:** what was detected, with masked samples and detector outcomes, plus **Decoys correctly rejected**.
3. **Investigation & Root Cause:** the **Access verdict** with confidence and reasons ("Being public is never treated as proof of exfiltration"); **Log sources** with coverage; events split into *External · successful download of a real object*, *External · attempts without object bytes*, *Known partner*, *Internal*; the root-cause commit with its diff.
4. **Asset Graph:** an interactive graph (React Flow). Red animated edges are exposure paths from the internet. Tiles: **Records affected**, **Withdrew marketing consent**, **Locations holding the data**, **Assets in the blast radius**, **Unverified locations**. A table "Where the affected records live", and an **Unverified** panel ("Shown honestly: these were not inspected by the Blast Radius Agent").
5. **Remediation:** action cards in waves, each with risk, rollback, verification requirement and status (pending, approved, held, executed); the **Proposed patch · infra-config/buckets.yaml** shown as a diff; select, **Approve**, override with reason, **Execute approved**; the presenter auto-approve toggle.
6. **Verification:** one entry per run (VER-…-1, VER-…-2). The verdict banner; **External attack test** table (method, path, edge/origin layer, HTTP status, cache status, outcome); the **Copy and replica hunt** ("Match = data present; accessibility tested separately"); the authorised-consumer result.
7. **Evidence:** the **Hash chain** with every event and its hash; **Signed packs** with download and **Verify now** (shows the five PASS/FAIL checks).
8. **Timeline (UTC):** every event in order.
9. **Drafts:** compliance drafts and **Obligations and timers** ("Record an obligation").

### Breach Drill Lab (`/drills`)
All 20 scenarios as cards (Deep and Lite), each with its description and "Hard part". Each card's footer has:
- an **Attacker variant** picker where it applies ("A · attempts, no download" or "B · confirmed download");
- a **Presenter auto-approve** switch;
- a **Run drill** button.

**Recent drills** are listed below.

### Live run (`/drills/[id]`)
Updates live while a drill runs: the **Six agents** strip showing which agent is running/done/failed, and **Story beats**, the narrative of what just happened ("Investigation: 3 anonymous attempts, no successful download"). Links into the incident.

### Assets (`/assets`)
Everything the Exposure Hunter discovered through the worker: buckets, tables, vendor integrations, CDN. Filter by kind. A **Connectors** panel ("Every connector here is a sandbox or mock").

### Benchmarks (`/benchmarks`)
Eyebrow: "Honest by design". The **Main set** and **Held-out set** each get a grid of tiles, every one showing its sample size (n):
- **Detection F1**, with precision, recall and TP/FP/FN counts;
- **Decoy false positives**;
- **Verdict accuracy**, including attempt-vs-download;
- **Root-cause accuracy**;
- **Blast-radius accuracy**;
- **Fingerprint accuracy**;
- **Remediation correctness**;
- **Approval compliance**;
- **Idempotency**;
- the composite.

Below that are a chart, **Detection to verified fix (mean seconds)** per scenario, and the **Runs** table, which includes failed and incomplete runs. The harness also writes `benchmark.json`, `runs.csv` and `report.pdf` to `benchmark/results/<run id>/`.

### Evidence Vault (`/evidence`)
All signed packs across incidents, with download, **Verify now**, and a **Copy verify command** button that copies the `python tools/mallya_verify.py …` line.

### Privacy Boundary (`/privacy`)
Eyebrow: "Zero raw identifiers to the LLM". Tiles: **Detected locally**, **Fingerprinted**, **Masked samples**, **LLM calls made**, **Payloads blocked**, **Violations (non-test)**, **Privacy tests**. Tables: **Recent model calls** (with the exact fields shared), **Privacy policy violations** (test violations labelled TEST, blocks labelled BLOCKED), and the **Privacy test suite** results.

### Agents (`/agents`)
"Six agents with typed inputs and outputs, retries, timings and short decision summaries." For each agent: **Runs**, **Failed**, **Mean** time. **Recent executions** below.

### Settings (`/settings`)
**Environment**: environment name, organisation ("Meridian Bank (fictional, single tenant)"), LLM provider ("local · deterministic reasoning templates (no API key)"), whether Demo Mode is enabled, and your role. Then **Regulatory context for drafts**. No secret is ever shown.

---

## 22. Users, roles and login

All demo accounts share the password **`mallya-demo-2026`** (sandbox only).

| Account | Role | Can |
|---|---|---|
| `analyst@meridian.demo` | SECURITY_ANALYST | Run drills, approve and execute remediation |
| `engineer@meridian.demo` | IMPLEMENTATION_ENGINEER | Run drills (operate), not approve |
| `admin@meridian.demo` | ADMIN | Everything |
| `viewer@meridian.demo` | VIEWER | Read only |

- Passwords are hashed with **Argon2**.
- Login sets an HTTP-only cookie `mallya_session`.
- Permission groups in code: `CAN_APPROVE` and `CAN_OPERATE` (`backend/app/core/security.py`).
- Login is rate-limited (`backend/app/core/ratelimit.py`).
- The frontend's `proxy.ts` redirects to `/login` if you aren't signed in.

---

## 23. The backend, file by file

FastAPI app in `backend/app/`. Python 3.12, SQLAlchemy 2, Alembic migrations, Postgres.

| Path | What's in it |
|---|---|
| `main.py` | Creates the app, mounts routers, error handlers. |
| `seed_users.py` | Creates the four demo accounts. |
| `core/config.py` | Settings from environment variables. |
| `core/db.py` | Database engine and sessions. |
| `core/security.py` | Argon2, sessions, roles. |
| `core/errors.py` | Error responses that never echo raw data. |
| `core/ratelimit.py` | Simple rate limiting. |
| `core/events.py` | Publishes live events to Redis. |
| `core/jobs.py` | Background job runner. |
| `models/` | All database tables (section 27). |
| `agents/base.py` | The common harness: inputs, outputs, retries, timings, summaries. |
| `agents/hunter.py`, `investigation.py`, `blast_radius.py`, `remediation.py`, `verification.py`, `verification_vendor.py`, `compliance.py`, `lite.py`, `registry.py` | The agents (section 8). `lite.py` also correlates Lite findings with open Deep incidents so nothing is reported twice. |
| `orchestration/graph.py` | The LangGraph graphs (section 9) and `apply_risk`. |
| `drills/catalog.py` | The 20 scenarios' public descriptions. |
| `drills/engine.py` | Reset, run, approve, continue. |
| `investigation/ingest.py`, `verdict.py`, `rootcause.py` | Log ingestion, access verdict, root cause. |
| `verification/verdict.py` | The pure VERIFIED_FIXED decision function (unit tested). |
| `privacy/gateway.py`, `provider.py`, `templates.py` | The privacy gateway and the local template "model". |
| `evidence/chain.py`, `signing.py`, `pack.py`, `pdf.py` | Hash chain, Ed25519, ZIP, PDF. |
| `risk/score.py` | The risk score. |
| `remediation/approvals.py` | Approval records and signed tokens. |
| `api/internal.py` | `/internal/minio-audit` (the storage webhook). |
| `api/v1/auth.py`, `incidents.py`, `drills.py`, `actions.py`, `overview.py`, `benchmarks.py` | The public API used by the console. Interactive docs at http://localhost:8000/docs. |
| `migrations/` | Alembic: the initial schema and the `is_test` flag on LLM calls. |
| `tests/` | See section 29. |

---

## 24. The worker, file by file

`worker/mallya_worker/`. This is the "customer side": the only code with database passwords, storage credentials and the fingerprint key.

| File | What's in it |
|---|---|
| `api.py` | The worker's HTTP endpoints, called by the backend (scans, checks, actions, jobs). |
| `config.py` | Settings. |
| `synth.py` | Generates the 5,000 deterministic synthetic customers. |
| `seed.py` | Resets everything: wipes buckets, rebuilds the bank database, sets up networks and IAM. |
| `meridian.py` | The bank's database schema, including the data catalogue. |
| `storage.py` | MinIO helpers through `mc`: principals, anonymous rules, make public/private. |
| `infra.py` | The `infra-config` git repo: commits, sync with gates, regression check that replays the bad commit. |
| `scan.py` | Scans objects, tables, vendors and the CDN cache; builds the subject (fingerprint) index; consent breakdown. |
| `scenarios.py` | The "plants" for HERO-01 and D-02…D-05. |
| `lite.py` | The 15 Lite plants and their checks. |
| `checks.py` | Consent sync, egress and run-sync checks. |
| `actions.py` | The remediation actions, approval-token verification and the run-once ledger. |
| `leakscan.py` | The leak scanner used by the privacy suite (with a positive-control self test). |

`shared/mallya_common/` holds code used by both sides: `detectors.py`, `verhoeff.py`, `masking.py`, `fingerprint.py`, `canonical.py`.

`policies/no_public_pii_buckets.py` is the policy gate that blocks commits making a personal-data bucket public.

---

## 25. The sandbox services, one by one

`sandbox/`:
- **`nginx/nginx.conf`**: the CDN. Caches GETs for 30 days, keyed by method and path. Never caches authenticated requests or query-string requests. Never caches requests carrying MALLYA's probe headers. Port 9100 is the "probe gateway" that only accepts calls from inside the bank network.
- **`cdn-admin/app.py`**: reads nginx's cache files to list what's cached and how long it's valid; `/purge` and `/prefetch`.
- **`mock-iam/app.py`**: principals, policy events, networks (with roles like partner or internal), `/presign` for presigned URLs.
- **`mock-vendor/app.py`**: Northwind contacts API, QuickSummarize upload store, `/admin/calls` logs, delete endpoints, and a catch-all that logs calls to other "vendors" without keeping the payload.
- **`attacker/app.py`**: variants A (attempts only) and B (real download).
- **`verifier/app.py`**: runs probes and classifies results; has a network self-test.
- **`postgres/init.sh`**: creates the two databases.

---

## 26. The frontend, file by file

Next.js 16 (App Router), React, TypeScript, Tailwind CSS v4, shadcn/ui components.

| Path | What's in it |
|---|---|
| `styles/tokens.css` | All colours as **OKLCH tokens**, driven by one `--brand-hue`. Dark and light themes. No hard-coded colours in components. |
| `app/globals.css` | Base styles, a faint grid background, motion that respects "reduce motion". |
| `app/login/page.tsx` | Login. |
| `app/(app)/layout.tsx` | The shell around every signed-in page. |
| `app/(app)/…/page.tsx` | One file per screen (section 21). |
| `components/shell/` | Sidebar, top bar, nav, Demo Mode dialog. |
| `components/incidents/` | The incident tabs: list, investigation, graph, remediation, verification, other tabs. |
| `components/status.tsx` | Maps every verdict to a colour meaning (unit tested: a missing verdict is grey, never green). |
| `components/panel.tsx` | Panels, metric tiles, key–value rows, page headers. |
| `components/states.tsx` | Loading, empty and error states. |
| `components/diff.tsx` | The git diff viewer. |
| `components/verdict-banner.tsx`, `agent-timeline.tsx` | Verdict banner, agent progress. |
| `components/ui/` | shadcn/ui building blocks (buttons, tabs, dialogs, tooltips…). |
| `lib/api.ts`, `types.ts`, `hooks.ts`, `format.ts` | API calls, types, data hooks (TanStack Query), number/date formatting. |
| `proxy.ts` | Redirects to login when signed out. |
| `next.config.ts` | Forwards `/api/v1/*` to the backend. |
| `tests/unit.test.ts` | Vitest tests for status colours and formatters. |

Other libraries: react-hook-form + zod (forms), Recharts (charts), @xyflow/react (the asset graph), next-themes (dark/light), EventSource (live updates).

---

## 27. The database

The `mallya` database (MALLYA's own records; 26 tables) holds, among others:
- users and sessions;
- drills and drill events;
- incidents (with reference, scope, severity, status);
- assets and findings (masked samples and fingerprints only);
- subject sets (fingerprint groups);
- log records ingested from nginx and MinIO;
- verdicts, root causes, risk scores;
- remediation actions, approvals and executed actions;
- verification runs and probe results;
- evidence events (the hash chain) and packs;
- LLM calls (with `shared_fields`) and privacy violations (each with an `is_test` flag);
- agent executions and timings;
- benchmark runs;
- a small key–value table.

No table stores a raw PAN, Aadhaar, email or phone. The leak scan checks this on every run.

The `meridian` database is the fake bank's own data, which only the worker reads.

---

## 28. Live updates

When a drill runs, the screen moves without refreshing:
1. Agents and the engine publish events to **Redis** (`core/events.py`).
2. The backend exposes them as **Server-Sent Events (SSE)**.
3. The browser listens with `EventSource` and updates the live run page and incident tabs.

---

## 29. Tests: how we know it works

| Suite | Result | What it covers |
|---|---|---|
| Backend (unit, boundary, privacy, tamper, HERO E2E, Deep E2E) | **44 passed** | Verdict logic, evidence tamper (9 tests), privacy gateway, network boundaries, ground-truth isolation, the full HERO-01 story both variants, D-02…D-05 |
| Backend Lite E2E | **15 passed** | Each Lite scenario creates exactly one incident of the right type, with the right verdict, recommendation only |
| Worker | **3 passed** | Including replaying the bad commit and confirming the policy gate blocks it |
| Privacy suite | **13/13** | 0 raw identifiers in 387 artefacts; positive control 4/4 |
| Frontend Vitest | **5 passed** | Status colours and formatters |
| Frontend type check (`tsc`) | **clean** | No TypeScript errors |

Key "proof" tests:
- the verifier can't reach MinIO except through nginx;
- a cached copy or exposed replica prevents VERIFIED_FIXED;
- the re-applied bad commit is blocked;
- agents can't import or read the ground truth;
- every form of tampering is detected;
- closing an incident is refused unless the latest verification is VERIFIED_FIXED.

---

## 30. The benchmark: how good is it, honestly

`benchmark/`:
- `scenarios/generator.py` creates scenario runs and their expected answers (ground truth).
- `holdout/generator.py` creates a **held-out set** with a different random seed (7919), never used while building the detectors.
- `holdout/FROZEN_DETECTORS.json` stores hashes of the detector code, frozen at git tag `detectors-v1`, so we can prove they didn't change.
- `evaluation/metrics.py`, `run.py`, `report.py` run every drill for real and score the results.

Scores: precision, recall, F1 for detection, plus correctness of verdicts, attempt-vs-download, root cause, blast radius, fingerprints, remediation, approvals, idempotency, verification and residual exposure. A project-defined **composite** weights Detection 30 / Investigation 25 / Remediation 25 / Verification 20. It's not an industry standard.

### All three runs (failures kept)
| Run | Main set | Held-out set | Notes |
|---|---|---|---|
| Run 1 | F1 0.926, composite 97.8 | F1 0.818, composite 93.1 | 4 false positives: Lite reported the same issue a Deep incident already had (a real MALLYA bug, fixed). The held-out set also exposed a bug in the ground-truth generator (fixed). |
| Run 2 | — | — | **Incomplete:** a temporary Docker Desktop file error killed the harness after 28 of 34 runs. Marked FAILED, kept in history. |
| Run 3 | 100% on everything, composite 100.0 | 100% on everything, composite 100.0 | Detectors unchanged since `detectors-v1`. |

Run 3's mean timings: detect 1.8 s, verdict 0.6 s, blast radius 1.7 s, remediation 0.5 s, verification 12.2 s, evidence pack 0.2 s; detection to verified fix 23.4 s (with presenter auto-approve).

### Read the 100% with care
- **Same author.** The same person (and AI) wrote the scenarios, the answers and the detectors. 100% shows the system is internally consistent, not that it would catch real-world leaks this well.
- **Small held-out set:** 9 runs.
- **No LLM comparison:** that mode needs an API key and wasn't run.

---

## 31. How to run it yourself

Needs Docker Desktop and Python 3.10+.

```bash
python tools/gen_env.py          # creates .env with random secrets (never committed)
docker compose up -d --build     # or ./mallya.ps1 dev on Windows, make dev elsewhere
./mallya.ps1 reset-demo          # seed the sandbox on a fresh start
```

- Console: http://localhost:3100 (change with `FRONTEND_PORT` in `.env`)
- API docs: http://localhost:8000/docs

Sign in as `analyst@meridian.demo` / `mallya-demo-2026`, click **Demo Mode**.

| Task | Windows | Elsewhere |
|---|---|---|
| Reset sandbox | `./mallya.ps1 reset-demo` | `make reset-demo` |
| Unit tests | `./mallya.ps1 test-unit` | `make test-unit` |
| All E2E scenarios | `./mallya.ps1 test-e2e` | `make test-e2e` |
| Privacy suite | `python tools/privacy_suite.py` | `make test-privacy` |
| Benchmark | `./mallya.ps1 benchmark` | `make benchmark` |
| Verify a pack | `python tools/mallya_verify.py pack.zip` | same |

A 3-minute spoken demo script is in [docs/demo-script.md](docs/demo-script.md).

---

## 32. Secrets and keys

| Secret | Where it lives | Used for |
|---|---|---|
| `FINGERPRINT_KEY` | Worker environment only | Keyed fingerprints |
| `APPROVAL_SIGNING_KEY` | Backend and worker | Signing and checking approval tokens |
| Evidence signing key | File at `EVIDENCE_SIGNING_KEY_PATH` in a secrets volume | Ed25519 signing of packs |
| MinIO / database / vendor credentials | Worker and sandbox services | Real access to the fake bank |
| MinIO audit token | MinIO and backend | Authenticating the audit webhook |

The fingerprint key and the signing key are separate. `.env` is generated with random values and is in `.gitignore`. Nothing secret is committed. Key **contents** never appear in the database, browser or logs.

---

## 33. What it does NOT do (limitations)

Full list in [docs/limitations.md](docs/limitations.md):
- **MinIO's public-read policy also allows LIST**, so the attacker's anonymous LIST gets 200 with file names (no file contents). MALLYA reports this as it really happens.
- No KMS, so no real encryption at rest.
- Verdicts are only as good as the logs. That's why INSUFFICIENT_EVIDENCE exists.
- Fingerprint search covers known locations only.
- Lite scenarios only recommend; they don't fix.
- Vendor deletion is a mock (a real vendor would need a real deletion proof).
- The evidence key is a dev key.
- Bucket names are fixed across benchmark variants.
- Starting from completely empty Docker volumes was tested at the start but not re-run at the very end (it would erase the benchmark history).
- No Playwright end-to-end browser test suite in the repo; Playwright was used for 48 screenshots in `docs/screenshots/`.
- The console runs as a development server, not a production build.

---

## 34. What a real product would need

- Keys in an HSM or cloud KMS, with rotation.
- Approvals signed by the person's own device (WebAuthn), not just a server token.
- An egress proxy so no component can send data out unexpectedly.
- Real vendor deletion with proof.
- SSO and MFA for logins.
- Multi-tenancy (many customers, isolated).
- Connectors for real clouds (AWS, Azure, GCP) and real CDNs.
- A production frontend build, monitoring and backups.
- An independent party writing the benchmark scenarios.

---

## 35. Glossary

| Term | Meaning |
|---|---|
| **PAN** | Indian Permanent Account Number (tax ID), format `ABCDE1234F`. |
| **Aadhaar** | Indian 12-digit identity number with a Verhoeff check digit. |
| **Verhoeff** | A check-digit algorithm that catches typing mistakes. |
| **Bucket** | A folder-like container in object storage (S3/MinIO). |
| **CDN** | Content Delivery Network: servers that cache files close to users. Here, nginx. |
| **Cache HIT / MISS** | HIT = served from the cache; MISS = fetched from the origin. |
| **Origin** | The real storage behind the CDN. |
| **Edge** | The CDN's public front. |
| **Presigned URL** | A private download link that expires. |
| **IaC / infra-config** | Infrastructure as code: settings stored in git and applied automatically. |
| **Policy gate** | A check that blocks bad config changes before they're applied. |
| **HMAC** | A hash that needs a secret key; used for fingerprints and approval tokens. |
| **SHA-256** | A standard hash function. |
| **Ed25519** | A modern digital-signature algorithm. |
| **Hash chain** | Each record includes the hash of the previous one, so edits are detectable. |
| **DLP** | Data Loss Prevention: scanning content for sensitive data before it leaves. |
| **LLM** | Large language model (the AI that writes text). |
| **LangGraph** | A library for wiring agent steps into a graph. |
| **SSE** | Server-Sent Events: the server pushing live updates to the browser. |
| **Exfiltration** | Data actually leaving to someone who shouldn't have it. |
| **Blast radius** | How many records, people and places are affected. |
| **RoPA** | Record of Processing Activities, a privacy register. |
| **Idempotent** | Running it twice has the same effect as once. |
| **F1** | A single score combining precision (no false alarms) and recall (nothing missed). |
| **Held-out set** | Test cases kept aside and never used while building, to check for overfitting. |
| **OKLCH** | A colour format where lightness is perceptually even, used for theme tokens. |

---

## 36. Questions your friend might ask

**"Is the attack real?"**
Yes, within the sandbox. Real HTTP requests from a real container to real nginx and MinIO. It just never leaves the laptop.

**"So why did the first fix only partly work? Did you fake that?"**
No. The CDN really had the file cached, so it kept serving it after storage was closed. And the replica was held on purpose because a partner depended on it. Both show up as real 200 responses.

**"Where's the AI in this?"**
Mostly not where people expect. Detection, verdicts, scores, fixes and verification are plain, testable code. The language model only writes the wording of summaries and drafts, behind a gateway that blocks raw identifiers. By default it's a local template, so it runs without any API key.

**"Could the AI accidentally see a customer's PAN?"**
The gateway rejects forbidden field names, scans every outgoing payload, blocks on any hit and logs the block (without the value). The privacy suite scans every log, table, export and API response for all 20,000 sandbox identifiers and finds 0, with a positive control proving the scanner works.

**"Can MALLYA fix things by itself?"**
No. Every action needs a recorded human approval. The worker checks the signed token itself, and each approval runs only once. Even presenter auto-approve is recorded as such and never touches held actions.

**"What stops someone editing the evidence afterwards?"**
The hash chain and the Ed25519 signature. Any edit, deletion, insertion or reordering fails verification, and the standalone script can be run by anyone.

**"Is 100% on the benchmark real?"**
The runs are real, but the same author wrote the tests and the system, so treat it as "consistent", not "proven in the real world". The earlier, lower runs are kept to show what was found and fixed.

**"Could a bank use this tomorrow?"**
No. It's a concept prototype. Section 34 lists what's missing.
