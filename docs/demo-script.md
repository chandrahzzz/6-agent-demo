# Demo script: 3 minutes (Devpost recording)

**Setup before recording:** stack running; signed in as `analyst@meridian.demo`; dark theme; browser at 1440×900; a clean tab on the Dashboard. Leave presenter auto-approve **off** so the approval is a real click on camera.

| Time | On screen | Say |
|---|---|---|
| 0:00 | Dashboard | "This is MALLYA. Most tools stop at 'you have a data exposure'. MALLYA finds out whether anyone actually took the data, fixes the cause, attacks its own fix, and proves it, without ever showing a raw customer identifier to its AI. Everything here is a local sandbox with synthetic data." |
| 0:15 | Click **Demo Mode** → **Reset sandbox and run** | "One click resets a fictional bank, Meridian, and plants a real incident: a config commit made the customer-backup bucket public." |
| 0:25 | Live run: Exposure Hunter completes | "The Exposure Hunter swept every bucket. Its detectors run on the customer side, and it rejected decoy SKUs and invoice numbers that only *look* like PANs. Two exposures: the backup and its replica." |
| 0:40 | Investigation completes → open incident → **Investigation & Root Cause** | "Was it taken? MALLYA correlated the CDN log with the storage audit log: **three anonymous attempts, no successful download**. A list, a wrong key and a HEAD, zero bytes of the file. Both log sources were covered, five of five origin hits matched. The root cause: commit 'share backups with vendor' by dev.rahul, applied by the sync pipeline. Here's the offending diff, and here's MALLYA's patch." |
| 1:05 | **Asset Graph** | "Blast radius, by keyed fingerprint: **5,000 records**, and **306 had withdrawn marketing consent**. The same records are also in the archive. The CDN cache is marked *unverified*, because this agent can't see inside it." |
| 1:20 | **Remediation** | "Every action shows its risk, rollback and verification requirement. Note this one is **held**: the safety check found the Northwind partner reads the replica anonymously, so it proposes a presigned link instead of breaking them. I approve the rest." Select pending → **Approve** → **Execute approved** |
| 1:40 | **Verification** (VER-1) | "Now the important part. A separate verifier, outside the bank's network, attacks the fix like an attacker would. The origin now returns 403. But the CDN still serves the backup from cache: **200, cache HIT**. And the replica is still open. Verdict: **PARTIALLY FIXED**. A permission checker would have said 'fixed'." |
| 2:05 | **Remediation** → wave 2 | "MALLYA re-plans from that evidence: hand the partner a presigned link, close the replica, purge the cache. The held action needs an override with a reason." Approve with reason → Execute |
| 2:25 | **Verification** (VER-2) | "Second attack: every path returns a genuine 403, every copy is accounted for, and the legitimate reporting service still gets 200. **Verified fixed**." |
| 2:40 | **Evidence Vault** → **Verify now** | "Every step went into a hash chain, signed with Ed25519. Anyone can check it with one standalone script: five checks pass. Edit one record and it fails." |
| 2:50 | Privacy Boundary | "And across all of that: **zero raw identifiers sent to the AI**. That's computed from audited calls, backed by a leak scan of every log, table and export. Detect, investigate, remediate, prove." |

**Timings:** read them from the incident's Overview → *Measured timings*. Quote the measured numbers, not round ones.
