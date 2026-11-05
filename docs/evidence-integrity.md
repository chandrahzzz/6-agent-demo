# Evidence integrity

Evidence packs are **cryptographically tamper-evident and audit-oriented.** They are not a statement of legal admissibility or regulatory compliance.

## Hash chain (per incident)
```
payload_hash = SHA256(canonical(payload))
event_hash   = SHA256(canonical({metadata, payload_hash, previous_event_hash}))
metadata     = {incident_id, seq, ts, event_type, actor}      genesis previous hash = 64 zeros
canonical    = JSON, sorted keys, UTF-8, no insignificant whitespace
```
Appends are serialised per incident with a Postgres advisory lock. An insertion, deletion, reordering or edit breaks a link.

## Signing
- **Algorithm:** Ed25519 over the canonical bytes of `manifest.json`.
- **Key storage:** the private key lives at `EVIDENCE_SIGNING_KEY_PATH` in a secrets volume. It never touches the database, the browser or git.
- **Dev key:** generated on first start and labelled `DEV-NON-PRODUCTION`.
- **Key IDs** are versioned (`<label>-v1-<fingerprint>`), so keys can be rotated. The public key ships inside each pack.
- **The manifest pins** the chain's event count and head hash, and the SHA-256 of every file.

## Pack contents
| File | Purpose |
|---|---|
| `manifest.json` | **Authoritative.** The full incident record (verdicts, root cause, blast radius, asset graph, actions, approvals, verification requests/responses, copy hunt, unverified locations, limitations, drafts, agent history, final status), plus file hashes and the chain head. |
| `manifest.sig`, `public_key.pem` | Ed25519 signature and verification key |
| `events.jsonl` | The hash-chained events |
| `report.pdf`, `timeline.csv` | Human-readable views |
| `checksums.sha256` | SHA-256 of every other file |

## Verifying
```bash
python tools/mallya_verify.py mallya-evidence-INC-2026-0001-....zip [--pubkey trusted.pem]
```
The verifier prints PASS/FAIL for five checks: checksums, manifest-files, hash-chain, chain-head and signature. It needs only the standard library plus `cryptography`. The console's **Verify now** button runs the same script.

**Tamper tests** (`backend/tests/test_evidence_tamper.py`, 9 passing):
- an edited event, a deleted event, reordered events, an inserted event;
- a fully re-hashed chain: internally consistent, but rejected because the signed head no longer matches;
- an edited manifest;
- an attacker re-signing with their own key, rejected against a trusted key.

All of these FAIL verification.
