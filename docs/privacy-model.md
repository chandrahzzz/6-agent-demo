# Privacy model: zero raw identifiers to the AI

## Where raw values exist
Raw identifiers exist in only two places:
- the Meridian customer database;
- the sandbox's object storage and vendor mocks.

Only the **customer-side worker** reads them. It runs detectors, validates them (holder type, Verhoeff, column context), masks, fingerprints, and returns metadata only. Raw values never leave the worker. They don't appear in logs, traces, errors, control-plane tables, exports or LLM payloads.

## Detectors (`shared/mallya_common/detectors.py`)
- **PAN:** `^[A-Z]{5}[0-9]{4}[A-Z]$`, then the 4th-character holder type, then column context.
  - Outcomes: FORMAT_MATCH, STRUCTURAL_MATCH, CONFIRMED_SYNTHETIC_TEST_VALUE.
  - A pattern match is never a claim that a value is a real PAN.
- **Aadhaar:** 12 digits, first digit not 0 or 1, Verhoeff checksum. A passing checksum does not mean the number was ever issued.
- **Email and phone:** standard deterministic detectors.
- **Decoys present in every run:**
  - product SKUs shaped like PANs (FORMAT_MATCH, context 0.0);
  - 12-digit invoice numbers that fail Verhoeff;
  - a QA fixture table whose PAN-shaped labels are structurally valid but rejected by context.

## Fingerprints
- HMAC-SHA-256 with a versioned key (`FINGERPRINT_KEY`).
- The key exists only in the worker's environment, never in a database.
- Values are normalised before hashing.
- Stored as `HMAC-SHA256:v1:<hex>`. There are no plain hashes.

## LLM privacy gateway (`backend/app/privacy/gateway.py`)
Every model call, including the default local template provider, goes through four steps:
1. **Schema validation.** Only allow-listed metadata fields; forbidden field names (`rows`, `email`, `pan`, …) are rejected.
2. **Deterministic outbound DLP.** Checks for unmasked PAN candidates, Verhoeff-valid Aadhaar candidates, full emails and full phone numbers.
3. **Block on any hit.** The payload doesn't leave. A `PrivacyPolicyViolation` is recorded with detector types, counts and field paths only, never the value.
4. **Audit.** Every allowed call records exactly which field paths were shared (`llm_calls.shared_fields`).

The headline "0 raw identifiers sent to the AI" is computed from those audit records. It is not a constant.

## Proving it: `tools/privacy_suite.py`
- **10 unit tests:** detection, structure, Verhoeff, decoys, masking, fingerprint match and uniqueness, gateway blocking of PAN, Aadhaar, emails, phones and forbidden fields.
- **3 leak scans:**
  - The host collects all container logs, a full dump of the control-plane database, telemetry tables, every evidence pack (PDF streams decompressed) and the API responses for every incident.
  - It pipes them as a tar into the worker, which counts occurrences of the sandbox's 20,000 real raw identifiers.
  - A **positive control** plants one real identifier of each kind and must detect all four, otherwise the suite fails.

Latest result: 13/13. See [PROGRESS.md](../PROGRESS.md).
