# Known limitations (honest list)

- **Sandbox only.** Single fictional tenant, synthetic data, local containers. There are no real cloud accounts, no SSO and no multi-tenancy (an `org_id` column exists for later). Not production-ready.
- **MinIO "download" policy includes ListBucket.** The spec expected variant A's anonymous LIST to return 403/404. Real MinIO returns 200 with key names (no object bytes). MALLYA reports what really happens and counts it as an attempt.
- **Blast radius does not inspect the CDN cache.** It models the CDN as a path and marks it UNVERIFIED. Cached copies are found by adversarial verification. This is a deliberate split of duties, and it is one reason the first HERO-01 verification is PARTIALLY_FIXED.
- **Log-bounded verdicts.** Access verdicts see only the CDN access log, the MinIO audit webhook and vendor call logs. When a source has gaps, the verdict is INSUFFICIENT_EVIDENCE.
- **Known locations only.** The fingerprint search covers locations in MALLYA's inventory. Copies elsewhere (laptops, email) cannot be ruled out.
- **No encryption at rest in the sandbox.** MinIO runs without a KMS. UNENCRYPTED-STORAGE is a real finding on a bucket that declares SSE. Base buckets declare `platform-disk` (out of MALLYA's view).
- **Lite scenarios are not remediated live.** They produce a verdict and a recommendation only.
- **Vendor mocks.** Third-party deletion is a mock API call. A real vendor's deletion can't be proven by re-querying alone. The shadow-AI fix blocks the vendor in the registry rather than at a network egress proxy.
- **EXPOSED-POSTGRES** is modelled as a login role with a default credential. The database is not reachable from external_net (the verifier's self-test proves that).
- **Benchmark.**
  - The same author wrote the scenarios, the ground-truth generator and the detectors.
  - Bucket names are fixed; variants change access, cache and replica layout, record counts and samples.
  - The held-out set is small (9 runs).
  - The LLM-assisted comparison needs an API key and is reported as not run without one.
- **Approval signing.** Approval tokens are signed by the control plane on behalf of the logged-in user, not by the approver's own device key.
- **Dev signing key.** The evidence key is a development key labelled DEV-NON-PRODUCTION.
- **Dev servers.** The frontend runs `next dev` (webpack, polling) for Windows bind-mount compatibility. A production build is not wired into compose.
