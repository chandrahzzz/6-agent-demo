# Security model (MALLYA itself)

| Control | Implementation |
|---|---|
| Roles | ADMIN, SECURITY_ANALYST (approves remediation), IMPLEMENTATION_ENGINEER (runs drills, executes approved actions), VIEWER (read-only), enforced on every endpoint |
| Passwords | Argon2id (`argon2-cffi`) |
| Sessions | Opaque random token in an `httpOnly`, `SameSite=Lax` cookie (`Secure` outside development). Only its SHA-256 is stored. 12-hour expiry. |
| CORS | Restricted to the console origin. The console calls the API same-origin through Next.js rewrites. |
| Input validation | Pydantic schemas with length and pattern limits. Validation errors never echo submitted values. |
| Rate limiting | Token buckets on login (10/min) and on action endpoints |
| Approvals | A human approval is recorded per action with an HMAC-signed token bound to the action type and a SHA-256 of its parameters. The worker re-verifies it, refuses mismatched or forged tokens, and executes each approval once (replays return the stored result). |
| Held actions | Actions held by the safety check can't be approved without `override_hold` and a written reason, which is recorded in the evidence chain |
| No arbitrary execution | Agents choose from allow-listed action templates with fixed argv (`mc`, `git`). There is no shell, SQL or URL input from agents or the LLM. |
| LLM | Never initiates actions. Only phrases summaries and drafts, behind the privacy gateway. |
| Secrets | Read only from environment variables or files. `.env` is generated with random values and gitignored. The signing key lives in a secrets volume. |
| Network | `/internal/minio-audit` accepts only customer_net (excluding the docker gateway), plus a token. The probes sit on external_net only. Host ports bind to 127.0.0.1. |
| Audit | `audit_logs` records logins, failed logins, approvals, executions, drills, settings changes and closures. The evidence chain records every incident step. |
| Closing an incident | Enforced in the backend: it returns 409 unless the latest verification is VERIFIED_FIXED |
| Demo credentials | Labelled demo-only on the sign-in page and in the README |
