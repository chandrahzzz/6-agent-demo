# Threat model (prototype scope)

| Threat | Mitigation in the prototype | Residual risk / production work |
|---|---|---|
| Raw identifiers leak to the LLM vendor | Worker-side detection; schema allow-list plus outbound DLP block; leak scan with a positive control | DLP covers PAN, Aadhaar, email and phone formats only; names are handled by schema (forbidden fields), not by detection |
| Agent or LLM triggers destructive change | Allow-listed action templates; human approval token verified by the worker; the LLM has no tool access | A compromised backend holding `APPROVAL_SIGNING_KEY` could mint tokens. Production needs approvals signed by the approver's own key (WebAuthn) |
| Verification fooled by transport failures | DNS failure, refused, timeout and 5xx are never "blocked"; only 401/403 counts, and the origin AccessDenied body is recorded | — |
| Verification creates the residual it measures | Probe and inspection requests carry headers nginx is configured never to cache | An attacker-controlled cache layer outside MALLYA's view would not be tested |
| Evidence tampering | Per-incident hash chain; Ed25519-signed manifest pins the chain head and file hashes; standalone verifier | Dev key is DEV-NON-PRODUCTION. Production needs HSM/KMS keys, external timestamping, and a trusted key registry |
| Verifier traffic mistaken for attacker traffic | Probes tagged with the run ID and excluded only when the ID was issued and the source IP is the verifier's | A spoofed header from the verifier's own IP would be excluded |
| Ground truth leaks into agents | Ground truth is not mounted in the worker; an AST import-boundary test covers agent packages | Process discipline; the boundary test checks imports and file references |
| Session theft | httpOnly cookie, hashed server-side, expiry | No MFA or SSO (out of scope) |
| Abuse of the internal webhook | Network restriction plus token | Single shared token |
