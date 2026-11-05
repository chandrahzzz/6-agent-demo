# API (`/api/v1`)

The live OpenAPI is at `http://localhost:8000/docs`. Authentication uses the session cookie from `POST /auth/login`.

**Errors** always look like this:
```json
{"error": {"code": "...", "message": "...", "details": {}}}
```
**Lists** are paginated with `?page=&page_size=` and return:
```json
{"items": [], "page": 1, "page_size": 50, "total": 0}
```

| Area | Endpoints |
|---|---|
| Auth | `POST /auth/login`, `POST /auth/logout`, `GET /auth/me` |
| Health | `GET /health` |
| Dashboard | `GET /dashboard` |
| Incidents | `GET /incidents`, `GET /incidents/{id}`, `GET /incidents/{id}/findings`, `/investigation`, `/blast-radius`, `/remediation`, `/verification`, `/evidence`, `/timeline`, `/drafts`, `/agents`, `/events` (SSE); `POST /incidents/{id}/remediation/execute`, `/obligations`, `/close` (409 unless the latest verification is VERIFIED_FIXED) |
| Approvals | `POST /approvals` `{action_ids, decision, reason, override_hold}` (SECURITY_ANALYST or ADMIN) |
| Verification | `POST /verification/{incident_id}/run` |
| Evidence | `GET /evidence`, `POST /evidence/{incident_id}/build`, `GET /evidence/packs/{id}/verify`, `/download`, `/file/{name}` |
| Assets | `GET /assets`, `GET /assets/relationships`, `GET /connectors` |
| Scenarios and drills | `GET /scenarios`, `POST /drills`, `GET /drills`, `GET /drills/{id}`, `GET /drills/{id}/events` (SSE), `/event-log`, `POST /drills/reset`, `POST /demo/start` |
| Benchmarks | `POST /benchmarks/run`, `GET /benchmarks`, `GET /benchmarks/{id}`, `GET /benchmarks/{id}/export.{csv,json,pdf}` |
| Agents | `GET /agents`, `GET /agents/executions` |
| Privacy | `GET /privacy/summary`, `/tests`, `/violations`, `/llm-calls`; `POST /privacy/tests` (ADMIN, used by the suite) |
| Audit and settings | `GET /audit-logs`, `GET /settings`, `PUT /settings/regulatory-context` |
| Internal | `POST /internal/minio-audit` (customer_net only, token) |
