# Setup

1. **Install prerequisites:** Docker Desktop with Compose v2, and Python 3.10+ on the host (stdlib only, for `tools/gen_env.py` and `tools/privacy_suite.py`).
2. **Generate secrets:** `python tools/gen_env.py` writes `.env` with random values. Fingerprint key, approval key, session secret and service tokens are all separate.
3. **Start everything:** `docker compose up -d --build` (or `make dev`, or `./mallya.ps1 dev` on Windows). The backend container then:
   - generates the dev Ed25519 key in a secrets volume (first start only);
   - runs Alembic migrations;
   - seeds the four demo users.
4. **Seed the sandbox:** `make reset-demo`. It rebuilds the customers, buckets, git history, IAM registry, vendor state and CDN cache from `SEED`. Every drill also resets automatically.
5. **Open the console:** http://localhost:3100 and sign in as `analyst@meridian.demo` with password `mallya-demo-2026` (demo-only).

## Ports (bound to 127.0.0.1)
| Port | Service |
|---|---|
| 3100 | Console (`FRONTEND_PORT`) |
| 8000 | API |
| 8080 | Public CDN edge, for manual poking |

## Images
- One shared Python 3.12 image serves every Python service.
- `bitnamilegacy/minio:2025.7.23` is used because the Docker Hub and Quay MinIO images can no longer be pulled anonymously.
- `postgres:16-alpine`, `redis:7-alpine`, `nginx:1.27-alpine`, `node:22-alpine`.

## Running tests
```bash
docker compose exec backend sh -c "cd /app/backend && python -m pytest -q -m 'not e2e'"   # unit, boundary, privacy, tamper
docker compose exec backend sh -c "cd /app/backend && python -m pytest -q -m e2e"         # all scenarios (~10 min)
docker compose exec worker  sh -c "cd /app/worker && python -m pytest -q"                 # worker incl. live policy-gate test
python tools/privacy_suite.py                                                             # 13 privacy tests + leak scan
docker compose exec backend sh -c "cd /app && python -m benchmark.evaluation.run --mode all"
```
