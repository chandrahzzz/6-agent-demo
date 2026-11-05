#!/bin/sh
set -e
cd /app/backend
python -c "from app.evidence.signing import ensure_dev_key; import os; ensure_dev_key(os.environ['EVIDENCE_SIGNING_KEY_PATH'])"
alembic upgrade head
python -m app.seed_users
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload --reload-dir /app/backend/app --reload-dir /app/shared
