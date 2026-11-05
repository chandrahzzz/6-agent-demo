# MALLYA — make targets (Windows without make: use ./mallya.ps1 <target>)
DC = docker compose
BE = $(DC) exec -T backend sh -c
.PHONY: install dev up down migrate seed reset-demo test test-unit test-e2e test-privacy benchmark lint build logs

install:            ## generate .env with random secrets and build images
	python tools/gen_env.py
	$(DC) build

dev: install        ## start the full stack (sandbox + control plane + frontend)
	$(DC) up -d
	@echo "MALLYA: http://localhost:3000   API: http://localhost:8000/docs"

down:
	$(DC) down

migrate:
	$(BE) "cd /app/backend && alembic upgrade head"

seed:               ## deterministic sandbox seed (SEED from .env)
	$(BE) "cd /app/backend && python -c 'from app.drills.engine import reset_sandbox; from app.core.config import settings; print(reset_sandbox(settings().seed))'"

reset-demo: seed    ## clean demo state (same as seed: sandbox + incident data rebuilt)

test: test-unit test-e2e test-privacy

test-unit:
	$(BE) "cd /app/backend && python -m pytest -q -m 'not e2e'"
	$(DC) exec -T worker sh -c "cd /app/worker && python -m pytest -q"

test-e2e:
	$(BE) "cd /app/backend && python -m pytest -q -m e2e"

test-privacy:
	python tools/privacy_suite.py

benchmark:
	$(BE) "cd /app && python -m benchmark.evaluation.run --mode all"

lint:
	$(BE) "cd /app/backend && python -m compileall -q app"
	$(DC) exec -T frontend npm run lint

build:
	$(DC) build

logs:
	$(DC) logs -f --tail 100
