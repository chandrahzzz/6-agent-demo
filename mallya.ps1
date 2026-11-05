# MALLYA task runner for Windows (mirrors the Makefile targets).
# Usage: ./mallya.ps1 dev | seed | reset-demo | test | test-unit | test-e2e | test-privacy | benchmark | down | logs
param([Parameter(Position = 0)][string]$Target = "help")
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function BE([string]$cmd) { docker compose exec -T backend sh -c $cmd; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }

switch ($Target) {
  "install" { python tools/gen_env.py; docker compose build }
  "dev" {
    python tools/gen_env.py
    docker compose up -d --build
    Write-Host "MALLYA: http://localhost:3000   API: http://localhost:8000/docs"
  }
  "down" { docker compose down }
  "migrate" { BE "cd /app/backend && alembic upgrade head" }
  { $_ -in "seed", "reset-demo" } {
    BE "cd /app/backend && python -c 'from app.drills.engine import reset_sandbox; from app.core.config import settings; print(reset_sandbox(settings().seed))'"
  }
  "test-unit" {
    BE "cd /app/backend && python -m pytest -q -m 'not e2e'"
    docker compose exec -T worker sh -c "cd /app/worker && python -m pytest -q"
  }
  "test-e2e" { BE "cd /app/backend && python -m pytest -q -m e2e" }
  "test-privacy" { python tools/privacy_suite.py }
  "test" { & $PSCommandPath test-unit; & $PSCommandPath test-e2e; & $PSCommandPath test-privacy }
  "benchmark" { BE "cd /app && python -m benchmark.evaluation.run --mode all" }
  "logs" { docker compose logs -f --tail 100 }
  default { Get-Content $PSCommandPath | Select-Object -First 3 }
}
