from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    app_env: str = "development"
    demo_mode: bool = True
    org_id: str = "meridian-bank"
    seed: int = 42
    database_url: str
    redis_url: str = "redis://redis:6379/0"
    secret_key: str
    worker_url: str = "http://worker:7100"
    worker_token: str
    approval_signing_key: str
    probe_gateway_url: str = "http://nginx:9100"
    probe_token: str
    cdn_admin_url: str = "http://cdn-admin:7000"
    cdn_admin_token: str
    mock_iam_url: str = "http://mock-iam:7000"
    mock_iam_token: str
    minio_audit_token: str
    evidence_signing_key_path: str = "/run/mallya-secrets/evidence_signing_key.pem"
    evidence_export_dir: str = "/exports"
    llm_provider: str = "local"
    llm_model: str = ""
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    groq_api_key: str = ""
    cors_origins: str = "http://localhost:3000"
    internal_cidrs: str = "172.28.0.0/24"
    session_hours: int = 12

    @property
    def is_dev(self) -> bool:
        return self.app_env == "development"


@lru_cache
def settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
