from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Settings:
    worker_token: str
    approval_signing_key: str
    fingerprint_key: str
    fingerprint_key_version: str
    meridian_db_url: str
    minio_endpoint: str
    minio_access_key: str
    minio_secret_key: str
    service_password: str
    cdn_internal_url: str
    cdn_admin_url: str
    cdn_admin_token: str
    mock_iam_url: str
    mock_iam_token: str
    mock_vendor_url: str
    mock_vendor_token: str
    infra_config_dir: str
    nginx_log_path: str
    seed: int


@lru_cache
def settings() -> Settings:
    e = os.environ
    return Settings(
        worker_token=e["WORKER_TOKEN"],
        approval_signing_key=e["APPROVAL_SIGNING_KEY"],
        fingerprint_key=e["FINGERPRINT_KEY"],
        fingerprint_key_version=e.get("FINGERPRINT_KEY_VERSION", "v1"),
        meridian_db_url=e["MERIDIAN_DB_URL"],
        minio_endpoint=e.get("MINIO_ENDPOINT", "minio:9000"),
        minio_access_key=e["MINIO_ACCESS_KEY"],
        minio_secret_key=e["MINIO_SECRET_KEY"],
        service_password=e["SANDBOX_SERVICE_PASSWORD"],
        cdn_internal_url=e.get("CDN_INTERNAL_URL", "http://cdn.meridian.sandbox:8080"),
        cdn_admin_url=e.get("CDN_ADMIN_URL", "http://cdn-admin:7000"),
        cdn_admin_token=e["CDN_ADMIN_TOKEN"],
        mock_iam_url=e.get("MOCK_IAM_URL", "http://mock-iam:7000"),
        mock_iam_token=e["MOCK_IAM_TOKEN"],
        mock_vendor_url=e.get("MOCK_VENDOR_URL", "http://mock-vendor:7000"),
        mock_vendor_token=e["MOCK_VENDOR_TOKEN"],
        infra_config_dir=e.get("INFRA_CONFIG_DIR", "/sandbox/infra-config"),
        nginx_log_path=e.get("NGINX_LOG_PATH", "/var/log/mallya/access.json"),
        seed=int(e.get("SEED", "42")),
    )
