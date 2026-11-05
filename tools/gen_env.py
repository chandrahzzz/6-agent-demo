#!/usr/bin/env python3
"""Write a .env with fresh random secrets from .env.example (stdlib only).

Existing .env is never overwritten unless --force is given.
"""
from __future__ import annotations

import pathlib
import secrets
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RANDOM_KEYS = {
    "POSTGRES_PASSWORD", "MALLYA_DB_PASSWORD", "MERIDIAN_DB_PASSWORD",
    "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY", "MINIO_AUDIT_TOKEN", "SANDBOX_SERVICE_PASSWORD",
    "SECRET_KEY", "FINGERPRINT_KEY", "APPROVAL_SIGNING_KEY",
    "WORKER_TOKEN", "PROBE_TOKEN", "CDN_ADMIN_TOKEN", "MOCK_IAM_TOKEN", "MOCK_VENDOR_TOKEN",
}


def main() -> int:
    target = ROOT / ".env"
    if target.exists() and "--force" not in sys.argv:
        print(".env already exists (use --force to regenerate)")
        return 0
    out: list[str] = []
    values: dict[str, str] = {}
    for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, _ = line.split("=", 1)
            key = key.strip()
            if key in RANDOM_KEYS:
                val = ("mallya" + secrets.token_hex(6)) if key == "MINIO_ACCESS_KEY" else secrets.token_urlsafe(32)
                values[key] = val
                line = f"{key}={val}"
        out.append(line)
    text = "\n".join(out) + "\n"
    text = text.replace(
        "DATABASE_URL=postgresql+psycopg://mallya_app:change-me@",
        f"DATABASE_URL=postgresql+psycopg://mallya_app:{values['MALLYA_DB_PASSWORD']}@",
    )
    target.write_text(text, encoding="utf-8")
    print("wrote .env with fresh random secrets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
