"""MinIO access for the customer side.

Bucket anonymous access is changed only through the real `mc` client
(`mc anonymous set download|none`), invoked with a fixed argument list (no shell). Each
call runs as a named sandbox principal via MC_HOST_<alias>, so MinIO's audit log records
who changed what.
"""
from __future__ import annotations

import io
import json
import os
import subprocess
from functools import lru_cache
from urllib.parse import quote

from minio import Minio

from .config import settings

BUCKETS = [
    "meridian-customer-backups",
    "meridian-backups-replica",
    "meridian-archive",
    "meridian-exports",
    "meridian-internal-docs",
]

# Sandbox principals backed by real MinIO users. Secrets derive from SANDBOX_SERVICE_PASSWORD.
PRINCIPALS = {
    "infra-sync": {
        "kind": "pipeline", "description": "Applies infra-config/buckets.yaml to object storage",
        "statements": [{"Effect": "Allow", "Action": ["s3:PutBucketPolicy", "s3:GetBucketPolicy", "s3:DeleteBucketPolicy",
                                                     "s3:GetBucketLocation", "s3:ListBucket"],
                        "Resource": ["arn:aws:s3:::meridian-*"]}],
    },
    "dev-rahul": {
        "kind": "human", "description": "Platform engineer (dev.rahul)",
        "statements": [{"Effect": "Allow", "Action": ["s3:PutBucketPolicy", "s3:GetBucketPolicy", "s3:DeleteBucketPolicy",
                                                     "s3:GetBucketLocation", "s3:ListBucket", "s3:ListAllMyBuckets"],
                        "Resource": ["arn:aws:s3:::meridian-*"]}],
    },
    "mallya-scanner": {
        "kind": "service", "description": "MALLYA customer-side worker (read-only inventory + scan)",
        "statements": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketPolicy",
                                                     "s3:GetBucketLocation", "s3:ListAllMyBuckets", "s3:GetBucketTagging",
                                                     "s3:GetEncryptionConfiguration", "s3:GetReplicationConfiguration"],
                        "Resource": ["arn:aws:s3:::*"]}],
    },
    "mallya-remediator": {
        "kind": "service", "description": "MALLYA remediation executor (runs only human-approved actions)",
        "statements": [{"Effect": "Allow", "Action": ["s3:PutBucketPolicy", "s3:GetBucketPolicy", "s3:DeleteBucketPolicy",
                                                     "s3:GetBucketLocation", "s3:ListBucket", "s3:DeleteObject",
                                                     "s3:GetObject", "s3:PutObject"],
                        "Resource": ["arn:aws:s3:::meridian-*"]}],
    },
    "finance-analyst": {
        "kind": "human", "description": "Finance analytics analyst (meera.s team)",
        "statements": [{"Effect": "Allow", "Action": ["s3:PutBucketPolicy", "s3:GetBucketPolicy", "s3:GetObject", "s3:PutObject",
                                                     "s3:ListBucket", "s3:GetBucketLocation"],
                        "Resource": ["arn:aws:s3:::meridian-exports", "arn:aws:s3:::meridian-exports/*"]}],
    },
    "reporting-service": {
        "kind": "service", "description": "Nightly regulatory reporting job (authorised consumer of backups)",
        "statements": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": ["arn:aws:s3:::meridian-customer-backups", "arn:aws:s3:::meridian-customer-backups/*"]}],
    },
}


def secret_for(principal: str) -> str:
    import hashlib
    return hashlib.sha256(f"{settings().service_password}:{principal}".encode()).hexdigest()[:32]


@lru_cache
def root() -> Minio:
    s = settings()
    return Minio(s.minio_endpoint, access_key=s.minio_access_key, secret_key=s.minio_secret_key, secure=False)


@lru_cache
def as_principal(principal: str) -> Minio:
    return Minio(settings().minio_endpoint, access_key=principal, secret_key=secret_for(principal), secure=False)


def _mc_env(alias: str, access_key: str, secret_key: str) -> dict:
    s = settings()
    env = dict(os.environ)
    env[f"MC_HOST_{alias}"] = f"http://{quote(access_key, safe='')}:{quote(secret_key, safe='')}@{s.minio_endpoint}"
    env["MC_CONFIG_DIR"] = "/tmp/.mc"
    return env


def mc(principal: str, *args: str) -> list[dict]:
    """Run `mc --json <args>` as a named principal ('root' = sandbox root). Fixed argv, no shell."""
    s = settings()
    if principal == "root":
        env = _mc_env("m", s.minio_access_key, s.minio_secret_key)
    else:
        env = _mc_env("m", principal, secret_for(principal))
    proc = subprocess.run(["mc", "--json", "--no-color", *args], env=env, capture_output=True, text=True, timeout=60)
    out = [json.loads(line) for line in proc.stdout.splitlines() if line.strip().startswith("{")]
    if proc.returncode != 0:
        msg = next((o.get("error", {}).get("message") for o in out if o.get("status") == "error"), proc.stderr.strip())
        raise RuntimeError(f"mc {args[0]} failed: {msg}")
    return out


def set_anonymous(principal: str, target: str, permission: str) -> None:
    """target is a bucket or bucket/prefix."""
    assert permission in ("download", "none")
    mc(principal, "anonymous", "set", permission, f"m/{target}")


def anonymous_rules(bucket: str) -> list[dict]:
    """Every anonymous grant on the bucket, including prefix-scoped ones (`mc anonymous list`).
    Returns [{"prefix": "" | "shared/", "allow": "readonly" | ...}]."""
    out = []
    for r in mc("mallya-scanner", "anonymous", "list", f"m/{bucket}"):
        res = r.get("resource", "")
        prefix = res[len(bucket):].lstrip("/").rstrip("*")
        out.append({"prefix": prefix, "allow": r.get("allow")})
    return out


def object_public(key: str, rules: list[dict]) -> bool:
    return any(r["allow"] in ("readonly", "readwrite", "download", "public") and key.startswith(r["prefix"]) for r in rules)


def get_anonymous(bucket: str) -> str:
    out = mc("mallya-scanner", "anonymous", "get", f"m/{bucket}")
    perm = (out[0].get("permission") if out else None) or "none"
    return "none" if perm == "private" else perm


def ensure_principals() -> None:
    for name, p in PRINCIPALS.items():
        policy = {"Version": "2012-10-17", "Statement": p["statements"]}
        path = f"/tmp/policy-{name}.json"
        with open(path, "w") as f:
            json.dump(policy, f)
        mc("root", "admin", "user", "add", "m", name, secret_for(name))
        mc("root", "admin", "policy", "create", "m", f"pol-{name}", path)
        try:
            mc("root", "admin", "policy", "attach", "m", f"pol-{name}", "--user", name)
        except RuntimeError as exc:  # already attached
            if "already" not in str(exc).lower():
                raise


def put_bytes(bucket: str, key: str, data: bytes, content_type: str = "text/csv") -> None:
    root().put_object(bucket, key, io.BytesIO(data), len(data), content_type=content_type)


def read_bytes(bucket: str, key: str, principal: str = "mallya-scanner") -> bytes:
    resp = as_principal(principal).get_object(bucket, key)
    try:
        return resp.read()
    finally:
        resp.close()
        resp.release_conn()


def wipe_bucket(bucket: str) -> None:
    c = root()
    if not c.bucket_exists(bucket):
        return
    for obj in c.list_objects(bucket, recursive=True):
        c.remove_object(bucket, obj.object_name)
    c.remove_bucket(bucket)
