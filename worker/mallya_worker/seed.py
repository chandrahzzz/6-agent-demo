"""Deterministic baseline for the Meridian Bank sandbox (`make seed` / `make reset-demo`).

Everything is rebuilt from SEED: customers, decoys, buckets/objects, MinIO principals,
infra-config git history, IAM registry and vendor state. All buckets start private.
"""
from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta, timezone

from minio.commonconfig import Tags

from . import infra, meridian, scan, storage, synth
from .clients import cdn_admin, iam, vendor

BACKUP_KEY = "backups/2026-11-04/customers_full.csv"
ARCHIVE_KEY = "archive/2026-10/customers_full_2026-10-01.csv"
CANARY_KEY = "_mallya_canary/canary.txt"

NETWORKS = [
    {"cidr": "172.28.0.21/32", "label": "cdn-admin edge prefetch job", "zone": "internal", "role": "infrastructure"},
    {"cidr": "172.28.0.23/32", "label": "Northwind Analytics connector (partner)", "zone": "partner"},
    {"cidr": "172.28.0.30/32", "label": "MALLYA customer-side worker", "zone": "internal", "role": "security"},
    {"cidr": "172.29.0.77/32", "label": "MALLYA external verifier probe", "zone": "probe", "role": "security"},
    {"cidr": "172.28.0.99/32", "label": "reporting-service host", "zone": "internal"},
    {"cidr": "172.28.0.0/24", "label": "Meridian customer network", "zone": "internal"},
]


def canary_body(bucket: str, seed: int) -> bytes:
    token = hashlib.sha256(f"canary:{bucket}:{seed}".encode()).hexdigest()[:24]
    return f"MALLYA-CANARY bucket={bucket} token={token}\nThis object contains no customer data.\n".encode()


def _register_iam(now: datetime) -> None:
    iam("POST", "/reset")
    for name, p in storage.PRINCIPALS.items():
        perms = []
        for st in p["statements"]:
            for res in st["Resource"]:
                b = res.removeprefix("arn:aws:s3:::").split("/")[0]
                if b != "*":
                    perms.append({"bucket": b, "actions": st["Action"]})
        body = {"name": name, "kind": p["kind"], "description": p["description"], "access_key": name,
                "permissions": perms, "approved": True,
                "credential_expires_at": (now + timedelta(days=90)).isoformat()}
        if name == "reporting-service":
            body["secret_key"] = storage.secret_for(name)  # mock IAM may mint presigned URLs for it
        iam("PUT", f"/principals/{name}", json=body)
    iam("PUT", "/principals/northwind-analytics", json={
        "name": "northwind-analytics", "kind": "partner", "description": "Marketing analytics vendor (Northwind)",
        "permissions": [], "approved": True, "source_ips": ["172.28.0.23"],
        "credential_expires_at": (now + timedelta(days=45)).isoformat()})
    iam("PUT", "/networks", json=NETWORKS)


def seed(seed_value: int) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    r = random.Random(f"seed-{seed_value}")
    people = synth.customers(seed_value)

    # 1. customer-side database
    meridian.reset_schema()
    meridian.load_customers(people, scan.fp())
    qa = random.Random(f"qa-{seed_value}")
    meridian.execute("INSERT INTO qa_fixture_cases VALUES " + ",".join(
        f"('TC-{i:04d}', '{synth.synthetic_pan(qa, 'Q')}', 'pass')" for i in range(1, 121)))
    meridian.execute("""INSERT INTO ropa_entries VALUES
      ('ROPA-001','Core banking','Account servicing','contract'),
      ('ROPA-002','Marketing campaigns','Direct marketing','consent'),
      ('ROPA-003','Regulatory reporting','Statutory reporting','legal_obligation')""")
    meridian.execute("""INSERT INTO integration_registry VALUES
      ('INT-NW','Northwind Analytics','Marketing campaign analytics','http://mock-vendor:7000/northwind/v1',
        TRUE, FALSE, 'email,phone', 'contacts:write', 'contacts:write', :nw_exp, 'ROPA-002'),
      ('INT-MAIL','Acme Mailer','Transactional email','http://mock-vendor:7000/acme/v1',
        TRUE, FALSE, 'email', 'send:write', 'send:write', :mail_exp, 'ROPA-001')""",
                     nw_exp=now + timedelta(days=45), mail_exp=now + timedelta(days=200))
    meridian.execute("""INSERT INTO integration_jobs VALUES
      ('JOB-NW-SYNC','INT-NW','marketing_campaign_members', FALSE, NULL, FALSE)""")
    scan.index(refresh=True)

    # 2. object storage
    storage.ensure_principals()
    c = storage.root()
    for b in storage.BUCKETS:
        storage.wipe_bucket(b)
        c.make_bucket(b)
        storage.put_bytes(b, CANARY_KEY, canary_body(b, seed_value), "text/plain")
    backup = synth.customers_csv(people)
    storage.put_bytes("meridian-customer-backups", BACKUP_KEY, backup)
    storage.put_bytes("meridian-backups-replica", BACKUP_KEY, backup)  # replication target
    storage.put_bytes("meridian-archive", ARCHIVE_KEY, synth.customers_csv(people[:4870]))
    storage.put_bytes("meridian-exports", "finance/monthly-summary-2026-10.csv",
                      b"segment,accounts,avg_balance_inr\nretail,3120,84210\npremium,850,912400\nsme,610,402300\nnri,420,301900\n")
    storage.put_bytes("meridian-exports", "catalog/products.csv", synth.products_csv(seed_value))  # DECOY
    storage.put_bytes("meridian-exports", "finance/invoices-2026-q3.csv", synth.invoices_csv(seed_value))  # DECOY
    for i, title in enumerate(["Platform operating rhythm", "On-call handbook", "Capacity plan FY27", "Vendor review checklist",
                               "Branch IT refresh", "Incident retro template", "Data platform roadmap", "Office network map",
                               "Laptop policy", "Release calendar", "DR test summary", "Quarterly OKRs"]):
        storage.put_bytes("meridian-internal-docs", f"docs/{i + 1:02d}-{title.lower().replace(' ', '-')}.md",
                          synth.harmless_doc(r, title), "text/markdown")
    for b in storage.BUCKETS:
        tags = Tags.new_bucket_tags()
        tags["classification"] = {"meridian-internal-docs": "internal", "meridian-exports": "confidential"}.get(b, "pii")
        c.set_bucket_tags(b, tags)

    # 3. infra-config git history + full apply (everything private)
    infra.init_history(now)
    for b in storage.BUCKETS:
        storage.set_anonymous("infra-sync", b, "none")

    # 4. IAM registry, vendor state, CDN cache
    _register_iam(now)
    vendor("POST", "/admin/reset")
    cdn_admin("POST", "/purge", params={"key": "/"})
    return {"seed": seed_value, "customers": len(people), "buckets": storage.BUCKETS, "at": now.isoformat()}


def synthetic_history(seed_value: int, now: datetime | None = None) -> list[dict]:
    """Access history for the 7 days BEFORE a scenario starts. Always labelled synthetic_history."""
    now = now or datetime.now(timezone.utc)
    r = random.Random(f"history-{seed_value}")
    out = []
    for d in range(7, 0, -1):
        ts = (now - timedelta(days=d)).replace(hour=1, minute=r.randrange(0, 50), second=r.randrange(0, 59), microsecond=0)
        out.append({"source": "minio_audit", "ts": ts.isoformat(), "bucket": "meridian-customer-backups",
                    "object_key": BACKUP_KEY, "api": "GetObject", "method": "GET", "status": 200,
                    "bytes": 612000 + r.randrange(0, 4000), "remote_ip": "172.28.0.99", "principal": "reporting-service",
                    "user_agent": "reporting-service/4.1", "synthetic_history": True})
    return out
