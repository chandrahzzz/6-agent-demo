"""Scenario plants (customer side). Each function changes REAL sandbox state.

Setup returns a harness record for the drill engine (never shown to agents). Hidden ground
truth is produced separately by the benchmark harness, never by this module.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from . import checks, infra, meridian, scan, storage, synth
from .clients import cdn_admin, iam, vendor
from .config import settings
from .seed import BACKUP_KEY

CDN = "http://cdn.meridian.sandbox:8080"


def _people():
    return synth.customers(settings().seed)


def hero01_setup(params: dict) -> dict:
    """HERO-01 PUBLIC-BACKUP.

    1. dev.rahul commits "share backups with vendor" (primary public: true); infra-sync applies it.
    2. dev.rahul opens the replica by hand for Northwind's pull (out-of-band drift; not in buckets.yaml).
    3. The edge prefetch job warms the CDN with the backup file.
    4. Northwind pulls the replica through the CDN (real partner traffic).
    The attacker's variant A/B traffic is driven by the drill engine afterwards.
    """
    now = datetime.now(timezone.utc).replace(microsecond=0)
    primary = params.get("primary_bucket", "meridian-customer-backups")
    replica = params.get("replica_bucket", "meridian-backups-replica")
    key = params.get("object_key", BACKUP_KEY)
    sha = infra.commit(infra.AUTHORS["rahul"], now - timedelta(minutes=47), "share backups with vendor",
                       {"buckets.yaml": infra.set_public(primary, True)})
    sync = infra.sync("infra-sync")
    log = {"commit": sha, "sync": sync}
    if params.get("replica_public", True):
        storage.set_anonymous("dev-rahul", replica, "download")
        iam("POST", "/events", json={"type": "BucketPolicyChanged", "principal": "dev-rahul", "target": replica,
                                     "details": {"anonymous": "download", "via": "manual mc command (out-of-band)"}})
        log["replica"] = "public (manual)"
    if params.get("cdn_cached", True):
        log["prefetch"] = cdn_admin("POST", "/prefetch", params={"path": f"/{primary}/{key}"})
    if params.get("replica_public", True) and params.get("vendor_pull", True):
        log["vendor_pull"] = vendor("POST", "/admin/simulate-pull", json={"url": f"{CDN}/{replica}/{key}"})
    log["attack_targets"] = [{"bucket": primary, "key": key}]
    return log


def d02_setup(params: dict) -> dict:
    """D-02 PUBLIC-S3-BUCKET: internal-docs made public by a config commit; a few docs carry identifiers."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    r = random.Random(f"d02-{params.get('variant_seed', 0)}")
    people = _people()
    n_sensitive = int(params.get("n_sensitive", 3))
    docs = [("kyc/exceptions-2026-q3.md", "KYC exception register"), ("ops/escalations-export.md", "Escalations export"),
            ("support/callback-list.md", "Callback list"), ("risk/watchlist-review.md", "Watchlist review")][:n_sensitive]
    planted = []
    for key, title in docs:
        sample = r.sample(people, int(params.get("rows_per_doc", 25)))
        lines = [f"# {title}", "", "Internal working notes. Do not distribute.", ""]
        for c in sample:
            lines.append(f"- {c.customer_id}: PAN {c.pan}, Aadhaar {c.aadhaar[:4]} {c.aadhaar[4:8]} {c.aadhaar[8:]}, email {c.email}")
        storage.put_bytes("meridian-internal-docs", key, ("\n".join(lines) + "\n").encode(), "text/markdown")
        planted.append(key)
    text = infra.set_public("meridian-internal-docs", True)
    sha = infra.commit(infra.AUTHORS["meera"], now - timedelta(minutes=33), "open internal docs for contractor onboarding",
                       {"buckets.yaml": text})
    sync = infra.sync("infra-sync")
    return {"commit": sha, "sync": sync, "sensitive_objects": planted,
            "attack_targets": [{"bucket": "meridian-internal-docs", "key": planted[0]}]}


def d03_setup(params: dict) -> dict:
    """D-03 SENSITIVE-EXPORT: a CSV export with identifiers behind a public (prefix-scoped) link."""
    people = _people()
    lo, hi = int(params.get("start", 1000)), int(params.get("start", 1000)) + int(params.get("rows", 800))
    rows = people[lo:hi]  # all of these are also in the October archive (first 4,870 customers)
    key = params.get("key", "shared/customer-export-2026-11-04.csv")
    storage.put_bytes("meridian-exports", key,
                      synth.customers_csv(rows, ["customer_id", "full_name", "pan", "email", "phone", "segment"]))
    storage.set_anonymous("finance-analyst", "meridian-exports/" + key.split("/")[0], "download")
    iam("POST", "/events", json={"type": "BucketPolicyChanged", "principal": "finance-analyst",
                                 "target": "meridian-exports/" + key.split("/")[0],
                                 "details": {"anonymous": "download", "via": "public link created by analyst (prefix grant)"}})
    return {"export_key": key, "rows": len(rows), "attack_targets": [{"bucket": "meridian-exports", "key": key}]}


def d04_setup(params: dict) -> dict:
    """D-04 CONSENT-WITHDRAWAL-MISMATCH: campaign members incl. withdrawn consent synced to Northwind."""
    people = _people()
    r = random.Random(f"d04-{params.get('variant_seed', 0)}")
    members = r.sample(people, int(params.get("members", 1200)))
    meridian.execute("INSERT INTO marketing_campaign_members VALUES " + ",".join(
        f"('CMP-DIWALI-26', '{c.customer_id}', '{c.email}', '{c.phone}', now())" for c in members))
    meridian.execute("UPDATE integration_jobs SET enabled = TRUE, filter_withdrawn_consent = FALSE WHERE job_id = 'JOB-NW-SYNC'")
    iam("POST", "/events", json={"type": "IntegrationJobChanged", "principal": "meera.s", "target": "JOB-NW-SYNC",
                                 "details": {"enabled": True, "filter_withdrawn_consent": False, "via": "integration console"}})
    run = checks.run_sync("JOB-NW-SYNC")
    return {"members": len(members), "sync": run, "attack_targets": []}


def d05_setup(params: dict) -> dict:
    """D-05 SHADOW-AI-UPLOAD: an employee uploads a customer file to an unapproved AI tool."""
    people = _people()
    r = random.Random(f"d05-{params.get('variant_seed', 0)}")
    rows = r.sample(people, int(params.get("rows", 150)))
    content = synth.customers_csv(rows, ["customer_id", "full_name", "pan", "phone", "email"]).decode()
    vendor("PUT", "/quicksummarize/v1/account/training", params={"opt_in": bool(params.get("training", False))})
    iam("PUT", "/principals/arjun.k", json={"name": "arjun.k", "kind": "human", "description": "Credit operations analyst",
                                            "permissions": [], "approved": True})
    import httpx
    s = settings()
    res = httpx.post(f"{s.mock_vendor_url}/quicksummarize/v1/upload", timeout=20,
                     headers={"X-Api-Key-Id": "qs-personal-key/arjun.k"},
                     json={"filename": params.get("filename", "loan-review-batch-17.csv"), "content": content}).json()
    scan.index()
    return {"upload": res, "rows": len(rows), "attack_targets": []}


SETUP = {"HERO-01": hero01_setup, "D-02": d02_setup, "D-03": d03_setup, "D-04": d04_setup, "D-05": d05_setup}
