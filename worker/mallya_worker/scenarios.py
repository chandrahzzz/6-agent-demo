"""Scenario plants (customer side). Each function changes REAL sandbox state.

Setup returns a harness record for the drill engine (never shown to agents). Hidden ground
truth is produced separately by benchmark/ and never by this module.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from . import infra, storage
from .clients import cdn_admin, iam, vendor
from .seed import BACKUP_KEY

CDN = "http://cdn.meridian.sandbox:8080"


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


SETUP = {"HERO-01": hero01_setup}
