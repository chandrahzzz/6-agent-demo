"""Customer-side worker tests (run inside the worker container)."""
from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

import pytest

from mallya_common.canonical import canonical
from mallya_worker import actions, infra, scenarios, seed, storage


def test_ground_truth_not_mounted_in_worker():
    assert not os.path.exists("/app/benchmark")
    assert not any("ground_truth" in p for p in os.listdir("/app"))


def test_approval_token_required_and_bound_to_params():
    params = {"bucket": "meridian-exports"}
    body = {"action_id": "a1", "action_type": "bucket.set_private",
            "params_sha256": hashlib.sha256(canonical(params)).hexdigest(), "approval_id": "ap1",
            "approved_by": "analyst@meridian.demo", "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()}
    good = {**body, "signature": hmac.new(os.environ["APPROVAL_SIGNING_KEY"].encode(), canonical(body), hashlib.sha256).hexdigest()}
    actions.verify_approval("bucket.set_private", params, good)
    with pytest.raises(actions.ApprovalError):
        actions.verify_approval("bucket.set_private", {"bucket": "meridian-customer-backups"}, good)  # params swapped
    with pytest.raises(actions.ApprovalError):
        actions.verify_approval("bucket.set_private", params, {**good, "signature": "0" * 64})  # forged
    with pytest.raises(actions.ApprovalError):
        actions.verify_approval("cdn.purge", params, good)  # different action type
    with pytest.raises(actions.ApprovalError):
        actions.execute("bucket.set_private", params, {})  # no token at all


@pytest.mark.e2e
def test_reapplying_bad_commit_is_blocked_by_policy_gate():
    """Live: plant HERO-01, fix the config, enable the gate, then re-apply dev.rahul's bad commit
    on the REAL repo and run the REAL sync. The sync must refuse and the bucket must stay private."""
    seed.seed(int(os.environ.get("SEED", "42")))
    log = scenarios.hero01_setup({"cdn_cached": False, "vendor_pull": False})
    bad = log["commit"]
    assert storage.get_anonymous("meridian-customer-backups") == "download"
    actions.a_infra_patch_private({"bucket": "meridian-customer-backups", "action_id": "TEST"})
    assert storage.get_anonymous("meridian-customer-backups") == "none"
    gate = actions.a_infra_enable_gate({"gate": "no_public_pii_buckets", "bad_commit": bad})
    assert gate["regression_test"]["blocked"] is True

    infra._git("cherry-pick", bad, env={"GIT_AUTHOR_NAME": "dev.rahul", "GIT_AUTHOR_EMAIL": "dev.rahul@meridian-bank.test",
                                        "GIT_COMMITTER_NAME": "dev.rahul", "GIT_COMMITTER_EMAIL": "dev.rahul@meridian-bank.test"})
    assert "meridian-customer-backups" in infra.current_buckets_public()  # the bad config is back in the repo...
    res = infra.sync("infra-sync")
    assert res["status"] == "BLOCKED" and res["violations"][0]["bucket"] == "meridian-customer-backups"
    assert storage.get_anonymous("meridian-customer-backups") == "none"  # ...but it never reaches storage
    seed.seed(int(os.environ.get("SEED", "42")))
