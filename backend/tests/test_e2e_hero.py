"""M1 exit check: HERO-01 end to end from a clean reset, with real human approvals.

plant -> detect -> investigate -> blast radius -> approve -> remediate -> verify (PARTIALLY_FIXED
because the real nginx cache and the held replica still serve data) -> fix residual -> VERIFIED_FIXED.
Also proves: an exposed replica / cached copy prevents VERIFIED_FIXED; closing is blocked until
VERIFIED_FIXED; re-applying the bad commit is blocked by the policy gate; the pack verifies.
"""
from __future__ import annotations

import pytest

from conftest import wait_drill_idle, wait_incident_idle

pytestmark = pytest.mark.e2e


def _start(c, variant: str) -> tuple[str, str]:
    r = c.post("/drills", json={"scenario_id": "HERO-01", "access_variant": variant, "auto_approve": False, "reset": True})
    assert r.status_code == 202, r.text
    d = wait_drill_idle(c, r.json()["id"])
    assert d["status"] == "COMPLETED", d
    assert d["incident_id"]
    return d["id"], d["incident_id"]


def test_hero01_variant_a_full_loop(analyst, viewer):
    _, iid = _start(analyst, "A")
    inc = analyst.get(f"/incidents/{iid}").json()
    assert inc["status"] == "AWAITING_APPROVAL"
    assert set(inc["scope"]["buckets"]) == {"meridian-customer-backups", "meridian-backups-replica"}

    inv = analyst.get(f"/incidents/{iid}/investigation").json()
    assert inv["verdict"] == "ACCESS_ATTEMPTED_NOT_SUCCESSFUL"
    assert inv["log_coverage"]["nginx"] and inv["log_coverage"]["minio_audit"]
    assert len(inv["evidence"]["external_attempts"]) == 3 and not inv["evidence"]["external_success"]
    rc = {c["bucket"]: c for c in inv["root_cause"]}
    assert rc["meridian-customer-backups"]["kind"] == "CONFIG_COMMIT"
    assert rc["meridian-customer-backups"]["commit"]["author"] == "dev.rahul"
    assert rc["meridian-customer-backups"]["commit"]["subject"] == "share backups with vendor"
    assert rc["meridian-backups-replica"]["kind"] == "OUT_OF_BAND_CHANGE"

    br = analyst.get(f"/incidents/{iid}/blast-radius").json()
    assert br["record_count"] == 5000
    assert 0 < br["consent"]["marketing_withdrawn"] < 5000
    present = {loc["location"] for loc in br["locations"] if loc["present"]}
    assert "s3://meridian-archive/archive/2026-10/customers_full_2026-10-01.csv" in present

    acts = analyst.get(f"/incidents/{iid}/remediation").json()["items"]
    held = [a for a in acts if a["approval_status"] == "HELD"]
    assert len(held) == 1 and held[0]["target"] == "s3://meridian-backups-replica"
    assert held[0]["safety"]["result"] == "DEPENDENCY_FOUND"
    patch = next(a for a in acts if a["action_type"] == "infra.patch_bucket_private")
    assert "-    public: true" in patch["patch_diff"] and "+    public: false" in patch["patch_diff"]

    # viewers cannot approve; held actions cannot be approved without an explicit override
    pending = [a["id"] for a in acts if a["approval_status"] == "PENDING"]
    assert viewer.post("/approvals", json={"action_ids": pending, "decision": "APPROVED"}).status_code == 403
    assert analyst.post("/approvals", json={"action_ids": [held[0]["id"]], "decision": "APPROVED"}).status_code == 409
    # nothing executes before approval
    assert analyst.post(f"/incidents/{iid}/remediation/execute").status_code == 409

    assert analyst.post("/approvals", json={"action_ids": pending, "decision": "APPROVED"}).status_code == 200
    assert analyst.post(f"/incidents/{iid}/remediation/execute").status_code == 202
    inc = wait_incident_idle(analyst, iid)

    runs = analyst.get(f"/incidents/{iid}/verification").json()["items"]
    first = runs[0]
    assert first["verdict"] == "PARTIALLY_FIXED", first["reasons"]
    residual = " ".join(first["residual"])
    assert "CDN cache" in residual and "replica bucket" in residual
    cdn_hits = [r for r in first["external_results"] if r.get("layer") == "edge" and r.get("served_from_cache")]
    assert cdn_hits, "the real nginx cache must be serving the backup after the origin was closed"
    primary_origin = [r for r in first["external_results"] if r.get("layer") == "origin"
                      and r["path"].startswith("/meridian-customer-backups/")]
    assert primary_origin and all(r["outcome"] == "DENIED" for r in primary_origin)
    assert first["authorised_results"][0]["outcome"] == "ACCESSIBLE"

    gate = next(a for a in analyst.get(f"/incidents/{iid}/remediation").json()["items"] if a["action_type"] == "infra.enable_policy_gate")
    assert gate["result"]["regression_test"]["blocked"] is True

    # closing as fixed is refused by the backend while the latest verification is not VERIFIED_FIXED
    assert analyst.post(f"/incidents/{iid}/close", json={}).status_code == 409

    acts = analyst.get(f"/incidents/{iid}/remediation").json()["items"]
    wave2 = [a for a in acts if a["approval_status"] == "PENDING"]
    assert {a["action_type"] for a in wave2} == {"partner.presigned_handoff", "cdn.purge"}
    assert analyst.post("/approvals", json={"action_ids": [a["id"] for a in wave2], "decision": "APPROVED",
                                            "reason": "verifier proved residual exposure"}).status_code == 200
    assert analyst.post(f"/incidents/{iid}/remediation/execute").status_code == 202
    inc = wait_incident_idle(analyst, iid)
    assert inc["status"] == "VERIFIED_FIXED", inc
    last = analyst.get(f"/incidents/{iid}/verification").json()["items"][-1]
    assert last["verdict"] == "VERIFIED_FIXED" and not last["residual"]
    assert all(r["outcome"] == "DENIED" for r in last["external_results"] if r.get("layer") in ("edge", "origin"))

    ev = analyst.get(f"/incidents/{iid}/evidence").json()
    assert ev["chain"]["ok"] and ev["packs"]
    assert analyst.get(f"/evidence/packs/{ev['packs'][0]['id']}/verify").json()["ok"] is True
    assert analyst.post(f"/incidents/{iid}/close", json={"note": "verified"}).status_code == 200


def test_hero01_variant_b_confirmed_download(analyst):
    _, iid = _start(analyst, "B")
    inv = analyst.get(f"/incidents/{iid}/investigation").json()
    assert inv["verdict"] == "LIKELY_EXFILTRATED"
    succ = inv["evidence"]["external_success"]
    assert succ and succ[0]["bytes"] > 100_000 and succ[0]["status"] == 200


def test_hero01_rejected_fix_and_reverification_do_not_deadlock(analyst):
    """Regression: rejecting the replica fix used to leave the approved purge waiting forever, and every
    re-verification stacked another purge. Now: execute explains the block, re-verification re-proposes the
    rejected fix once and keeps a single purge, and approving both reaches VERIFIED_FIXED."""
    _, iid = _start(analyst, "A")
    acts = analyst.get(f"/incidents/{iid}/remediation").json()["items"]
    assert analyst.post("/approvals", json={"action_ids": [a["id"] for a in acts if a["approval_status"] == "PENDING"],
                                            "decision": "APPROVED"}).status_code == 200
    assert analyst.post(f"/incidents/{iid}/remediation/execute").status_code == 202
    wait_incident_idle(analyst, iid)

    acts = analyst.get(f"/incidents/{iid}/remediation").json()["items"]
    handoff = next(a for a in acts if a["action_type"] == "partner.presigned_handoff")
    purge = next(a for a in acts if a["action_type"] == "cdn.purge")
    assert purge["depends_on"] == [handoff["code"]]
    assert analyst.post("/approvals", json={"action_ids": [handoff["id"]], "decision": "REJECTED",
                                            "reason": "testing rejection"}).status_code == 200
    assert analyst.post("/approvals", json={"action_ids": [purge["id"]], "decision": "APPROVED"}).status_code == 200
    r = analyst.post(f"/incidents/{iid}/remediation/execute")
    assert r.status_code == 409 and "blocked_by_dependency" in r.text and handoff["code"] in r.text

    for _ in range(2):  # re-verify twice: the old code added a new purge each time
        assert analyst.post(f"/verification/{iid}/run").status_code == 202
        wait_incident_idle(analyst, iid)
    acts = analyst.get(f"/incidents/{iid}/remediation").json()["items"]
    open_purges = [a for a in acts if a["action_type"] == "cdn.purge" and a["approval_status"] in ("PENDING", "HELD", "APPROVED")]
    assert len(open_purges) == 1, [(a["code"], a["approval_status"]) for a in acts]
    again = [a for a in acts if a["action_type"] == "partner.presigned_handoff" and a["approval_status"] == "PENDING"]
    assert len(again) == 1 and handoff["code"] in again[0]["problem"]
    assert open_purges[0]["depends_on"] == [again[0]["code"]]

    assert analyst.post("/approvals", json={"action_ids": [again[0]["id"]], "decision": "APPROVED"}).status_code == 200
    assert analyst.post(f"/incidents/{iid}/remediation/execute").status_code == 202
    inc = wait_incident_idle(analyst, iid)
    assert inc["status"] == "VERIFIED_FIXED", inc
