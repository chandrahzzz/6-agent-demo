"""M4 exit check: the other four Deep scenarios, each end to end with real sandbox state changes.

These use presenter auto-approve (approvals are still recorded per action and verified by the
worker); the manual-approval path is covered by test_e2e_hero.py.
"""
from __future__ import annotations

import pytest

from conftest import wait_drill_idle

pytestmark = pytest.mark.e2e


def run(c, scenario: str, variant: str = "A") -> tuple[dict, str]:
    r = c.post("/drills", json={"scenario_id": scenario, "access_variant": variant, "auto_approve": True, "reset": True})
    assert r.status_code == 202, r.text
    d = wait_drill_idle(c, r.json()["id"])
    assert d["status"] == "COMPLETED", d
    return d, d["incident_id"]


def final(c, iid: str) -> dict:
    return c.get(f"/incidents/{iid}/verification").json()["items"][-1]


def actions(c, iid: str) -> list[dict]:
    return c.get(f"/incidents/{iid}/remediation").json()["items"]


def test_d02_public_bucket_only_sensitive_objects(analyst):
    _, iid = run(analyst, "D-02")
    f = analyst.get(f"/incidents/{iid}/findings").json()["items"]
    exposed = sorted(x["details"]["key"] for x in f if x["finding_type"] == "PUBLIC_OBJECT_WITH_IDENTIFIERS")
    assert exposed == ["kyc/exceptions-2026-q3.md", "ops/escalations-export.md", "support/callback-list.md"]
    br = analyst.get(f"/incidents/{iid}/blast-radius").json()
    present_docs = [loc["location"] for loc in br["locations"] if loc["present"] and "internal-docs" in loc["location"]]
    assert len(present_docs) == 3, "harmless docs must not appear in the blast radius"
    inv = analyst.get(f"/incidents/{iid}/investigation").json()
    assert inv["root_cause"][0]["commit"]["author"] == "meera.s"
    patch = next(a for a in actions(analyst, iid) if a["action_type"] == "infra.patch_bucket_private")
    assert "+    classification: confidential" in patch["patch_diff"]
    gate = next(a for a in actions(analyst, iid) if a["action_type"] == "infra.enable_policy_gate")
    assert gate["result"]["regression_test"]["blocked"] is True
    v = final(analyst, iid)
    assert v["verdict"] == "VERIFIED_FIXED", v["reasons"]


def test_d03_export_link_and_archive_copy(analyst):
    _, iid = run(analyst, "D-03")
    inc = analyst.get(f"/incidents/{iid}").json()
    assert inc["exposure_type"] == "PUBLIC_EXPORT_LINK"
    br = analyst.get(f"/incidents/{iid}/blast-radius").json()
    assert br["record_count"] == 800
    archive = next(loc for loc in br["locations"] if "meridian-archive" in loc["location"])
    assert archive["matches"] == 800, "every exported record must also be found in the archive"
    act = actions(analyst, iid)
    assert [a["action_type"] for a in act] == ["bucket.set_private"] and act[0]["params"]["prefix"] == "shared"
    v = final(analyst, iid)
    assert v["verdict"] == "VERIFIED_FIXED", v["reasons"]
    assert v["authorised_results"][0]["principal"] == "finance-analyst"
    assert v["authorised_results"][0]["outcome"] == "ACCESSIBLE"
    archived = next(c for c in v["copy_hunt"] if "meridian-archive" in c["location"])
    assert archived["present"] and archived["accessible"] is False


def test_d04_consent_withdrawal_mismatch(analyst):
    _, iid = run(analyst, "D-04")
    br = analyst.get(f"/incidents/{iid}/blast-radius").json()
    assert br["record_count"] > 0 and br["consent"]["marketing_withdrawn"] == br["record_count"]
    types = [a["action_type"] for a in actions(analyst, iid)]
    assert types == ["integration.disable_sync", "vendor.delete_subjects", "integration.enable_consent_filter"]
    v = final(analyst, iid)
    assert v["verdict"] == "VERIFIED_FIXED", v["reasons"]
    forced = next(r for r in v["external_results"] if r["probe_id"] == "force-sync")
    assert forced["status"] == "DISABLED" and forced["outcome"] == "DENIED"
    vendor = next(c for c in v["copy_hunt"] if c["location"] == "vendor://northwind/contacts")
    assert vendor["matches"] == 0
    assert v["authorised_results"][0]["outcome"] == "ACCESSIBLE"  # consented members are untouched


def test_d05_shadow_ai_upload(analyst):
    _, iid = run(analyst, "D-05")
    inv = analyst.get(f"/incidents/{iid}/investigation").json()
    assert inv["verdict"] == "LIKELY_EXFILTRATED"
    assert "arjun.k" in inv["root_cause"][0]["statement"]
    br = analyst.get(f"/incidents/{iid}/blast-radius").json()
    assert br["record_count"] == 150
    v = final(analyst, iid)
    assert v["verdict"] == "VERIFIED_FIXED", v["reasons"]
    cause = next(r for r in v["external_results"] if r["probe_id"] == "cause")
    assert cause["status"] == "blocked=True"
