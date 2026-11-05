"""M5 exit check: every Lite scenario is detected with the correct verdict on the default seed,
fires nothing else, and gets a recommendation (no live remediation)."""
from __future__ import annotations

import pathlib

import pytest
import yaml

from conftest import wait_drill_idle

pytestmark = pytest.mark.e2e
TRUTH = yaml.safe_load(pathlib.Path("/app/benchmark/ground_truth/static/lite_default_seed.yaml").read_text())


@pytest.mark.parametrize("sid", sorted(TRUTH))
def test_lite_scenario(analyst, sid):
    r = analyst.post("/drills", json={"scenario_id": sid, "reset": True})
    assert r.status_code == 202, r.text
    d = wait_drill_idle(analyst, r.json()["id"])
    assert d["status"] == "COMPLETED", d
    incs = [i for i in analyst.get("/incidents?page_size=50").json()["items"] if i["drill_id"] == d["id"]]
    assert [i["exposure_type"] for i in incs] == [f"LITE:{sid}"], "exactly one incident, of the planted type (no false positives)"
    inc = incs[0]
    assert inc["scope"]["asset"] == TRUTH[sid]["asset"]
    assert inc["access_verdict"] == TRUTH[sid]["verdict"]
    acts = analyst.get(f"/incidents/{inc['id']}/remediation").json()["items"]
    assert len(acts) == 1 and acts[0]["approval_status"] == "RECOMMENDATION" and acts[0]["execution_status"] == "NOT_APPLICABLE"
