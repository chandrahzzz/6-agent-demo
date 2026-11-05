"""Pure unit tests for the investigation and verification verdict engines."""
from __future__ import annotations

from datetime import datetime, timezone

from app.investigation import rootcause
from app.investigation.verdict import classify_ip, collect, decide
from app.verification import verdict as vd

NET = [{"cidr": "172.28.0.23/32", "label": "Northwind", "zone": "partner"},
       {"cidr": "172.29.0.77/32", "label": "verifier", "zone": "probe"},
       {"cidr": "172.28.0.0/24", "label": "internal", "zone": "internal"}]
T = datetime(2026, 11, 5, tzinfo=timezone.utc)
SENS = {("b", "k.csv")}


def ev(**kw):
    base = {"source": "nginx", "ts": T, "bucket": "b", "object_key": "k.csv", "api": "GetObject", "method": "GET",
            "status": 200, "bytes": 1000, "remote_ip": "172.29.0.66", "principal": None, "probe_run_id": None,
            "synthetic_history": False, "authenticated": False}
    return {**base, **kw}


def test_classify_most_specific_wins():
    assert classify_ip("172.28.0.23", NET).zone == "partner"
    assert classify_ip("172.28.0.50", NET).zone == "internal"
    assert classify_ip("8.8.8.8", NET).zone == "external"


def test_public_alone_is_not_exfiltration():
    assert decide(collect([], SENS, NET, set(), set()), {"nginx": True, "minio": True})[0] == "EXPOSED_NOT_ACCESSED"


def test_attempts_without_bytes():
    rows = [ev(method="HEAD", bytes=0), ev(status=404, object_key="wrong"), ev(object_key=None, api="ListObjects")]
    assert decide(collect(rows, SENS, NET, set(), set()), {"n": True})[0] == "ACCESS_ATTEMPTED_NOT_SUCCESSFUL"


def test_download_is_exfiltration_even_from_cache():
    rows = [ev(cache_status="HIT")]
    assert decide(collect(rows, SENS, NET, set(), set()), {"n": False})[0] == "LIKELY_EXFILTRATED"


def test_missing_log_source_is_insufficient_evidence():
    rows = [ev(method="HEAD", bytes=0)]
    assert decide(collect(rows, SENS, NET, set(), set()), {"minio_audit_log": False})[0] == "INSUFFICIENT_EVIDENCE"


def test_internal_only_and_probe_excluded():
    rows = [ev(remote_ip="172.28.0.21"), ev(remote_ip="172.29.0.77", probe_run_id="VER-1")]
    e = collect(rows, SENS, NET, {"VER-1"}, {"172.29.0.77"})
    assert e.probe_excluded == 1
    assert decide(e, {"n": True})[0] == "ACCESSED_INTERNAL_ONLY"


def test_minio_duplicate_of_cdn_miss_not_double_counted():
    rows = [ev(method="HEAD", bytes=0), ev(source="minio_audit", method="HEAD", bytes=0)]
    assert len(collect(rows, SENS, NET, set(), set()).external_attempts) == 1


def test_root_cause_diff_parsing():
    diff = ("@@ -1,6 +1,6 @@\n buckets:\n   - name: meridian-customer-backups\n     classification: pii\n"
            "-    public: false\n+    public: true\n")
    assert rootcause.public_flips(diff) == ["meridian-customer-backups"]


def _p(outcome, path="/b/k", **kw):
    return {"outcome": outcome, "method": "GET", "path": path, "status": 403 if outcome == "DENIED" else 200, **kw}


OK_AUTH = [_p("ACCESSIBLE")]


def test_verified_fixed_requires_everything():
    r = vd.decide(original_probes=[_p("DENIED")], copy_probes=[_p("DENIED", "/r/k")],
                  copy_hunt=[{"location": "s3://r/k", "checked": True, "present": True, "accessible": False}],
                  authorised=OK_AUTH, evidence_recorded=True)
    assert r["verdict"] == "VERIFIED_FIXED"


def test_cached_copy_prevents_verified_fixed():
    r = vd.decide(original_probes=[_p("DENIED")], copy_probes=[_p("ACCESSIBLE", served_from_cache=True, location_label="CDN cache")],
                  copy_hunt=[], authorised=OK_AUTH, evidence_recorded=True)
    assert r["verdict"] == "PARTIALLY_FIXED" and r["residual"] == ["CDN cache"]


def test_exposed_replica_prevents_verified_fixed():
    r = vd.decide(original_probes=[_p("DENIED")], copy_probes=[_p("ACCESSIBLE", "/replica/k", location_label="replica bucket")],
                  copy_hunt=[], authorised=OK_AUTH, evidence_recorded=True)
    assert r["verdict"] == "PARTIALLY_FIXED"


def test_transport_errors_are_never_blocked():
    for outcome in ("DNS_FAILURE", "CONNECTION_REFUSED", "TIMEOUT", "SERVER_ERROR"):
        r = vd.decide(original_probes=[_p(outcome)], copy_probes=[], copy_hunt=[], authorised=OK_AUTH, evidence_recorded=True)
        assert r["verdict"] == "UNVERIFIED", outcome


def test_unchecked_location_is_unverified():
    r = vd.decide(original_probes=[_p("DENIED")], copy_probes=[], copy_hunt=[{"location": "x", "checked": False}],
                  authorised=OK_AUTH, evidence_recorded=True)
    assert r["verdict"] == "UNVERIFIED"


def test_original_open_is_still_exposed():
    r = vd.decide(original_probes=[_p("ACCESSIBLE")], copy_probes=[], copy_hunt=[], authorised=OK_AUTH, evidence_recorded=True)
    assert r["verdict"] == "STILL_EXPOSED"


def test_broken_authorised_access_is_not_fixed():
    r = vd.decide(original_probes=[_p("DENIED")], copy_probes=[], copy_hunt=[], authorised=[_p("DENIED")], evidence_recorded=True)
    assert r["verdict"] != "VERIFIED_FIXED"


def test_verifier_down_is_verification_failed():
    r = vd.decide(original_probes=[], copy_probes=[], copy_hunt=[], authorised=[], evidence_recorded=True, verifier_ok=False)
    assert r["verdict"] == "VERIFICATION_FAILED"
