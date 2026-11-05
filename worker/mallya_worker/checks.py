"""Customer-side integration checks and the (real) marketing sync job. Metadata out only."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from . import meridian, scan
from .clients import vendor

VENDOR_INTEGRATION = {"northwind": "INT-NW", "acme": "INT-MAIL", "quicksummarize": "INT-QS"}


def _withdrawn_members(job: dict) -> list[dict]:
    return meridian.query(
        f'SELECT m.customer_id, m.email, m.phone FROM "{job["source_table"]}" m '  # source_table comes from the job registry
        "JOIN consent_records c ON c.customer_id = m.customer_id AND c.purpose = 'marketing' WHERE c.state = 'withdrawn'")


def consent_sync(include_fingerprints: bool = False) -> list[dict]:
    """For each sync job: are customers who withdrew marketing consent being sent to the vendor?"""
    out = []
    jobs = meridian.query("SELECT * FROM integration_jobs ORDER BY job_id")
    at_vendor = set(scan.scan_vendor("northwind/contacts", True).get("subject_fingerprints") or [])
    idx = scan.index()
    for j in jobs:
        members = meridian.query(f'SELECT count(*) AS n FROM "{j["source_table"]}"')[0]["n"]
        wd = _withdrawn_members(j)
        wd_fps = {idx.subject("email", r["email"]) for r in wd} - {None}
        hit = sorted(wd_fps & at_vendor)
        rec = {"job_id": j["job_id"], "integration_id": j["integration_id"], "enabled": j["enabled"],
               "filter_withdrawn_consent": j["filter_withdrawn_consent"], "source_table": j["source_table"],
               "members": int(members), "withdrawn_members": len(wd_fps), "withdrawn_at_vendor": len(hit),
               "vendor_rows": len(at_vendor), "last_run_at": j["last_run_at"].isoformat() if j["last_run_at"] else None}
        if include_fingerprints:
            rec["withdrawn_at_vendor_fingerprints"] = hit
        out.append(rec)
    return out


def run_sync(job_id: str) -> dict:
    """The sync job itself: pushes campaign members to Northwind. Honors enabled + consent filter."""
    jobs = meridian.query("SELECT * FROM integration_jobs WHERE job_id = :j", j=job_id)
    if not jobs:
        return {"status": "UNKNOWN_JOB"}
    j = jobs[0]
    if not j["enabled"]:
        return {"status": "DISABLED", "sent": 0}
    q = f'SELECT m.campaign_id, m.customer_id, m.email, m.phone FROM "{j["source_table"]}" m'
    if j["filter_withdrawn_consent"]:
        q += (" WHERE NOT EXISTS (SELECT 1 FROM consent_records c WHERE c.customer_id = m.customer_id "
              "AND c.purpose = 'marketing' AND c.state = 'withdrawn')")
    rows = meridian.query(q)
    contacts = [{"customer_ref": r["customer_id"], "campaign_id": r["campaign_id"], "email": r["email"], "phone": r["phone"]} for r in rows]
    for i in range(0, len(contacts), 500):
        vendor("POST", "/northwind/v1/contacts:batchUpsert", json={"contacts": contacts[i:i + 500]})
    meridian.execute("UPDATE integration_jobs SET last_run_at = now() WHERE job_id = :j", j=job_id)
    return {"status": "RAN", "sent": len(contacts), "consent_filter": j["filter_withdrawn_consent"],
            "at": datetime.now(timezone.utc).isoformat()}


def egress(include_fingerprints: bool = False) -> list[dict]:
    """Outbound calls to vendors (from the vendor-side call log), compared with the approved registry."""
    reg = {r["integration_id"]: r for r in meridian.query("SELECT * FROM integration_registry")}
    calls = vendor("GET", "/admin/calls")
    by_vendor: dict[str, list[dict]] = defaultdict(list)
    for c in calls:
        by_vendor[c["vendor"]].append(c)
    out = []
    for v, cs in by_vendor.items():
        r = reg.get(VENDOR_INTEGRATION.get(v, ""), {})
        rec = {"vendor": v, "integration_id": VENDOR_INTEGRATION.get(v), "in_registry": bool(r),
               "approved": bool(r.get("approved")), "blocked": bool(r.get("blocked")), "is_ai_tool": v == "quicksummarize",
               "calls": len(cs), "bytes_out": sum(c["bytes_in"] or 0 for c in cs),
               "api_keys": sorted({c["api_key_id"] for c in cs if c["api_key_id"]}),
               "endpoints": sorted({c["endpoint"] for c in cs}),
               "first_call": min(c["ts"] for c in cs), "last_call": max(c["ts"] for c in cs)}
        if v == "quicksummarize":
            s = scan.scan_vendor("quicksummarize/uploads", include_fingerprints)
            rec.update({"uploads": s["uploads"], "categories": s["categories"], "subject_count": s["subject_count"],
                        "contains_identifiers": s["contains_identifiers"]})
            if include_fingerprints:
                rec["subject_fingerprints"] = s["subject_fingerprints"]
        out.append(rec)
    return out
