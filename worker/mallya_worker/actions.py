"""Customer-side remediation executor.

Defence in depth for "no remediation without human approval": the worker independently
verifies an HMAC-signed approval token minted by the control plane only after a human
(SECURITY_ANALYST/ADMIN) approved the exact action + parameters. Each approval executes at
most once; replays return the recorded result (idempotent). Every action is an allowlisted
template with fixed argv - no arbitrary shell, SQL or URLs.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone

from mallya_common.canonical import canonical

from . import infra, meridian, scan, storage
from .clients import cdn_admin, vendor
from .config import settings


class ApprovalError(Exception):
    pass


def _expected_sig(token: dict) -> str:
    body = {k: token[k] for k in ("action_id", "action_type", "params_sha256", "approval_id", "approved_by", "expires_at")}
    return hmac.new(settings().approval_signing_key.encode(), canonical(body), hashlib.sha256).hexdigest()


def verify_approval(action_type: str, params: dict, token: dict) -> None:
    for k in ("action_id", "action_type", "params_sha256", "approval_id", "approved_by", "expires_at", "signature"):
        if k not in token:
            raise ApprovalError(f"approval token missing {k}")
    if not hmac.compare_digest(_expected_sig(token), token["signature"]):
        raise ApprovalError("approval signature invalid")
    if token["action_type"] != action_type:
        raise ApprovalError("approval is for a different action type")
    if token["params_sha256"] != hashlib.sha256(canonical(params)).hexdigest():
        raise ApprovalError("approved parameters do not match requested parameters")
    if datetime.fromisoformat(token["expires_at"]) < datetime.now(timezone.utc):
        raise ApprovalError("approval expired")


def _ensure_ledger() -> None:
    meridian.execute("CREATE TABLE IF NOT EXISTS executed_actions (approval_id TEXT PRIMARY KEY, action_id TEXT, "
                     "action_type TEXT, result JSONB, executed_at TIMESTAMPTZ DEFAULT now())")


# ------------------------------------------------------------------ action templates
def a_bucket_set_private(p: dict) -> dict:
    before = storage.get_anonymous(p["bucket"])
    if before == "none":
        return {"changed": False, "before": before, "after": "none", "note": "already private (idempotent no-op)"}
    storage.set_anonymous("mallya-remediator", p["bucket"], "none")
    return {"changed": True, "before": before, "after": storage.get_anonymous(p["bucket"])}


def a_infra_patch_private(p: dict) -> dict:
    bucket = p["bucket"]
    if bucket not in infra.current_buckets_public():
        sync = infra.sync("infra-sync")
        return {"changed": False, "note": "buckets.yaml already declares bucket private", "sync": sync}
    new_text = infra.set_public(bucket, False)
    diff = infra.unified_diff("buckets.yaml", new_text)
    sha = infra.commit(infra.AUTHORS["mallya"], datetime.now(timezone.utc),
                       f"{p.get('action_id', 'MALLYA')}: make {bucket} private ({p.get('incident_ref', '')})".strip(),
                       {"buckets.yaml": new_text})
    sync = infra.sync("infra-sync")
    return {"changed": True, "commit": sha, "diff": diff, "sync": sync, "anonymous_after": storage.get_anonymous(bucket)}


def a_infra_enable_gate(p: dict) -> dict:
    gate = p["gate"]
    gates = infra.enabled_gates()
    sha = None
    if gate not in gates:
        gates.append(gate)
        sha = infra.commit(infra.AUTHORS["mallya"], datetime.now(timezone.utc),
                           f"{p.get('action_id', 'MALLYA')}: enforce policy gate {gate}",
                           {infra.GATES_FILE: "gates:\n" + "".join(f"  - {g}\n" for g in gates)})
    regression = infra.check_reapply(p["bad_commit"]) if p.get("bad_commit") else None
    return {"changed": sha is not None, "commit": sha, "gates": gates, "regression_test": regression}


def a_cdn_purge(p: dict) -> dict:
    results = [cdn_admin("POST", "/purge", params={"key": path}) for path in p["paths"]]
    after = [cdn_admin("GET", "/cache/inspect", params={"key": path}) for path in p["paths"]]
    return {"changed": any(r["purged_count"] for r in results),
            "purged": [k for r in results for k in r["purged"]],
            "still_cached": [a["key"] for a in after if a["cached"]]}


def a_partner_presigned_handoff(p: dict) -> dict:
    """Safer alternative to anonymous access: give the partner a scoped, expiring link, then close the bucket."""
    from datetime import timedelta

    url = storage.as_principal("mallya-remediator").presigned_get_object(
        p["bucket"], p["key"], expires=timedelta(seconds=int(p.get("expires_seconds", 86400))))
    vendor("POST", "/northwind/v1/delivery-links",
           json={"url": url, "expires_seconds": int(p.get("expires_seconds", 86400)),
                 "note": f"replaces anonymous access to {p['bucket']}"})
    closed = a_bucket_set_private({"bucket": p["bucket"]})
    return {"changed": True, "link_delivered_to": p.get("partner", "northwind-analytics"),
            "link_expires_seconds": int(p.get("expires_seconds", 86400)), "bucket": closed}


def a_disable_sync_job(p: dict) -> dict:
    n = meridian.execute("UPDATE integration_jobs SET enabled = FALSE WHERE job_id = :j AND enabled", j=p["job_id"])
    return {"changed": n > 0, "job_id": p["job_id"], "enabled_after": False}


def a_vendor_delete_subjects(p: dict) -> dict:
    """Delete rows at the vendor for the given subject fingerprints (mapped to refs locally)."""
    wanted = set(p["subject_fingerprints"])
    idx = scan.index()
    contacts = vendor("GET", "/northwind/v1/contacts")["contacts"]
    refs = []
    for c in contacts:
        subj = idx.subject("email", c.get("email", "")) or idx.subject("phone", c.get("phone", ""))
        if subj in wanted:
            refs.append(c["customer_ref"])
    res = vendor("POST", "/northwind/v1/contacts:batchDelete", json={"customer_refs": refs}) if refs else {"deleted": 0}
    return {"changed": res["deleted"] > 0, "requested_subjects": len(wanted), "deleted_rows": res["deleted"]}


def a_delete_object(p: dict) -> dict:
    c = storage.as_principal("mallya-remediator")
    try:
        c.stat_object(p["bucket"], p["key"])
    except Exception:  # noqa: BLE001
        return {"changed": False, "note": "object already absent"}
    c.remove_object(p["bucket"], p["key"])
    return {"changed": True, "deleted": f"s3://{p['bucket']}/{p['key']}"}


def a_vendor_ai_delete(p: dict) -> dict:
    deleted = [vendor("DELETE", f"/quicksummarize/v1/received/{int(u)}")["deleted"] for u in p["upload_ids"]]
    return {"changed": sum(deleted) > 0, "deletion_requests": len(deleted), "deleted": sum(deleted)}


ACTIONS = {
    "bucket.set_private": a_bucket_set_private,
    "infra.patch_bucket_private": a_infra_patch_private,
    "infra.enable_policy_gate": a_infra_enable_gate,
    "cdn.purge": a_cdn_purge,
    "partner.presigned_handoff": a_partner_presigned_handoff,
    "integration.disable_sync": a_disable_sync_job,
    "vendor.delete_subjects": a_vendor_delete_subjects,
    "object.delete": a_delete_object,
    "vendor.ai_delete_uploads": a_vendor_ai_delete,
}


def execute(action_type: str, params: dict, token: dict) -> dict:
    if action_type not in ACTIONS:
        raise ApprovalError("unknown action type")
    verify_approval(action_type, params, token)
    _ensure_ledger()
    prior = meridian.query("SELECT result FROM executed_actions WHERE approval_id = :a", a=token["approval_id"])
    if prior:
        return {**prior[0]["result"], "replayed": True}
    result = ACTIONS[action_type](params)
    result["executed_at"] = datetime.now(timezone.utc).isoformat()
    meridian.execute("INSERT INTO executed_actions (approval_id, action_id, action_type, result) VALUES (:a,:i,:t,CAST(:r AS JSONB))",
                     a=token["approval_id"], i=token["action_id"], t=action_type, r=json.dumps(result, default=str))
    return result
