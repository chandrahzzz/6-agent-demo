"""Lite scenarios: real plants + real customer-side checks. No live remediation.

Every check must stay silent on the default seed (baseline) and fire only on its plant.
Checks return METADATA evidence only; the control plane's investigation rules turn that
evidence into a verdict, and the remediation agent turns it into a recommendation.
"""
from __future__ import annotations

import random
import re
from datetime import datetime, timedelta, timezone

import psycopg
import yaml

from . import checks, infra, meridian, scan, storage, synth
from .clients import iam, vendor
from .config import settings

ICD10 = re.compile(r"^[A-TV-Z][0-9][0-9AB](\.[0-9A-Z]{1,4})?$")


def _people():
    return synth.customers(settings().seed)


def _r(params: dict, sid: str) -> random.Random:
    return random.Random(f"{sid}-{params.get('variant_seed', 0)}")


# ------------------------------------------------------------------ plants
def p_unencrypted(params):
    b = "meridian-kyc-uploads"
    storage.root().make_bucket(b) if not storage.root().bucket_exists(b) else None
    rows = _r(params, "enc").sample(_people(), int(params.get("rows", 60)))
    storage.put_bytes(b, "kyc/batch-0412.csv", synth.customers_csv(rows, ["customer_id", "full_name", "aadhaar", "pan"]))
    text = (infra.repo() / "buckets.yaml").read_text()
    text += "  - name: meridian-kyc-uploads\n    classification: pii\n    public: false\n    owner: onboarding\n    encryption: sse-s3\n"
    infra.commit(infra.AUTHORS["arjun"], datetime.now(timezone.utc) - timedelta(hours=3), "add kyc uploads bucket (sse-s3)",
                 {"buckets.yaml": text})
    storage.set_anonymous("infra-sync", b, "none")
    return {"bucket": b}


def p_db_perms(params):
    meridian.execute("CREATE ROLE analytics_ro NOLOGIN")
    meridian.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON customers TO analytics_ro")
    return {"role": "analytics_ro"}


def p_exposed_pg(params):
    meridian.execute("CREATE ROLE legacy_report LOGIN PASSWORD 'legacy_report'")
    meridian.execute("GRANT CONNECT ON DATABASE meridian TO legacy_report")
    meridian.execute("GRANT SELECT ON customers TO legacy_report")
    return {"role": "legacy_report"}


def p_backup_drift(params):
    b = "meridian-tmp-dumps"
    if not storage.root().bucket_exists(b):
        storage.root().make_bucket(b)
    rows = _people()[: int(params.get("rows", 2000))]
    storage.put_bytes(b, "pg_dump/customers-2026-11-02.csv", synth.customers_csv(rows))
    return {"bucket": b}


def p_pan_discovery(params):
    rows = _r(params, "pan").sample(_people(), int(params.get("rows", 90)))
    meridian.execute("CREATE TABLE loan_applications (application_id TEXT PRIMARY KEY, applicant_name TEXT, pan_number TEXT, amount_inr INT)")
    meridian.execute("INSERT INTO loan_applications VALUES " + ",".join(
        f"('LA-{i:05d}', '{c.full_name}', '{c.pan}', {10000 + i * 7})" for i, c in enumerate(rows)))
    return {"table": "loan_applications"}


def p_aadhaar_discovery(params):
    rows = _r(params, "aad").sample(_people(), int(params.get("rows", 40)))
    storage.put_bytes("meridian-exports", "ops/aadhaar-verification-batch.csv",
                      synth.customers_csv(rows, ["customer_id", "aadhaar", "segment"]))
    return {"object": "meridian-exports/ops/aadhaar-verification-batch.csv"}


def p_health(params):
    r = _r(params, "health")
    codes = ["E11.9", "I10", "J45.909", "C50.919", "F32.9", "M54.5"]
    rows = r.sample(_people(), int(params.get("rows", 120)))
    meridian.execute("INSERT INTO health_claims VALUES " + ",".join(
        f"('CLM-{i:05d}', '{c.customer_id}', '{r.choice(codes)}', {r.randrange(5000, 400000)})" for i, c in enumerate(rows)))
    meridian.execute("GRANT SELECT ON health_claims TO PUBLIC")
    return {"table": "health_claims"}


def p_unapproved_api(params):
    import httpx
    rows = _r(params, "sms").sample(_people(), 25)
    body = {"messages": [{"to": c.phone, "text": "Your statement is ready"} for c in rows]}
    httpx.post(f"{settings().mock_vendor_url}/fastsms/v1/messages:send", json=body, headers={"X-Api-Key-Id": "fastsms-trial-key"}, timeout=10)
    return {"vendor": "fastsms"}


def p_overpermission(params):
    meridian.execute("UPDATE integration_registry SET granted_scopes = 'contacts:write,contacts:read,exports:read,customers:read' "
                     "WHERE integration_id = 'INT-NW'")
    return {"integration": "INT-NW"}


def p_cred_expiry(params):
    meridian.execute("UPDATE integration_registry SET credential_expires_at = now() - interval '2 days' WHERE integration_id = 'INT-MAIL'")
    return {"integration": "INT-MAIL"}


def p_missing_ropa(params):
    meridian.execute("""INSERT INTO integration_registry VALUES ('INT-ANX', 'Analytix Cloud', 'Product analytics on customer emails',
        'http://mock-vendor:7000/analytix/v1', TRUE, FALSE, 'email', 'events:write', 'events:write', now() + interval '90 days', NULL, FALSE)""")
    return {"integration": "INT-ANX"}


def p_retention(params):
    n = meridian.execute("""UPDATE retention_records SET last_reviewed = NULL WHERE customer_id IN (
        SELECT customer_id FROM retention_records WHERE retain_until < CURRENT_DATE ORDER BY customer_id LIMIT :n)""",
                         n=int(params.get("rows", 40)))
    return {"records": n}


def p_unapproved_ai(params):
    import httpx
    httpx.post(f"{settings().mock_vendor_url}/quicksummarize/v1/upload", timeout=10, headers={"X-Api-Key-Id": "qs-personal-key/meera.s"},
               json={"filename": "q3-okr-notes.md", "content": synth.harmless_doc(random.Random(3), "Quarterly OKRs").decode()})
    return {"vendor": "quicksummarize"}


def p_ai_training(params):
    import httpx
    meridian.execute("INSERT INTO ropa_entries VALUES ('ROPA-004', 'AI-assisted document summaries', 'Operations efficiency', 'legitimate_interest')")
    meridian.execute("""INSERT INTO integration_registry VALUES ('INT-QS', 'QuickSummarize AI', 'Document summarisation (approved pilot)',
        'http://mock-vendor:7000/quicksummarize/v1', TRUE, TRUE, 'free text', 'upload:write', 'upload:write', now() + interval '60 days',
        'ROPA-004', FALSE)""")
    vendor("PUT", "/quicksummarize/v1/account/training", params={"opt_in": True})
    rows = _r(params, "train").sample(_people(), 30)
    httpx.post(f"{settings().mock_vendor_url}/quicksummarize/v1/upload", timeout=10, headers={"X-Api-Key-Id": "qs-pilot-key"},
               json={"filename": "complaints-digest.csv",
                     "content": synth.customers_csv(rows, ["customer_id", "full_name", "email", "phone"]).decode()})
    return {"vendor": "quicksummarize"}


def p_shared_drive(params):
    rows = _r(params, "drive").sample(_people(), 35)
    lines = ["# Branch callback sheet (shared drive)", ""] + [f"- {c.full_name}: PAN {c.pan}, {c.email}" for c in rows]
    storage.put_bytes("meridian-internal-docs", "drive/branch-callbacks.md", ("\n".join(lines) + "\n").encode(), "text/markdown")
    iam("PUT", "/principals/all-staff", json={"name": "all-staff", "kind": "group", "description": "Every employee (4,200 members)",
                                              "permissions": [{"bucket": "meridian-internal-docs", "actions": ["s3:GetObject"]}],
                                              "approved": True})
    return {"object": "meridian-internal-docs/drive/branch-callbacks.md"}


SETUP = {
    "UNENCRYPTED-STORAGE": p_unencrypted, "EXCESSIVE-DB-PERMISSIONS": p_db_perms, "EXPOSED-POSTGRES": p_exposed_pg,
    "DATABASE-BACKUP-DRIFT": p_backup_drift, "PAN-DISCOVERY": p_pan_discovery, "AADHAAR-DISCOVERY": p_aadhaar_discovery,
    "HEALTH-DATA-EXPOSURE": p_health, "UNAPPROVED-API": p_unapproved_api, "VENDOR-OVERPERMISSION": p_overpermission,
    "VENDOR-CREDENTIAL-EXPIRY": p_cred_expiry, "MISSING-ROPA-ENTRY": p_missing_ropa, "UNREVIEWED-DATA-RETENTION": p_retention,
    "UNAPPROVED-AI-VENDOR": p_unapproved_ai, "AI-TRAINING-DATA-LEAK": p_ai_training, "SHARED-DRIVE-EXPOSURE": p_shared_drive,
}


# ------------------------------------------------------------------ checks
def _f(check: str, asset: str, title: str, severity: str, evidence: dict, categories: dict | None = None) -> dict:
    return {"check": check, "asset_ref": asset, "title": title, "severity": severity, "evidence": evidence,
            "data_categories": categories or {}}


def run_checks() -> list[dict]:
    out: list[dict] = []
    cfg = yaml.safe_load((infra.repo() / "buckets.yaml").read_text())["buckets"]
    declared = {b["name"]: b for b in cfg}
    c = storage.as_principal("mallya-scanner")

    # UNENCRYPTED-STORAGE: bucket declares SSE but objects carry no server-side encryption
    for name, b in declared.items():
        if str(b.get("encryption", "")).startswith("sse") and c.bucket_exists(name):
            plain = [o.object_name for o in c.list_objects(name, recursive=True)
                     if not (c.stat_object(name, o.object_name).metadata or {}).get("x-amz-server-side-encryption")]
            pii = [k for k in plain if scan.scan_object(name, k)["contains_identifiers"]]
            if pii:
                out.append(_f("UNENCRYPTED-STORAGE", f"s3://{name}", f"{name} declares {b['encryption']} but {len(pii)} object(s) with identifiers are unencrypted",
                              "High", {"declared": b["encryption"], "unencrypted_objects": len(plain), "with_identifiers": len(pii), "public": False}))

    # EXCESSIVE-DB-PERMISSIONS: write privileges on personal-data tables for roles outside the owner
    pii_tables = {r["table_name"] for r in meridian.query("SELECT table_name FROM data_inventory WHERE holds_personal_data")}
    grants = meridian.query("""SELECT grantee, table_name, string_agg(privilege_type, ',' ORDER BY privilege_type) AS privs
        FROM information_schema.role_table_grants WHERE table_schema = 'public' AND grantee NOT IN ('meridian_app', 'postgres', 'PUBLIC')
        GROUP BY grantee, table_name""")
    for g in grants:
        writes = {"INSERT", "UPDATE", "DELETE", "TRUNCATE"} & set(g["privs"].split(","))
        if g["table_name"] in pii_tables and writes and g["grantee"].endswith(("_ro", "_readonly")):
            out.append(_f("EXCESSIVE-DB-PERMISSIONS", f"db://meridian/{g['table_name']}",
                          f"read-only role {g['grantee']} holds {', '.join(sorted(writes))} on {g['table_name']}", "Moderate",
                          {"role": g["grantee"], "privileges": g["privs"], "public": False}))

    # EXPOSED-POSTGRES: a login role accepts a default credential (password = role name)
    for r in meridian.query("SELECT rolname FROM pg_roles WHERE rolcanlogin AND rolname NOT IN ('postgres','meridian_app','mallya_app')"):
        try:
            with psycopg.connect(host="postgres", dbname="meridian", user=r["rolname"], password=r["rolname"], connect_timeout=3):
                out.append(_f("EXPOSED-POSTGRES", f"db://meridian/role/{r['rolname']}",
                              f"Postgres role {r['rolname']} accepts its default credential (password = username)", "High",
                              {"role": r["rolname"], "default_credential": True, "reachable_from_external_net": False, "public": False}))
        except psycopg.OperationalError as exc:
            if "password authentication failed" not in str(exc):  # credential valid but connection refused for another reason
                out.append(_f("EXPOSED-POSTGRES", f"db://meridian/role/{r['rolname']}",
                              f"Postgres role {r['rolname']} has a default credential (password = username)", "High",
                              {"role": r["rolname"], "default_credential": True, "reachable_from_external_net": False, "public": False}))

    # DATABASE-BACKUP-DRIFT: a bucket holding a customer dump that infra-config does not declare
    for b in c.list_buckets():
        if b.name not in declared:
            hits = [o.object_name for o in c.list_objects(b.name, recursive=True) if scan.scan_object(b.name, o.object_name)["contains_identifiers"]]
            if hits:
                out.append(_f("DATABASE-BACKUP-DRIFT", f"s3://{b.name}", f"undeclared bucket {b.name} holds {len(hits)} customer dump(s)", "High",
                              {"objects": hits, "declared_in_config": False, "public": storage.get_anonymous(b.name) != "none"}))

    # PAN-DISCOVERY: a table outside the data catalogue holds PAN-format customer identifiers
    known = {r["table_name"] for r in meridian.query("SELECT table_name FROM data_inventory")}
    for t in meridian.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public'"):
        n = t["table_name"]
        if n in known or n in ("worker_stats", "synthetic_registry", "executed_actions", "data_inventory"):
            continue
        r = scan.scan_table(n)
        if r["categories"].get("pan"):
            out.append(_f("PAN-DISCOVERY", f"db://meridian/{n}", f"uncatalogued table {n} holds {r['categories']['pan']} PAN-format identifiers",
                          "High", {"catalogued": False, "masked_samples": r["masked_samples"], "public": False}, r["categories"]))

    # AADHAAR-DISCOVERY: Aadhaar-shaped (Verhoeff-valid) identifiers outside buckets classified pii
    for name, b in declared.items():
        if b.get("classification") == "pii" or not c.bucket_exists(name):
            continue
        for o in c.list_objects(name, recursive=True):
            r = scan.scan_object(name, o.object_name)
            if r["categories"].get("aadhaar"):
                out.append(_f("AADHAAR-DISCOVERY", f"s3://{name}/{o.object_name}", f"{r['categories']['aadhaar']} Aadhaar-format identifiers in a '{b.get('classification')}' bucket",
                              "High", {"classification": b.get("classification"), "public": storage.object_public(o.object_name, storage.anonymous_rules(name))},
                              r["categories"]))

    # HEALTH-DATA-EXPOSURE: ICD-10 diagnosis data readable by PUBLIC
    rows = meridian.query("SELECT diagnosis_code FROM health_claims LIMIT 200")
    if rows and sum(1 for x in rows if ICD10.match(x["diagnosis_code"])) / len(rows) > 0.9:
        public = meridian.query("SELECT has_table_privilege('public', 'health_claims', 'SELECT') AS p")[0]["p"]
        if public:
            n = meridian.query("SELECT count(*) AS n FROM health_claims")[0]["n"]
            out.append(_f("HEALTH-DATA-EXPOSURE", "db://meridian/health_claims", f"{n} health claims with ICD-10 diagnoses are readable by every database role",
                          "High", {"grant": "SELECT TO PUBLIC", "rows": int(n), "public": False, "internal_broad": True}, {"health": int(n)}))

    reg = {r["integration_id"]: r for r in meridian.query("SELECT * FROM integration_registry")}
    egress = checks.egress()
    for v in egress:
        if not v["in_registry"] and not v["is_ai_tool"]:  # UNAPPROVED-API
            out.append(_f("UNAPPROVED-API", f"vendor://{v['vendor']}", f"{v['calls']} call(s) to unregistered API {v['vendor']} ({v['bytes_out']:,} bytes out)",
                          "Moderate", {"calls": v["calls"], "bytes_out": v["bytes_out"], "payload_retained": False, "endpoints": v["endpoints"]}))
        if v["is_ai_tool"] and not v["approved"] and not v["blocked"] and not v.get("contains_identifiers"):  # UNAPPROVED-AI-VENDOR
            out.append(_f("UNAPPROVED-AI-VENDOR", f"vendor://{v['vendor']}", f"unapproved AI tool {v['vendor']} in use ({v['calls']} upload(s))",
                          "Moderate", {"calls": v["calls"], "bytes_out": v["bytes_out"], "payload_retained": True, "identifiers_proven": 0}))
        if v["is_ai_tool"] and v["approved"] and v.get("contains_identifiers"):  # AI-TRAINING-DATA-LEAK
            acct = vendor("GET", "/quicksummarize/v1/account")
            trained = [u for u in v.get("uploads", []) if u["used_for_training"]]
            if acct["training_opt_in"] and trained:
                out.append(_f("AI-TRAINING-DATA-LEAK", f"vendor://{v['vendor']}",
                              f"approved AI vendor may train on {sum(u['subject_count'] for u in trained)} customers' data (training opt-in is on)",
                              "High", {"training_use": True, "identifiers_proven": sum(u["subject_count"] for u in trained), "payload_retained": True,
                                       "bytes_out": v["bytes_out"]}, v["categories"]))

    now = datetime.now(timezone.utc)
    for i in reg.values():
        if i["blocked"]:
            continue
        granted, required = set(i["granted_scopes"].split(",")) - {""}, set(i["required_scopes"].split(",")) - {""}
        if granted - required:
            out.append(_f("VENDOR-OVERPERMISSION", f"vendor://{i['integration_id']}", f"{i['vendor']} holds scopes it does not need: {', '.join(sorted(granted - required))}",
                          "Moderate", {"excess_scopes": sorted(granted - required), "required": sorted(required)}))
        if i["credential_expires_at"] and i["credential_expires_at"] < now + timedelta(days=7):
            out.append(_f("VENDOR-CREDENTIAL-EXPIRY", f"vendor://{i['integration_id']}",
                          f"{i['vendor']} credential {'expired' if i['credential_expires_at'] < now else 'expires'} {i['credential_expires_at'].date()}",
                          "Low", {"expires_at": i["credential_expires_at"].isoformat(), "expired": i["credential_expires_at"] < now}))
        ropa = {r["ropa_ref"] for r in meridian.query("SELECT ropa_ref FROM ropa_entries")}
        if i["approved"] and i["ropa_ref"] not in ropa:
            out.append(_f("MISSING-ROPA-ENTRY", f"vendor://{i['integration_id']}", f"{i['vendor']} processes {i['data_categories']} with no record of processing",
                          "Moderate", {"data_categories": i["data_categories"], "ropa_ref": i["ropa_ref"]}))

    # UNREVIEWED-DATA-RETENTION: records past retention with no review
    n = meridian.query("SELECT count(*) AS n FROM retention_records WHERE retain_until < CURRENT_DATE AND last_reviewed IS NULL")[0]["n"]
    if n:
        out.append(_f("UNREVIEWED-DATA-RETENTION", "db://meridian/retention_records", f"{n} customer records are past their retention date with no review",
                      "Moderate", {"records": int(n)}))

    # SHARED-DRIVE-EXPOSURE: identifiers on the shared drive readable by a whole-company group
    groups = [p for p in iam("GET", "/principals") if p["kind"] == "group"]
    for g in groups:
        for perm in g.get("permissions", []):
            bkt = perm.get("bucket")
            if "s3:GetObject" not in perm.get("actions", []) or not c.bucket_exists(bkt):
                continue
            for o in c.list_objects(bkt, recursive=True):
                r = scan.scan_object(bkt, o.object_name)
                if r["contains_identifiers"]:
                    out.append(_f("SHARED-DRIVE-EXPOSURE", f"s3://{bkt}/{o.object_name}", f"identifiers on the shared drive readable by group {g['name']}",
                                  "Moderate", {"group": g["name"], "group_size_note": g["description"], "internal_broad": True, "public": False},
                                  r["categories"]))
    return out
