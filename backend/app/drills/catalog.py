"""Scenario catalog: public metadata only. Expected outputs are kept in the hidden benchmark set."""
from __future__ import annotations

DEEP = [
    {"id": "HERO-01", "name": "PUBLIC-BACKUP", "tier": "deep",
     "description": "A buckets.yaml commit made the primary customer-backup bucket public; the replica was opened by hand "
                    "for a partner; the CDN edge has cached the backup file.",
     "hard_part": "First verification must find the CDN cache and the replica still serving data.",
     "variants": {"access_variant": ["A", "B"]}},
    {"id": "D-02", "name": "PUBLIC-S3-BUCKET", "tier": "deep",
     "description": "The internal-docs bucket is public; a few files contain identifiers among many harmless ones.",
     "hard_part": "Blast radius must identify only the sensitive objects.", "variants": {"access_variant": ["A", "B"]}},
    {"id": "D-03", "name": "SENSITIVE-EXPORT", "tier": "deep",
     "description": "A CSV export with identifiers left in meridian-exports behind a public link.",
     "hard_part": "Fingerprint search finds the same records also in the archive.", "variants": {"access_variant": ["A", "B"]}},
    {"id": "D-04", "name": "CONSENT-WITHDRAWAL-MISMATCH", "tier": "deep",
     "description": "Customers who withdrew marketing consent are still synced to the Northwind vendor API.",
     "hard_part": "Stop the sync and remove those rows at the vendor; verification re-queries the vendor.", "variants": {}},
    {"id": "D-05", "name": "SHADOW-AI-UPLOAD", "tier": "deep",
     "description": "A file with identifiers was uploaded to an unapproved AI tool (QuickSummarize).",
     "hard_part": "Prove which records left via fingerprints in the vendor's received-payload store.", "variants": {}},
]
LITE_IDS = ["UNENCRYPTED-STORAGE", "EXCESSIVE-DB-PERMISSIONS", "EXPOSED-POSTGRES", "DATABASE-BACKUP-DRIFT", "PAN-DISCOVERY",
            "AADHAAR-DISCOVERY", "HEALTH-DATA-EXPOSURE", "UNAPPROVED-API", "VENDOR-OVERPERMISSION", "VENDOR-CREDENTIAL-EXPIRY",
            "MISSING-ROPA-ENTRY", "UNREVIEWED-DATA-RETENTION", "UNAPPROVED-AI-VENDOR", "AI-TRAINING-DATA-LEAK",
            "SHARED-DRIVE-EXPOSURE"]
LITE_DESC = {
    "UNENCRYPTED-STORAGE": "A bucket declares server-side encryption but its customer files are stored unencrypted.",
    "EXCESSIVE-DB-PERMISSIONS": "A read-only analytics role holds write privileges on the customer table.",
    "EXPOSED-POSTGRES": "A legacy Postgres login role still accepts its default credential.",
    "DATABASE-BACKUP-DRIFT": "A customer dump sits in a bucket infra-config does not know about.",
    "PAN-DISCOVERY": "A new table outside the data catalogue holds PAN-format identifiers.",
    "AADHAAR-DISCOVERY": "Aadhaar-format identifiers in a bucket not classified for personal data.",
    "HEALTH-DATA-EXPOSURE": "Health claims with ICD-10 diagnoses are readable by every database role.",
    "UNAPPROVED-API": "Customer phone numbers sent to an unregistered SMS API that keeps no inspectable payload.",
    "VENDOR-OVERPERMISSION": "A vendor integration holds scopes it does not need.",
    "VENDOR-CREDENTIAL-EXPIRY": "A vendor credential has expired but the integration is still active.",
    "MISSING-ROPA-ENTRY": "An approved integration processes personal data with no record of processing.",
    "UNREVIEWED-DATA-RETENTION": "Customer records past their retention date with no review.",
    "UNAPPROVED-AI-VENDOR": "An unapproved AI tool is in use; the uploaded content has no personal data.",
    "AI-TRAINING-DATA-LEAK": "An approved AI vendor may train on uploaded customer data (training opt-in on).",
    "SHARED-DRIVE-EXPOSURE": "A file with identifiers on the shared drive is readable by an all-staff group.",
}
LITE = [{"id": i, "name": i, "tier": "lite", "description": LITE_DESC[i], "hard_part": "", "variants": {}} for i in LITE_IDS]
IMPLEMENTED = {"HERO-01", "D-02", "D-03", "D-04", "D-05", *LITE_IDS}


def all_scenarios() -> list[dict]:
    return [{**s, "implemented": s["id"] in IMPLEMENTED} for s in DEEP + LITE]


def get(sid: str) -> dict | None:
    return next((s for s in all_scenarios() if s["id"] == sid), None)
