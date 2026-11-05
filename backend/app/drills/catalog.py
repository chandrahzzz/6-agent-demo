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
LITE = [{"id": i, "name": i, "tier": "lite", "description": "", "hard_part": "", "variants": {}} for i in LITE_IDS]
IMPLEMENTED = {"HERO-01"}


def all_scenarios() -> list[dict]:
    return [{**s, "implemented": s["id"] in IMPLEMENTED} for s in DEEP + LITE]


def get(sid: str) -> dict | None:
    return next((s for s in all_scenarios() if s["id"] == sid), None)
