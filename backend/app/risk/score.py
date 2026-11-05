"""Deterministic, explainable risk score (0-100). It is a prioritisation aid, NOT a breach probability."""
from __future__ import annotations

import math

EXPOSURE_TYPE = {"PUBLIC_STORAGE": 14, "PUBLIC_EXPORT_LINK": 13, "SHADOW_AI_UPLOAD": 13, "CONSENT_MISMATCH": 10,
                 "CONFIG_DRIFT": 8, "PERMISSIONS": 7, "GOVERNANCE": 4}
VERDICT = {"LIKELY_EXFILTRATED": 16, "INSUFFICIENT_EVIDENCE": 9, "ACCESS_ATTEMPTED_NOT_SUCCESSFUL": 7,
           "ACCESSED_INTERNAL_ONLY": 3, "EXPOSED_NOT_ACCESSED": 2, "FALSE_POSITIVE": 0}
SENSITIVITY = {"pan": 9, "aadhaar": 11, "health": 11, "email": 3, "phone": 3}


def band(score: int) -> str:
    return "Critical" if score >= 75 else "High" if score >= 50 else "Moderate" if score >= 25 else "Low"


def score(*, exposure_type: str, categories: list[str], public: bool, record_count: int, asset_count: int,
          access_verdict: str | None, encrypted_at_rest: bool | None, replicated: bool, third_party: bool) -> dict:
    factors = []

    def add(name: str, points: float, max_points: int, why: str) -> None:
        factors.append({"factor": name, "points": round(points, 1), "max": max_points, "why": why})

    add("Exposure type", EXPOSURE_TYPE.get(exposure_type, 5), 14, exposure_type.replace("_", " ").lower())
    sens = min(20, sum(SENSITIVITY.get(c, 1) for c in set(categories)))
    add("Data sensitivity", sens, 20, ", ".join(sorted(set(categories))) or "none")
    add("Public accessibility", 15 if public else 2, 15, "anonymous internet access" if public else "not public")
    rc = min(15.0, 15 * math.log10(max(record_count, 1)) / 5)  # 100k records => max
    add("Record count", rc, 15, f"{record_count:,} records")
    add("Asset count", min(6, asset_count * 2), 6, f"{asset_count} assets")
    add("Access verdict", VERDICT.get(access_verdict or "", 5), 16, access_verdict or "pending investigation")
    add("Encryption at rest", 0 if encrypted_at_rest else 4, 4,
        "encrypted" if encrypted_at_rest else ("not encrypted" if encrypted_at_rest is False else "unknown"))
    add("Replication", 4 if replicated else 0, 4, "copies exist" if replicated else "single copy")
    add("Third-party involvement", 6 if third_party else 0, 6, "third party involved" if third_party else "none")
    total = int(round(min(100, sum(f["points"] for f in factors))))
    return {"score": total, "band": band(total), "factors": factors,
            "disclaimer": "Prioritisation score from fixed rules. Not a breach probability."}
