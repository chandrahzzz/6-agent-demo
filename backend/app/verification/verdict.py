"""Adversarial verification verdict. Pure function (unit-tested).

VERIFIED_FIXED only if ALL hold:
  * every external probe of a known exposed path got a genuine denial (401/403)
  * the original object is protected
  * every known copy location was checked (none UNVERIFIED)
  * every fingerprint match is accounted for (present => not externally accessible)
  * the authorised consumer still gets 200
  * evidence was recorded
Transport failures (DNS, refused, timeout, 5xx) never count as blocked.
"""
from __future__ import annotations

BLOCKED = {"DENIED"}
INCONCLUSIVE = {"DNS_FAILURE", "CONNECTION_REFUSED", "CONNECTION_ERROR", "TIMEOUT", "SERVER_ERROR",
                "UNEXPECTED_STATUS", "NOT_FOUND"}


def decide(*, original_probes: list[dict], copy_probes: list[dict], copy_hunt: list[dict],
           authorised: list[dict], evidence_recorded: bool, verifier_ok: bool = True,
           authorised_required: bool = True) -> dict:
    reasons: list[str] = []
    residual: list[str] = []
    if not verifier_ok:
        return {"verdict": "VERIFICATION_FAILED", "reasons": ["external verifier unavailable; nothing was tested"],
                "residual": []}

    orig_open = [p for p in original_probes if p["outcome"] == "ACCESSIBLE"]
    orig_inconclusive = [p for p in original_probes if p["outcome"] in INCONCLUSIVE]
    copy_open = [p for p in copy_probes if p["outcome"] == "ACCESSIBLE"]
    copy_inconclusive = [p for p in copy_probes if p["outcome"] in INCONCLUSIVE]
    unverified_locations = [c for c in copy_hunt if not c.get("checked")]
    unaccounted = [c for c in copy_hunt if c.get("present") and c.get("accessible") is None]
    auth_ok = (bool(authorised) and all(a["outcome"] == "ACCESSIBLE" for a in authorised)) if authorised_required else True

    for p in orig_open:
        reasons.append(f"{p['method']} {p['path']} -> {p['status']}" + (" (served from CDN cache)" if p.get("served_from_cache") else ""))
    for p in copy_open:
        residual.append(p.get("location_label") or p["path"])
        reasons.append(f"copy still reachable: {p['method']} {p['path']} -> {p['status']}"
                       + (" (CDN cache HIT)" if p.get("served_from_cache") else ""))
    for p in orig_inconclusive + copy_inconclusive:
        reasons.append(f"{p['path']}: {p['outcome']} is not a denial")
    for c in unverified_locations:
        reasons.append(f"location not inspected: {c['location']}")
    for c in unaccounted:
        reasons.append(f"fingerprint match at {c['location']} with unknown accessibility")
    if not auth_ok:
        reasons.append("authorised consumer did not get 200 (fix broke legitimate access)")
    if not evidence_recorded:
        reasons.append("evidence not recorded")

    if orig_open:
        residual = sorted({*(p.get("location_label") or p["path"] for p in orig_open), *residual})
        verdict = "STILL_EXPOSED"
    elif copy_open:
        verdict = "PARTIALLY_FIXED"
    elif orig_inconclusive or copy_inconclusive or unverified_locations or unaccounted or not evidence_recorded:
        verdict = "UNVERIFIED"
    elif not auth_ok:
        verdict = "PARTIALLY_FIXED"
    else:
        verdict = "VERIFIED_FIXED"
    return {"verdict": verdict, "reasons": reasons, "residual": sorted(set(residual))}
