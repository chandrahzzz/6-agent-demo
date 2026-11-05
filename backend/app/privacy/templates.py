"""Deterministic reasoning templates (LLM_PROVIDER=local). Pure functions of metadata facts."""
from __future__ import annotations


def _n(x) -> str:
    return f"{x:,}" if isinstance(x, int) else str(x)


def _plural(n: int, word: str) -> str:
    return f"{_n(n)} {word}{'' if n == 1 else 's'}"


def hunter(f: dict) -> str:
    if not f.get("exposures"):
        return (f"Swept {_plural(f.get('assets_scanned', 0), 'asset')}; no exposure found. "
                f"{_plural(f.get('decoys_rejected', 0), 'decoy column')} rejected by context and checksum rules.")
    ex = f["exposures"]
    return (f"Swept {_plural(f.get('assets_scanned', 0), 'asset')} and found {_plural(len(ex), 'exposure')}: "
            + "; ".join(ex[:3]) + ". "
            + f"{_plural(f.get('decoys_rejected', 0), 'decoy column')} rejected (pattern match without customer-identifier context).")


def investigation(f: dict) -> str:
    v = f.get("verdict")
    ext = f.get("external", {})
    if f.get("channel") == "vendor_upload" and v == "LIKELY_EXFILTRATED":
        s = (f"{_n(ext.get('bytes_served_real_object', 0))} bytes containing customer identifiers were uploaded to an unapproved "
             f"third-party AI tool ({_plural(ext.get('successful_downloads', 0), 'upload')}).")
        return (s + (f" Root cause: {f['root_cause']}." if f.get("root_cause") else "")).strip()
    if f.get("channel") == "vendor_sync":
        s = "Data went only to the approved processor; no unknown external access."
        s += f" {f['partner_access']}." if f.get("partner_access") else ""
        return (s + (f" Root cause: {f['root_cause']}." if f.get("root_cause") else "")).strip()
    s = {
        "LIKELY_EXFILTRATED": f"{_n(ext.get('bytes_served_real_object', 0))} bytes of the real object were served to an external origin "
                              f"({_plural(ext.get('successful_downloads', 0), 'successful download')}).",
        "ACCESS_ATTEMPTED_NOT_SUCCESSFUL": f"{_plural(ext.get('attempts', 0), 'anonymous attempt')} from an external origin, "
                                           "no successful download of the real object.",
        "ACCESSED_INTERNAL_ONLY": "Only internal or known-partner origins accessed the data; no unknown external access.",
        "EXPOSED_NOT_ACCESSED": "The data was publicly reachable but no access was recorded in any log source.",
        "INSUFFICIENT_EVIDENCE": "Log coverage is incomplete for the exposure window, so access cannot be ruled out.",
        "FALSE_POSITIVE": "The flagged data did not validate as customer identifiers.",
    }.get(v, "")
    rc = f.get("root_cause")
    if rc:
        s += f" Root cause: {rc}."
    if f.get("partner_access"):
        s += f" Known partner access recorded: {f['partner_access']}."
    return s.strip()


def blast(f: dict) -> str:
    s = (f"{_n(f.get('record_count', 0))} records affected across {_plural(f.get('locations_with_data', 0), 'location')}"
         f" ({', '.join(f.get('categories', []))}).")
    c = f.get("consent") or {}
    if c.get("marketing_withdrawn") is not None:
        s += f" {_n(c['marketing_withdrawn'])} had withdrawn marketing consent."
    if f.get("unverified"):
        s += f" {_plural(f['unverified'], 'location')} could not be inspected and is marked UNVERIFIED."
    return s


def remediation(f: dict) -> str:
    s = f"Proposed {_plural(f.get('proposed', 0), 'action')} (wave {f.get('wave', 1)})"
    if f.get("held"):
        s += f"; {_plural(f['held'], 'action')} held by the safety check: {f.get('held_reason', '')}"
    return s + ". Nothing executes without a recorded human approval."


def verification(f: dict) -> str:
    v = f.get("verdict")
    if v == "VERIFIED_FIXED" and f.get("mode") == "vendor":
        return ("A forced re-run and a keyed-fingerprint re-query found 0 affected subjects at the vendor, the root-cause control "
                "is in place, and legitimate flows are unaffected.")
    if v == "VERIFIED_FIXED":
        return (f"All {_plural(f.get('external_blocked', 0), 'external path')} returned a genuine 403, every fingerprint match is "
                "protected, and the authorised consumer still gets 200.")
    res = ", ".join(f.get("residual", [])) or "none"
    return f"{v}: residual exposure at {res}. " + " ".join(f.get("reasons", [])[:2])


def compliance(f: dict) -> str:
    return (f"Prepared {_plural(f.get('drafts', 0), 'draft')} for human legal review; no obligation or deadline was "
            "determined by MALLYA.")


def render(purpose: str, payload: dict) -> str:
    fn = {"hunter.summary": hunter, "investigation.summary": investigation, "blast.summary": blast,
          "remediation.summary": remediation, "verification.summary": verification,
          "compliance.summary": compliance}.get(purpose)
    return fn(payload.get("facts", {})) if fn else ""
