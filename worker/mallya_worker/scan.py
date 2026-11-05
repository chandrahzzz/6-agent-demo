"""Customer-side scanning. Raw values are read, classified, masked and fingerprinted HERE;
only metadata (counts, masked samples, keyed fingerprints) is returned to the control plane.
"""
from __future__ import annotations

import csv
import io
from collections import Counter
from functools import lru_cache

import httpx

from mallya_common.detectors import (CONFIRMED_SYNTHETIC_TEST_VALUE, classify_column, classify_pan, scan_text)
from mallya_common.fingerprint import Fingerprinter
from mallya_common.masking import mask

from . import meridian, storage
from .config import settings

MAX_SAMPLES = 3


@lru_cache
def fp() -> Fingerprinter:
    s = settings()
    return Fingerprinter(s.fingerprint_key.encode(), s.fingerprint_key_version)


class SubjectIndex:
    """Maps any identifier fingerprint to the subject's canonical (PAN) fingerprint, from the master table."""

    def __init__(self) -> None:
        self.by_fp: dict[str, str] = {}
        self.consent: dict[str, dict] = {}
        rows = meridian.query("SELECT c.customer_id, c.pan_number, c.aadhaar, c.email, c.phone, "
                              "m.state AS marketing FROM customers c LEFT JOIN consent_records m "
                              "ON m.customer_id = c.customer_id AND m.purpose = 'marketing'")
        f = fp()
        for r in rows:
            subj = f("pan", r["pan_number"])
            for cat, col in (("pan", "pan_number"), ("aadhaar", "aadhaar"), ("email", "email"), ("phone", "phone")):
                self.by_fp[f(cat, r[col])] = subj
            self.consent[subj] = {"marketing": r["marketing"]}

    def subject(self, category: str, value: str) -> str | None:
        return self.by_fp.get(fp()(category, value))


_index: SubjectIndex | None = None


def index(refresh: bool = False) -> SubjectIndex:
    global _index
    if _index is None or refresh:
        _index = SubjectIndex()
    return _index


def _tabular(location: str, header: list[str], rows: list[list[str]], container: str,
             include_fingerprints: bool) -> dict:
    cols = list(zip(*rows)) if rows else [[] for _ in header]
    verdicts, samples, counts = [], {}, Counter()
    flagged_cols: dict[str, int] = {}
    synthetic_confirmed = 0
    reg = meridian.synthetic_registry()
    for i, name in enumerate(header):
        v = classify_column(name, list(cols[i]) if i < len(cols) else [], container, header)
        verdicts.append({"column": name, "category": v.category, "outcome": v.outcome, "matched": v.matched,
                         "total": v.total, "context_score": v.context, "customer_identifier": v.is_customer_identifier,
                         "reasons": v.reasons})
        if v.is_customer_identifier and v.category:
            flagged_cols[v.category] = i
            counts[v.category] += v.matched
            samples[v.category] = [mask(v.category, x) for x in list(cols[i])[:MAX_SAMPLES]]
            if v.category == "pan":
                synthetic_confirmed += sum(
                    1 for x in cols[i] if classify_pan(x, reg, fp()("pan", x)) == CONFIRMED_SYNTHETIC_TEST_VALUE)
    subjects: set[str] = set()
    if flagged_cols:
        idx = index()
        f = fp()
        for row in rows:
            subj = None
            if "pan" in flagged_cols:
                subj = f("pan", row[flagged_cols["pan"]])
            else:
                for cat in ("aadhaar", "email", "phone"):
                    if cat in flagged_cols:
                        subj = idx.subject(cat, row[flagged_cols[cat]])
                        if subj:
                            break
            if subj:
                subjects.add(subj)
    n_ids = sum(counts.values())
    meridian.bump(detected=n_ids, masked=sum(len(s) for s in samples.values()),
                  fingerprinted=n_ids, scans=1)
    out = {
        "location": location, "format": "tabular", "record_count": len(rows), "columns": verdicts,
        "categories": dict(counts), "masked_samples": samples, "contains_identifiers": bool(flagged_cols),
        "subject_count": len(subjects), "synthetic_confirmed": synthetic_confirmed,
        "decoy_columns": [v["column"] for v in verdicts if v["category"] and not v["customer_identifier"]],
    }
    if include_fingerprints:
        out["subject_fingerprints"] = sorted(subjects)
    return out


def _text(location: str, text: str, include_fingerprints: bool) -> dict:
    hits = [h for h in scan_text(text) if h.context >= 0.5]
    counts = Counter(h.category for h in hits)
    samples: dict[str, list[str]] = {}
    for h in hits:
        samples.setdefault(h.category, [])
        if len(samples[h.category]) < MAX_SAMPLES:
            samples[h.category].append(mask(h.category, h.value))
    idx = index()
    subjects = {s for s in (idx.subject(h.category, h.value) for h in hits) if s}
    meridian.bump(detected=len(hits), masked=sum(len(s) for s in samples.values()), fingerprinted=len(hits), scans=1)
    out = {"location": location, "format": "text", "record_count": None, "columns": [],
           "categories": dict(counts), "masked_samples": samples, "contains_identifiers": bool(hits),
           "subject_count": len(subjects), "synthetic_confirmed": 0, "decoy_columns": []}
    if include_fingerprints:
        out["subject_fingerprints"] = sorted(subjects)
    return out


def scan_bytes(location: str, data: bytes, name: str, include_fingerprints: bool) -> dict:
    txt = data.decode("utf-8", errors="replace")
    if name.endswith(".csv"):
        rows = list(csv.reader(io.StringIO(txt)))
        if not rows:
            return _tabular(location, [], [], name, include_fingerprints)
        return _tabular(location, rows[0], [r for r in rows[1:] if r], name, include_fingerprints)
    return _text(location, txt, include_fingerprints)


def scan_object(bucket: str, key: str, include_fingerprints: bool = False) -> dict:
    data = storage.read_bytes(bucket, key)
    out = scan_bytes(f"s3://{bucket}/{key}", data, key, include_fingerprints)
    out["bytes"] = len(data)
    return out


def scan_table(table: str, include_fingerprints: bool = False) -> dict:
    allowed = {r["table_name"] for r in meridian.query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema='public'")}
    if table not in allowed:
        raise ValueError("unknown table")
    rows = meridian.query(f'SELECT * FROM "{table}"')  # table name validated against catalog above
    header = list(rows[0].keys()) if rows else []
    data = [[str(r[h]) if r[h] is not None else "" for h in header] for r in rows]
    return _tabular(f"db://meridian/{table}", header, data, table, include_fingerprints)


def _vendor(path: str) -> dict:
    s = settings()
    r = httpx.get(f"{s.mock_vendor_url}{path}", headers={"X-Mock-Vendor-Token": s.mock_vendor_token}, timeout=15)
    r.raise_for_status()
    return r.json()


def scan_vendor(store: str, include_fingerprints: bool = False) -> dict:
    if store == "northwind/contacts":
        data = _vendor("/northwind/v1/contacts")["contacts"]
        header = sorted({k for c in data for k in c}) if data else []
        rows = [[str(c.get(h, "")) for h in header] for c in data]
        out = _tabular("vendor://northwind/contacts", header, rows, "northwind_contacts", include_fingerprints)
    elif store == "quicksummarize/uploads":
        uploads = _vendor("/quicksummarize/v1/received")["uploads"]
        merged: dict = {"location": "vendor://quicksummarize/uploads", "format": "uploads", "uploads": [],
                        "categories": Counter(), "subject_fingerprints": set(), "contains_identifiers": False}
        for u in uploads:
            part = scan_bytes(f"vendor://quicksummarize/uploads/{u['id']}", u["content"].encode(), u["filename"], True)
            merged["uploads"].append({"upload_id": u["id"], "filename": u["filename"], "received_at": u["received_at"],
                                      "categories": part["categories"], "subject_count": part["subject_count"],
                                      "masked_samples": part["masked_samples"], "used_for_training": bool(u["used_for_training"])})
            merged["categories"].update(part["categories"])
            merged["subject_fingerprints"].update(part.get("subject_fingerprints", []))
            merged["contains_identifiers"] |= part["contains_identifiers"]
        merged["categories"] = dict(merged["categories"])
        merged["subject_count"] = len(merged["subject_fingerprints"])
        merged["subject_fingerprints"] = sorted(merged["subject_fingerprints"]) if include_fingerprints else None
        out = merged
    else:
        raise ValueError("unknown vendor store")
    return out


def scan_cdn(path: str, include_fingerprints: bool = False) -> dict:
    """Read an object through the CDN *as an internal inspector* without populating the cache
    (X-Mallya-Inspect disables storing). If the CDN serves it, fingerprint what it served."""
    s = settings()
    r = httpx.get(s.cdn_internal_url + path, headers={"X-Mallya-Inspect": "1", "User-Agent": "mallya-worker-inspect/1.0"},
                  timeout=15)
    out = {"location": f"cdn://{path.lstrip('/')}", "status": r.status_code, "cache": r.headers.get("x-cache-status"),
           "served": r.status_code == 200}
    if r.status_code == 200:
        out.update(scan_bytes(out["location"], r.content, path, include_fingerprints))
    return out


def consent_breakdown(subject_fps: list[str]) -> dict:
    idx = index()
    c = Counter((idx.consent.get(s) or {}).get("marketing", "unknown") for s in subject_fps)
    return {"subjects": len(subject_fps), "marketing_withdrawn": c.get("withdrawn", 0),
            "marketing_granted": c.get("granted", 0), "unknown": c.get("unknown", 0)}
