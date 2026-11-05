"""Leak scanner (customer side). Reads a tar of control-plane artefacts on stdin (logs, DB dump,
telemetry, evidence exports, API responses) and counts occurrences of the sandbox's REAL raw
identifiers in them. Prints counts only - never a value.

    tar -cf - artefacts | python -m mallya_worker.leakscan
"""
from __future__ import annotations

import io
import json
import re
import sys
import tarfile
import zipfile
import zlib

from . import meridian

PAN = re.compile(r"[A-Z]{5}[0-9]{4}[A-Z]")
DIG12 = re.compile(r"(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)")
DIG10 = re.compile(r"(?<!\d)[6-9]\d{9}(?!\d)")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@meridian-customer\.test", re.I)


def raw_sets() -> dict[str, set[str]]:
    rows = meridian.query("SELECT pan_number, aadhaar, email, phone FROM customers")
    return {"pan": {r["pan_number"] for r in rows}, "aadhaar": {r["aadhaar"] for r in rows},
            "email": {r["email"].lower() for r in rows}, "phone": {re.sub(r"\D", "", r["phone"])[-10:] for r in rows}}


def pdf_text(data: bytes) -> bytes:
    out = [data]
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S):
        try:
            out.append(zlib.decompress(m.group(1)))
        except zlib.error:
            pass
    return b"\n".join(out)


def expand(name: str, data: bytes) -> list[tuple[str, bytes]]:
    if data[:4] == b"PK\x03\x04":
        items = []
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for n in z.namelist():
                items += expand(f"{name}!{n}", z.read(n))
        return items
    if data[:5] == b"%PDF-":
        return [(name, pdf_text(data))]
    return [(name, data)]


def scan(text: str, sets: dict[str, set[str]]) -> dict[str, int]:
    hits = {"pan": 0, "aadhaar": 0, "email": 0, "phone": 0}
    hits["pan"] = sum(1 for m in PAN.findall(text) if m in sets["pan"])
    hits["aadhaar"] = sum(1 for m in DIG12.findall(text) if re.sub(r"\D", "", m) in sets["aadhaar"])
    hits["email"] = sum(1 for m in EMAIL.findall(text) if m.lower() in sets["email"])
    hits["phone"] = sum(1 for m in DIG10.findall(text) if m in sets["phone"])
    return hits


def self_test(sets: dict[str, set[str]]) -> dict:
    """Positive control: a planted real identifier of each kind MUST be detected, otherwise a clean
    result would be meaningless. The planted document never leaves this process."""
    r = meridian.query("SELECT pan_number, aadhaar, email, phone FROM customers ORDER BY customer_id LIMIT 1")[0]
    a = r["aadhaar"]
    doc = (f"log line pan={r['pan_number']} uid={a[:4]} {a[4:8]} {a[8:]} mail={r['email']} tel={r['phone']}")
    h = scan(doc, sets)
    return {"planted": 4, "detected": sum(1 for v in h.values() if v), "ok": all(h.values())}


def main() -> int:
    sets = raw_sets()
    data = sys.stdin.buffer.read()
    members = []
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        for m in t.getmembers():
            if not m.isfile():
                continue
            blob = t.extractfile(m).read()
            for name, content in expand(m.name, blob):
                h = scan(content.decode("utf-8", "replace"), sets)
                members.append({"name": name, "bytes": len(content), "hits": h, "total": sum(h.values())})
    groups: dict[str, dict] = {}
    for m in members:
        g = m["name"].split("/", 1)[0]
        grp = groups.setdefault(g, {"files": 0, "bytes": 0, "hits": 0})
        grp["files"] += 1
        grp["bytes"] += m["bytes"]
        grp["hits"] += m["total"]
    print(json.dumps({"self_test": self_test(sets), "identifiers_known": {k: len(v) for k, v in sets.items() if v}, "groups": groups,
                      "leaking_files": [{"name": m["name"], "hits": m["hits"]} for m in members if m["total"]]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
