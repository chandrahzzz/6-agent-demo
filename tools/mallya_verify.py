#!/usr/bin/env python3
"""Standalone verifier for MALLYA evidence packs.

    python tools/mallya_verify.py pack.zip [--pubkey trusted_public_key.pem]

Checks (each prints PASS/FAIL):
  1. checksums      every file matches checksums.sha256; no file missing or extra
  2. manifest-files every file hash recorded in the signed manifest matches
  3. hash-chain     events.jsonl recomputes: payload hashes, event hashes, links, sequence
  4. chain-head     event count and head hash equal the values in the signed manifest
  5. signature      Ed25519 signature over manifest.json verifies (pack key, or --pubkey)

Depends only on the Python standard library + `cryptography`. Exit code 0 only if all pass.
Evidence that verifies is cryptographically tamper-evident; this is not a statement of
legal admissibility.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import zipfile

GENESIS = "0" * 64


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 2
    path = argv[0]
    trusted = None
    if "--pubkey" in argv:
        with open(argv[argv.index("--pubkey") + 1], "rb") as fh:
            trusted = fh.read()
    results: list[tuple[str, bool, str]] = []
    with zipfile.ZipFile(path) as z:
        files = {n: z.read(n) for n in z.namelist()}

    # 1. checksums
    listed = {}
    for line in files.get("checksums.sha256", b"").decode().splitlines():
        if line.strip():
            h, n = line.split("  ", 1)
            listed[n] = h
    present = set(files) - {"checksums.sha256"}
    bad = [n for n, h in listed.items() if n not in files or sha(files[n]) != h]
    missing = [n for n in listed if n not in files]
    extra = sorted(present - set(listed))
    ok = bool(listed) and not bad and not extra
    results.append(("checksums", ok, "all files match" if ok else
                    f"modified={[n for n in bad if n not in missing]} missing={missing} unlisted={extra}"))

    manifest_bytes = files.get("manifest.json", b"{}")
    try:
        manifest = json.loads(manifest_bytes)
    except ValueError:
        manifest = {}

    # 2. manifest file hashes
    mf = manifest.get("files", {})
    mbad = [n for n, h in mf.items() if n not in files or sha(files[n]) != h]
    results.append(("manifest-files", bool(mf) and not mbad, "match" if mf and not mbad else f"mismatch: {mbad}"))

    # 3. hash chain
    problems = []
    prev = GENESIS
    records = [json.loads(line) for line in files.get("events.jsonl", b"").decode().splitlines() if line.strip()]
    for i, r in enumerate(records, start=1):
        if r.get("seq") != i:
            problems.append(f"seq {r.get('seq')} at position {i} (missing, inserted or reordered event)")
        if sha(canonical(r["payload"])) != r["payload_hash"]:
            problems.append(f"event {r['seq']}: payload modified")
        if r["previous_event_hash"] != prev:
            problems.append(f"event {r['seq']}: broken link to previous event")
        recomputed = sha(canonical({"metadata": r["metadata"], "payload_hash": r["payload_hash"],
                                    "previous_event_hash": r["previous_event_hash"]}))
        if recomputed != r["event_hash"]:
            problems.append(f"event {r['seq']}: event_hash mismatch")
        prev = r["event_hash"]
    results.append(("hash-chain", bool(records) and not problems,
                    f"{len(records)} events intact" if records and not problems else "; ".join(problems[:5]) or "no events"))

    # 4. chain head vs signed manifest
    ch = manifest.get("chain", {})
    head_ok = ch.get("event_count") == len(records) and ch.get("head_event_hash") == prev
    results.append(("chain-head", head_ok, "count and head match manifest" if head_ok else
                    f"manifest says {ch.get('event_count')} events / head {str(ch.get('head_event_hash'))[:12]}; "
                    f"pack has {len(records)} / {prev[:12]}"))

    # 5. signature
    try:
        from cryptography.hazmat.primitives import serialization
        pub_pem = trusted or files["public_key.pem"]
        pub = serialization.load_pem_public_key(pub_pem)
        pub.verify(base64.b64decode(files["manifest.sig"]), manifest_bytes)
        sig_ok, detail = True, f"Ed25519 valid (key {manifest.get('signature', {}).get('key_id')}" + (
            ", trusted key supplied)" if trusted else ", key shipped in pack — compare its key id with your trusted record)")
    except Exception as exc:  # noqa: BLE001
        sig_ok, detail = False, f"invalid ({type(exc).__name__})"
    results.append(("signature", sig_ok, detail))

    width = max(len(n) for n, _, _ in results)
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name.ljust(width)}  {detail}")
    overall = all(ok for _, ok, _ in results)
    print(f"\nOVERALL: {'PASS' if overall else 'FAIL'}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
