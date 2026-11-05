#!/usr/bin/env python3
"""Policy: no_public_pii_buckets (Python equivalent of an OPA/Conftest rule).

DENY any bucket in buckets.yaml whose classification is pii / confidential / restricted
and which is marked public: true. Used as a gate by the infra-config sync pipeline once
MALLYA's remediation enables it, so a reintroduced bad commit is rejected before it is
applied.

Usage: python no_public_pii_buckets.py path/to/buckets.yaml   (exit 1 on violation)
"""
from __future__ import annotations

import sys

import yaml

POLICY_ID = "no_public_pii_buckets"
POLICY_VERSION = "1.0.0"
SENSITIVE = {"pii", "confidential", "restricted"}


def evaluate(config: dict) -> list[dict]:
    violations: list[dict] = []
    for b in (config or {}).get("buckets", []) or []:
        cls = str(b.get("classification", "")).lower()
        if b.get("public") is True and cls in SENSITIVE:
            violations.append({
                "policy": POLICY_ID,
                "bucket": b.get("name"),
                "classification": cls,
                "message": f"bucket '{b.get('name')}' is classified '{cls}' and must not be public",
            })
    return violations


def evaluate_text(text: str) -> list[dict]:
    return evaluate(yaml.safe_load(text))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    with open(sys.argv[1], encoding="utf-8") as fh:
        found = evaluate_text(fh.read())
    for v in found:
        print(f"DENY  {v['message']}")
    print("PASS" if not found else f"FAIL ({len(found)} violation(s))")
    raise SystemExit(1 if found else 0)
