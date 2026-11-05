#!/usr/bin/env python3
"""MALLYA privacy suite (SPEC 7.5). Run from the repo root on the host: python tools/privacy_suite.py

1. Unit tests (backend container, pytest -m privacy): detectors, Verhoeff, decoys, masking,
   fingerprints, gateway blocking of PAN/Aadhaar/emails/phones/forbidden fields.
2. Leak scans: collects every control-plane artefact - all container logs, a dump of the MALLYA
   database, telemetry tables, evidence-pack exports and API responses - and pipes them into the
   customer-side worker, which counts occurrences of the sandbox's real raw identifiers (counts only).
3. Posts the combined result to the API so the Privacy Boundary page shows it.
Exit code 0 only if every test passes. Stdlib only.
"""
from __future__ import annotations

import http.cookiejar
import io
import json
import subprocess
import sys
import tarfile
import urllib.request
import xml.etree.ElementTree as ET

API = "http://127.0.0.1:8000/api/v1"
SERVICES = ["backend", "worker", "frontend", "nginx", "minio", "cdn-admin", "mock-iam", "mock-vendor", "attacker", "verifier", "redis"]
UNIT_NAMES = {
    "test_01_pan_detection": "PAN detection", "test_02_pan_structure_outcomes": "PAN structure",
    "test_03_verhoeff": "Verhoeff checksum", "test_04_decoys_not_flagged": "Decoys not flagged",
    "test_05_masking": "Masking", "test_06_fingerprint_match_across_datasets": "Fingerprint match across datasets",
    "test_07_different_ids_different_fingerprints": "Different IDs give different fingerprints",
    "test_08_no_raw_pan_in_llm_payload": "No raw PAN in LLM payload",
    "test_09_no_raw_aadhaar_in_llm_payload": "No raw Aadhaar in LLM payload",
    "test_13_gateway_blocks_unsafe_payloads": "Gateway blocks unsafe payloads",
}


def sh(*args: str, stdin: bytes | None = None) -> bytes:
    return subprocess.run(list(args), input=stdin, capture_output=True, check=False).stdout


def api_client():
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    req = urllib.request.Request(f"{API}/auth/login", data=json.dumps({"email": "admin@meridian.demo",
                                 "password": "mallya-demo-2026"}).encode(), headers={"content-type": "application/json"})
    op.open(req)
    return op


def get(op, path: str) -> bytes:
    try:
        return op.open(f"{API}{path}").read()
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": str(exc)}).encode()


def main() -> int:
    results = []
    print("== unit privacy tests (backend container)")
    sh("docker", "compose", "exec", "-T", "backend", "sh", "-c",
       "cd /app/backend && python -m pytest -q -p no:cacheprovider -m privacy --junitxml=/tmp/privacy.xml >/dev/null 2>&1")
    xml = sh("docker", "compose", "exec", "-T", "backend", "cat", "/tmp/privacy.xml")
    for tc in ET.fromstring(xml).iter("testcase"):
        name = tc.get("name")
        failed = tc.find("failure") is not None or tc.find("error") is not None
        results.append({"id": name, "name": UNIT_NAMES.get(name, name), "passed": not failed,
                        "detail": "pytest" + (": " + (tc.find("failure") or tc.find("error")).get("message", "")[:200] if failed else "")})

    print("== collecting control-plane artefacts")
    op = api_client()
    art: dict[str, bytes] = {}
    for s in SERVICES:
        art[f"logs/{s}.log"] = sh("docker", "compose", "logs", "--no-color", s)
    art["db/mallya.sql"] = sh("docker", "compose", "exec", "-T", "postgres", "pg_dump", "-U", "postgres", "mallya")
    for t in ("agent_events", "agent_executions", "llm_calls", "audit_logs", "privacy_violations"):
        art[f"telemetry/{t}.csv"] = sh("docker", "compose", "exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "mallya",
                                       "-c", f"COPY {t} TO STDOUT WITH CSV HEADER")
    exports = sh("docker", "compose", "exec", "-T", "backend", "tar", "-C", "/exports", "-cf", "-", ".")
    with tarfile.open(fileobj=io.BytesIO(exports)) as t:
        for m in t.getmembers():
            if m.isfile():
                art[f"exports/{m.name.lstrip('./')}"] = t.extractfile(m).read()
    incidents = json.loads(get(op, "/incidents?page_size=200")).get("items", [])
    for p in ("/dashboard", "/assets?page_size=500", "/privacy/llm-calls?page_size=500", "/agents/executions?page_size=500",
              "/audit-logs?page_size=500", "/evidence"):
        art[f"api{p.split('?')[0]}.json"] = get(op, p)
    for inc in incidents:
        for tab in ("", "/findings", "/investigation", "/blast-radius", "/remediation", "/verification", "/evidence",
                    "/timeline", "/drafts", "/agents"):
            art[f"api/incidents/{inc['ref']}{tab or '/overview'}.json"] = get(op, f"/incidents/{inc['id']}{tab}")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in art.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    print(f"   {len(art)} artefacts, {sum(len(v) for v in art.values()) / 1e6:.1f} MB, {len(incidents)} incident(s)")

    print("== leak scan inside the customer-side worker")
    out = sh("docker", "compose", "exec", "-T", "worker", "sh", "-c", "cd /app/worker && python -m mallya_worker.leakscan",
             stdin=buf.getvalue())
    scan = json.loads(out)
    g = scan["groups"]
    st = scan["self_test"]
    print(f"   scanner positive control: {st['detected']}/{st['planted']} planted identifiers detected"
          f" ({'OK' if st['ok'] else 'SCANNER BROKEN - results invalid'})")
    leaking = scan["leaking_files"]

    def grp_result(tid: str, name: str, keys: list[str]) -> dict:
        hits = sum(g.get(k, {}).get("hits", 0) for k in keys)
        files = sum(g.get(k, {}).get("files", 0) for k in keys)
        bad = [x["name"] for x in leaking if x["name"].split("/", 1)[0] in keys]
        return {"id": tid, "name": name, "passed": hits == 0 and files > 0 and scan["self_test"]["ok"],
                "detail": f"{files} artefact(s) scanned against {sum(scan['identifiers_known'].values()):,} known identifiers; "
                          f"{hits} raw identifier occurrence(s)" + (f" in {bad[:3]}" if bad else "")}

    results.append(grp_result("test_10_no_raw_ids_in_logs", "No raw IDs in logs", ["logs"]))
    results.append(grp_result("test_11_no_raw_ids_in_telemetry", "No raw IDs in telemetry", ["telemetry", "db"]))
    results.append(grp_result("test_12_no_raw_ids_in_evidence_exports", "No raw IDs in evidence exports", ["exports", "api"]))
    if not g.get("exports"):
        results[-1]["detail"] += " (no evidence pack exists yet - run a drill first)"
        results[-1]["passed"] = False
    results.sort(key=lambda r: r["id"])

    passed = sum(r["passed"] for r in results)
    for r in results:
        print(f"{'PASS' if r['passed'] else 'FAIL'}  {r['name']:<45} {r['detail']}")
    print(f"\n{passed}/{len(results)} privacy tests passed")
    req = urllib.request.Request(f"{API}/privacy/tests", data=json.dumps({"results": results, "source": "tools/privacy_suite.py"}).encode(),
                                 headers={"content-type": "application/json"}, method="POST")
    op.open(req)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
