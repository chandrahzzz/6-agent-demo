"""Isolation guarantees: hidden ground truth and network separation."""
from __future__ import annotations

import ast
import pathlib

import pytest

from app import connectors

APP = pathlib.Path(__file__).resolve().parent.parent / "app"
GUARDED = ["agents", "detection", "investigation", "remediation", "verification", "orchestration", "drills", "privacy"]


def _imports(path: pathlib.Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            out.append(node.module or "")
        elif isinstance(node, ast.Call) and getattr(node.func, "attr", getattr(node.func, "id", "")) in (
                "open", "read_text", "spec_from_file_location", "import_module"):
            for a in node.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    out.append(a.value)
    return out


def test_ground_truth_import_boundary():
    """Nothing the agents run on may import or open benchmark ground truth."""
    offenders = []
    for pkg in GUARDED:
        for f in (APP / pkg).rglob("*.py"):
            src = f.read_text(encoding="utf-8")
            for imp in _imports(f):
                if "ground_truth" in imp or imp.startswith("benchmark"):
                    offenders.append(f"{f.relative_to(APP)} -> {imp}")
            if "ground_truth" in src:
                offenders.append(f"{f.relative_to(APP)} mentions ground_truth")
    assert not offenders, offenders


def test_boundary_test_would_catch_a_violation(tmp_path):
    bad = tmp_path / "evil.py"
    bad.write_text("from benchmark.ground_truth import answers\n")
    assert any("ground_truth" in i for i in _imports(bad))


@pytest.mark.e2e
def test_verifier_cannot_reach_minio_except_via_nginx():
    res = connectors.verifier("GET", "/selftest/network")
    by = {c["target"]: c for c in res["checks"]}
    assert by["minio:9000"]["reachable"] is False and by["minio:9000"]["result"] == "DNS_FAILURE"
    assert by["172.28.0.12:9000"]["reachable"] is False  # direct IP on customer_net
    assert by["postgres:5432"]["reachable"] is False and by["worker:7100"]["reachable"] is False
    assert by["cdn.meridian.sandbox:8080"]["reachable"] is True  # the only way in
    assert res["origin"]["network"] == "external_net"
