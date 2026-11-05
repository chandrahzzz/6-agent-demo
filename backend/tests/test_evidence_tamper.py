"""M2 exit check: tampering with any evidence record makes the standalone verifier FAIL."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import zipfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.config import settings
from app.core.db import session_scope
from app.evidence import chain, pack
from app.models import EvidenceEvent, EvidencePack, Incident
from mallya_common.canonical import canonical

spec = importlib.util.spec_from_file_location("mallya_verify", "/app/tools/mallya_verify.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


@pytest.fixture(scope="module")
def pack_bytes():
    with session_scope() as db:
        inc = Incident(ref="TEST-TAMPER-0001", title="tamper test incident", exposure_type="PUBLIC_STORAGE", status="VERIFIED_FIXED")
        db.add(inc)
        db.flush()
        iid = inc.id
    for i in range(5):
        chain.append(iid, "test.event", "pytest", {"n": i, "note": f"event {i}"})
    with session_scope() as db:
        p = pack.build(db, iid)
        name = p.file_name
    data = open(f"{settings().evidence_export_dir}/{name}", "rb").read()
    yield data
    with session_scope() as db:
        for m in (EvidenceEvent, EvidencePack):
            db.query(m).filter(m.incident_id == iid).delete()
        db.query(Incident).filter(Incident.id == iid).delete()


def run(blob: bytes, tmp_path, *extra) -> tuple[int, str]:
    p = tmp_path / "pack.zip"
    p.write_bytes(blob)
    buf = io.StringIO()
    import contextlib
    with contextlib.redirect_stdout(buf):
        code = verifier.main([str(p), *extra])
    return code, buf.getvalue()


def rewrite(blob: bytes, mutate) -> bytes:
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        files = {n: z.read(n) for n in z.namelist()}
    mutate(files)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for n, d in files.items():
            z.writestr(n, d)
    return out.getvalue()


def events_of(files) -> list[dict]:
    return [json.loads(x) for x in files["events.jsonl"].decode().splitlines()]


def set_events(files, evs, fix_checksums: bool = False) -> None:
    files["events.jsonl"] = b"".join(canonical(e) + b"\n" for e in evs)
    if fix_checksums:  # an attacker who also rewrites checksums.sha256 (but cannot re-sign the manifest)
        files["checksums.sha256"] = "".join(f"{hashlib.sha256(d).hexdigest()}  {n}\n" for n, d in sorted(files.items())
                                            if n != "checksums.sha256").encode()


def test_untouched_pack_passes(pack_bytes, tmp_path):
    code, out = run(pack_bytes, tmp_path)
    assert code == 0, out
    assert sum(line.startswith("PASS  ") for line in out.splitlines()) == 5 and "OVERALL: PASS" in out


def test_edited_event_fails(pack_bytes, tmp_path):
    def m(f):
        evs = events_of(f)
        evs[2]["payload"]["note"] = "edited"
        set_events(f, evs, fix_checksums=True)
    code, out = run(rewrite(pack_bytes, m), tmp_path)
    assert code == 1 and "FAIL  hash-chain" in out and "payload modified" in out


def test_deleted_event_fails(pack_bytes, tmp_path):
    def m(f):
        evs = events_of(f)
        del evs[1]
        set_events(f, evs, fix_checksums=True)
    code, out = run(rewrite(pack_bytes, m), tmp_path)
    assert code == 1 and "FAIL  hash-chain" in out


def test_reordered_events_fail(pack_bytes, tmp_path):
    def m(f):
        evs = events_of(f)
        evs[1], evs[2] = evs[2], evs[1]
        set_events(f, evs, fix_checksums=True)
    code, out = run(rewrite(pack_bytes, m), tmp_path)
    assert code == 1 and "FAIL  hash-chain" in out


def test_inserted_event_fails(pack_bytes, tmp_path):
    def m(f):
        evs = events_of(f)
        evs.insert(2, {**evs[2], "payload": {"forged": True}})
        set_events(f, evs, fix_checksums=True)
    code, out = run(rewrite(pack_bytes, m), tmp_path)
    assert code == 1 and "FAIL" in out


def test_fully_rehashed_chain_still_fails_against_signed_head(pack_bytes, tmp_path):
    """Attacker edits an event AND recomputes every hash in the chain: the signed manifest pins the head."""
    def m(f):
        evs = events_of(f)
        evs[0]["payload"]["note"] = "rewritten history"
        prev = "0" * 64
        for e in evs:
            e["payload_hash"] = hashlib.sha256(canonical(e["payload"])).hexdigest()
            e["previous_event_hash"] = prev
            e["event_hash"] = hashlib.sha256(canonical({"metadata": e["metadata"], "payload_hash": e["payload_hash"],
                                                         "previous_event_hash": prev})).hexdigest()
            prev = e["event_hash"]
        set_events(f, evs, fix_checksums=True)
    code, out = run(rewrite(pack_bytes, m), tmp_path)
    assert code == 1
    assert "PASS  hash-chain" in out  # internally consistent ...
    assert "FAIL  chain-head" in out and "FAIL  manifest-files" in out  # ... but not what was signed


def test_edited_manifest_fails_signature(pack_bytes, tmp_path):
    def m(f):
        man = json.loads(f["manifest.json"])
        man["content"]["final_status"] = "VERIFIED_FIXED (edited)"
        f["manifest.json"] = canonical(man)
        set_events(f, events_of(f), fix_checksums=True)
    code, out = run(rewrite(pack_bytes, m), tmp_path)
    assert code == 1 and "FAIL  signature" in out


def test_resigned_with_attacker_key_fails_against_trusted_key(pack_bytes, tmp_path):
    attacker = Ed25519PrivateKey.generate()

    def m(f):
        man = json.loads(f["manifest.json"])
        man["content"]["final_status"] = "forged"
        f["manifest.json"] = canonical(man)
        f["manifest.sig"] = __import__("base64").b64encode(attacker.sign(f["manifest.json"]))
        f["public_key.pem"] = attacker.public_key().public_bytes(serialization.Encoding.PEM,
                                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
    trusted = tmp_path / "trusted.pem"
    with zipfile.ZipFile(io.BytesIO(pack_bytes)) as z:
        trusted.write_bytes(z.read("public_key.pem"))
    code, out = run(rewrite(pack_bytes, m), tmp_path, "--pubkey", str(trusted))
    assert code == 1 and "FAIL  signature" in out


def test_db_chain_detects_edit_in_place():
    with session_scope() as db:
        inc = Incident(ref="TEST-TAMPER-0002", title="db tamper", exposure_type="PUBLIC_STORAGE")
        db.add(inc)
        db.flush()
        iid = inc.id
    for i in range(3):
        chain.append(iid, "test.event", "pytest", {"n": i})
    with session_scope() as db:
        assert chain.verify_records(chain.as_records(chain.load(db, iid)))["ok"]
        e = db.query(EvidenceEvent).filter(EvidenceEvent.incident_id == iid, EvidenceEvent.seq == 2).one()
        e.payload = {"n": 99}
    with session_scope() as db:
        res = chain.verify_records(chain.as_records(chain.load(db, iid)))
        assert not res["ok"] and any("payload modified" in p for p in res["problems"])
        db.query(EvidenceEvent).filter(EvidenceEvent.incident_id == iid).delete()
        db.query(Incident).filter(Incident.id == iid).delete()
