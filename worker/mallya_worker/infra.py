"""sandbox/infra-config: a real git repo whose buckets.yaml drives bucket policy.

The sync pipeline is incremental (it applies only buckets that changed since the last
applied commit, like a targeted apply). Policy gates listed in .mallya/gates.yaml run
before anything is applied; a violating config is refused and nothing changes.
"""
from __future__ import annotations

import difflib
import importlib.util
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import yaml

from . import storage
from .config import settings

GATES_FILE = ".mallya/gates.yaml"
POLICY_PATH = Path("/app/policies/no_public_pii_buckets.py")


def repo() -> Path:
    return Path(settings().infra_config_dir)


def _git(*args: str, env: dict | None = None, cwd: Path | None = None) -> str:
    e = dict(os.environ)
    if env:
        e.update(env)
    proc = subprocess.run(["git", *args], cwd=cwd or repo(), env=e, capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        raise RuntimeError(f"git {args[0]} failed: {proc.stderr.strip()}")
    return proc.stdout


def _policy():
    spec = importlib.util.spec_from_file_location("no_public_pii_buckets", POLICY_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _bucket_block(name: str, classification: str, public: bool, extra: dict) -> str:
    lines = [f"  - name: {name}", f"    classification: {classification}", f"    public: {'true' if public else 'false'}"]
    for k, v in extra.items():
        lines.append(f"    {k}: {v}")
    return "\n".join(lines)


BASE_BUCKETS = [
    ("meridian-customer-backups", "pii", {"owner": "data-platform", "encryption": "sse-s3", "replicate_to": "meridian-backups-replica"}),
    ("meridian-archive", "pii", {"owner": "data-platform", "encryption": "sse-s3", "retention": "10y"}),
    ("meridian-exports", "confidential", {"owner": "finance-analytics", "encryption": "sse-s3"}),
    ("meridian-internal-docs", "internal", {"owner": "workplace-it", "encryption": "sse-s3"}),
]
REPLICA = ("meridian-backups-replica", "pii", {"owner": "data-platform", "encryption": "sse-s3", "replica_of": "meridian-customer-backups"})


def render(buckets: list[tuple[str, str, dict]], public: set[str]) -> str:
    head = "# Meridian Bank object storage (SANDBOX). Applied by the infra-sync pipeline.\n# Changes require review by data-platform.\nbuckets:\n"
    return head + "\n".join(_bucket_block(n, c, n in public, e) for n, c, e in buckets) + "\n"


@dataclass
class Author:
    name: str
    email: str


AUTHORS = {
    "priya": Author("priya.n", "priya.n@meridian-bank.test"),
    "arjun": Author("arjun.k", "arjun.k@meridian-bank.test"),
    "meera": Author("meera.s", "meera.s@meridian-bank.test"),
    "rahul": Author("dev.rahul", "dev.rahul@meridian-bank.test"),
    "mallya": Author("mallya-remediator", "mallya-remediator@meridian-bank.test"),
}


def commit(author: Author, when: datetime, message: str, files: dict[str, str]) -> str:
    for rel, text in files.items():
        p = repo() / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        _git("add", rel)
    stamp = when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+0000")
    env = {"GIT_AUTHOR_NAME": author.name, "GIT_AUTHOR_EMAIL": author.email, "GIT_AUTHOR_DATE": stamp,
           "GIT_COMMITTER_NAME": author.name, "GIT_COMMITTER_EMAIL": author.email, "GIT_COMMITTER_DATE": stamp}
    _git("commit", "-q", "-m", message, env=env)
    return head()


def head() -> str:
    return _git("rev-parse", "HEAD").strip()


def init_history(now: datetime) -> list[str]:
    """Rebuild the repo with a deterministic history (contents fixed; dates relative to now)."""
    r = repo()
    r.mkdir(parents=True, exist_ok=True)
    for child in r.iterdir():
        shutil.rmtree(child) if child.is_dir() else child.unlink()
    _git("init", "-q", "-b", "main")
    shas = []
    readme = "# infra-config (SANDBOX)\n\nDeclarative storage policy for Meridian Bank. `buckets.yaml` is applied by infra-sync.\n"
    shas.append(commit(AUTHORS["priya"], now - timedelta(days=30), "initial storage layout",
                       {"README.md": readme, "buckets.yaml": render(BASE_BUCKETS[:1] + BASE_BUCKETS[3:], set()),
                        GATES_FILE: "gates: []\n"}))
    shas.append(commit(AUTHORS["arjun"], now - timedelta(days=21), "add archive bucket and retention tags",
                       {"buckets.yaml": render(BASE_BUCKETS[:2] + BASE_BUCKETS[3:], set())}))
    shas.append(commit(AUTHORS["meera"], now - timedelta(days=12), "add exports bucket for finance reporting",
                       {"buckets.yaml": render(BASE_BUCKETS, set())}))
    shas.append(commit(AUTHORS["arjun"], now - timedelta(days=6), "enable replication for customer backups",
                       {"buckets.yaml": render(BASE_BUCKETS[:1] + [REPLICA] + BASE_BUCKETS[1:], set())}))
    _write_last_sync(head())
    return shas


def current_buckets_public() -> set[str]:
    cfg = yaml.safe_load((repo() / "buckets.yaml").read_text())
    return {b["name"] for b in cfg["buckets"] if b.get("public")}


def all_buckets() -> list[tuple[str, str, dict]]:
    return BASE_BUCKETS[:1] + [REPLICA] + BASE_BUCKETS[1:]


def set_public(bucket: str, public: bool) -> str:
    """Return buckets.yaml text with one bucket's `public:` line changed (preserves the rest)."""
    lines = (repo() / "buckets.yaml").read_text().splitlines(keepends=True)
    out, in_block = [], False
    for line in lines:
        if line.startswith("  - name: "):
            in_block = line.strip() == f"- name: {bucket}"
        if in_block and line.strip().startswith("public:"):
            line = f"    public: {'true' if public else 'false'}\n"
        out.append(line)
    return "".join(out)


def unified_diff(path: str, new_text: str) -> str:
    old = (repo() / path).read_text()
    return "".join(difflib.unified_diff(old.splitlines(keepends=True), new_text.splitlines(keepends=True),
                                        fromfile=f"a/{path}", tofile=f"b/{path}"))


def log(limit: int = 50) -> list[dict]:
    fmt = "%H%x1f%an%x1f%ae%x1f%aI%x1f%s"
    out = []
    for line in _git("log", f"-n{limit}", f"--format={fmt}").splitlines():
        sha, an, ae, date, subject = line.split("\x1f")
        out.append({"sha": sha, "author": an, "email": ae, "date": date, "subject": subject})
    return out


def show(sha: str, path: str = "buckets.yaml") -> dict:
    if not all(c in "0123456789abcdef" for c in sha) or not (7 <= len(sha) <= 40):
        raise ValueError("bad sha")
    diff = _git("show", "--format=", sha, "--", path)
    meta = log_one(sha)
    return {**meta, "path": path, "diff": diff}


def log_one(sha: str) -> dict:
    fmt = "%H%x1f%an%x1f%ae%x1f%aI%x1f%s"
    sha_, an, ae, date, subject = _git("show", "-s", f"--format={fmt}", sha).strip().split("\x1f")
    return {"sha": sha_, "author": an, "email": ae, "date": date, "subject": subject}


def _last_sync_file() -> Path:
    return repo() / ".git" / "mallya-last-sync"


def _write_last_sync(sha: str) -> None:
    _last_sync_file().write_text(sha)


def enabled_gates() -> list[str]:
    p = repo() / GATES_FILE
    if not p.exists():
        return []
    return list((yaml.safe_load(p.read_text()) or {}).get("gates") or [])


def run_gates(text: str, gates: list[str]) -> list[dict]:
    violations: list[dict] = []
    if "no_public_pii_buckets" in gates:
        violations += _policy().evaluate_text(text)
    return violations


def _iam_event(event: dict) -> None:
    s = settings()
    httpx.post(f"{s.mock_iam_url}/events", json=event, headers={"X-Mock-IAM-Token": s.mock_iam_token}, timeout=5)


def sync(actor: str = "infra-sync") -> dict:
    """Incremental apply of buckets.yaml (changed buckets since last applied commit)."""
    cur = head()
    last = _last_sync_file().read_text().strip() if _last_sync_file().exists() else None
    text = (repo() / "buckets.yaml").read_text()
    gates = enabled_gates()
    violations = run_gates(text, gates)
    if violations:
        _iam_event({"type": "SyncBlockedByPolicy", "principal": actor, "target": "buckets.yaml",
                    "details": {"commit": cur, "violations": violations}})
        return {"status": "BLOCKED", "commit": cur, "gates": gates, "violations": violations, "applied": []}
    new_cfg = {b["name"]: b for b in yaml.safe_load(text)["buckets"]}
    old_cfg = {}
    if last:
        try:
            old_cfg = {b["name"]: b for b in yaml.safe_load(_git("show", f"{last}:buckets.yaml"))["buckets"]}
        except RuntimeError:
            old_cfg = {}
    applied = []
    for name, b in new_cfg.items():
        if old_cfg.get(name, {}).get("public") == b.get("public") and last:
            continue
        perm = "download" if b.get("public") else "none"
        storage.set_anonymous(actor, name, perm)
        applied.append({"bucket": name, "anonymous": perm})
        _iam_event({"type": "BucketPolicyChanged", "principal": actor, "target": name,
                    "details": {"anonymous": perm, "commit": cur, "via": "infra-sync"}})
    _write_last_sync(cur)
    return {"status": "APPLIED", "commit": cur, "gates": gates, "violations": [], "applied": applied}


def check_reapply(bad_sha: str) -> dict:
    """Prove the policy gate rejects the bad commit if reintroduced: cherry-pick it in a scratch
    clone and run the gates that are now enabled. Never touches the live repo or storage."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp) / "clone"
        subprocess.run(["git", "clone", "-q", str(repo()), str(scratch)], check=True, capture_output=True, timeout=30)
        env = {"GIT_AUTHOR_NAME": "mallya-regression", "GIT_AUTHOR_EMAIL": "regression@mallya.test",
               "GIT_COMMITTER_NAME": "mallya-regression", "GIT_COMMITTER_EMAIL": "regression@mallya.test"}
        try:
            _git("cherry-pick", "--strategy=recursive", "-X", "theirs", bad_sha, env=env, cwd=scratch)
            reapplied = True
        except RuntimeError:
            # A conflict-free re-application isn't possible; re-apply the bad change textually instead.
            reapplied = False
        text = (scratch / "buckets.yaml").read_text()
        if not reapplied:
            diff = _git("show", "--format=", bad_sha, "--", "buckets.yaml", cwd=scratch)
            text = _apply_publics_from_diff(text, diff)
        gates = list((yaml.safe_load((scratch / GATES_FILE).read_text()) or {}).get("gates") or [])
        violations = run_gates(text, gates)
    return {"bad_commit": bad_sha, "gates": gates, "blocked": bool(violations), "violations": violations,
            "method": "cherry-pick in scratch clone" if reapplied else "textual re-application in scratch clone"}


def _apply_publics_from_diff(text: str, diff: str) -> str:
    # Find which bucket blocks the bad commit set public: true in, and do the same.
    bucket, targets = None, []
    for line in diff.splitlines():
        s = line[1:].strip() if line[:1] in "+- " else line.strip()
        if s.startswith("- name: "):
            bucket = s.split(": ", 1)[1]
        if line.startswith("+") and s == "public: true" and bucket:
            targets.append(bucket)
    lines, out, cur = text.splitlines(keepends=True), [], None
    for line in lines:
        if line.startswith("  - name: "):
            cur = line.strip()[len("- name: "):]
        if cur in targets and line.strip().startswith("public:"):
            line = "    public: true\n"
        out.append(line)
    return "".join(out)
