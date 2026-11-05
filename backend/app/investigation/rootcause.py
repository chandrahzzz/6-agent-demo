"""Root cause from git history + IAM policy-change events + MinIO audit (PutBucketPolicy)."""
from __future__ import annotations


def public_flips(diff: str) -> list[str]:
    """Buckets whose `public:` line became true in a unified diff of buckets.yaml."""
    bucket, out = None, []
    for line in diff.splitlines():
        if line.startswith(("+++", "---", "@@")):
            continue
        body = line[1:] if line[:1] in "+- " else line
        s = body.strip()
        if s.startswith("- name: "):
            bucket = s.split(": ", 1)[1]
        if line.startswith("+") and s == "public: true" and bucket:
            out.append(bucket)
    return out


def find_commit(bucket: str, commits_with_diffs: list[dict]) -> dict | None:
    """Most recent commit that set `bucket` public. commits ordered newest first."""
    for c in commits_with_diffs:
        if bucket in public_flips(c.get("diff", "")):
            return c
    return None


def correlate(bucket: str, commit: dict | None, iam_events: list[dict], audit_events: list[dict]) -> dict:
    changes = [e for e in iam_events if e.get("type") == "BucketPolicyChanged"
               and (e.get("target") == bucket or str(e.get("target", "")).startswith(bucket + "/"))
               and (e.get("details") or {}).get("anonymous") == "download"]
    audit = [e for e in audit_events if e.get("api") in ("PutBucketPolicy", "DeleteBucketPolicy") and e.get("bucket") == bucket]
    if commit:
        sync = next((e for e in changes if (e.get("details") or {}).get("commit") == commit["sha"]), None)
        return {
            "bucket": bucket, "kind": "CONFIG_COMMIT", "confidence": 0.95 if sync else 0.7,
            "commit": {k: commit.get(k) for k in ("sha", "author", "date", "subject")},
            "diff": commit.get("diff"),
            "policy_change_event": sync,
            "audit_corroboration": [{"ts": a["ts"].isoformat() if hasattr(a["ts"], "isoformat") else a["ts"],
                                     "api": a["api"], "principal": a.get("principal")} for a in audit][-3:],
            "statement": (f"commit {commit['sha'][:8]} \"{commit.get('subject')}\" by {commit.get('author')} set "
                          f"{bucket} public: true" + (f"; applied by {sync['principal']} at {sync['ts']}" if sync else "")),
        }
    manual = changes[-1] if changes else None
    if manual:
        return {
            "bucket": bucket, "kind": "OUT_OF_BAND_CHANGE", "confidence": 0.85, "commit": None, "diff": None,
            "policy_change_event": manual,
            "audit_corroboration": [{"ts": a["ts"].isoformat() if hasattr(a["ts"], "isoformat") else a["ts"],
                                     "api": a["api"], "principal": a.get("principal")} for a in audit][-3:],
            "statement": (f"{bucket} was opened outside infra-config by {manual['principal']} at {manual['ts']} "
                          f"({(manual.get('details') or {}).get('via', 'manual change')}); buckets.yaml still declares it private (drift)"),
        }
    return {"bucket": bucket, "kind": "UNKNOWN", "confidence": 0.2, "commit": None, "diff": None,
            "policy_change_event": None, "audit_corroboration": [],
            "statement": f"no commit or policy-change event explains why {bucket} is public"}
