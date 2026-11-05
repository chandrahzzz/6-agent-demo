"""Access verdict from real log evidence. Pure functions (unit-tested).

Rules (in precedence order):
  LIKELY_EXFILTRATED            bytes of a real sensitive object were served (200/206, >0 bytes) to an external origin
  INSUFFICIENT_EVIDENCE         a required log source is missing for the window (and exfiltration not already proven)
  ACCESS_ATTEMPTED_NOT_SUCCESSFUL  external origins tried (LIST/HEAD/wrong keys/denied GETs) but got no object bytes
  ACCESSED_INTERNAL_ONLY        only internal / known-partner origins touched the data
  EXPOSED_NOT_ACCESSED          publicly reachable, but nothing in any log source
Being public is never, on its own, evidence of exfiltration.
MALLYA's own verifier probes (matching an issued run id from the verifier's address) are excluded.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field


@dataclass
class Origin:
    zone: str  # internal | partner | probe | external
    label: str
    role: str = "consumer"


def classify_ip(ip: str | None, networks: list[dict]) -> Origin:
    if not ip:
        return Origin("unknown", "unknown origin")
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return Origin("unknown", "unparseable origin")
    best = None
    for n in networks:
        net = ipaddress.ip_network(n["cidr"], strict=False)
        if addr in net and (best is None or net.prefixlen > best[0].prefixlen):
            best = (net, n)
    if not best:
        return Origin("external", "unknown external origin")
    n = best[1]
    return Origin(n["zone"], n["label"], n.get("role", "consumer"))


@dataclass
class Evidence:
    external_attempts: list[dict] = field(default_factory=list)
    external_success: list[dict] = field(default_factory=list)
    internal: list[dict] = field(default_factory=list)
    partner: list[dict] = field(default_factory=list)
    probe_excluded: int = 0
    by_source: dict = field(default_factory=dict)


def _dedupe_origin_minio(events: list[dict]) -> list[dict]:
    """A CDN MISS appears in both nginx and MinIO logs. Keep nginx as the edge record for
    requests that came through the CDN; keep MinIO-only records (direct origin access)."""
    edge = [e for e in events if e["source"] == "nginx"]
    out = list(edge)
    for e in events:
        if e["source"] != "minio_audit":
            continue
        dup = any(n["bucket"] == e["bucket"] and n["object_key"] == e["object_key"] and n["remote_ip"] == e["remote_ip"]
                  and abs((n["ts"] - e["ts"]).total_seconds()) <= 3 for n in edge)
        if not dup:
            out.append(e)
    return out


def collect(events: list[dict], sensitive_objects: set[tuple[str, str]], networks: list[dict],
            issued_probe_runs: set[str], verifier_ips: set[str]) -> Evidence:
    ev = Evidence()
    for e in events:
        ev.by_source[e["source"]] = ev.by_source.get(e["source"], 0) + 1
    for e in _dedupe_origin_minio([e for e in events if not e.get("synthetic_history")]):
        if e.get("probe_run_id") and e["probe_run_id"] in issued_probe_runs and e.get("remote_ip") in verifier_ips:
            ev.probe_excluded += 1
            continue
        o = classify_ip(e.get("remote_ip"), networks)
        rec = {**e, "zone": o.zone, "origin_label": o.label, "origin_role": o.role}
        if o.zone in ("external", "unknown"):
            if (e.get("method") == "GET" and e.get("status") in (200, 206) and (e.get("bytes") or 0) > 0
                    and (e.get("bucket"), e.get("object_key")) in sensitive_objects):
                ev.external_success.append(rec)
            else:
                ev.external_attempts.append(rec)
        elif o.zone == "partner":
            ev.partner.append(rec)
        elif o.zone == "probe":
            ev.probe_excluded += 1
        else:
            ev.internal.append(rec)
    return ev


def decide(ev: Evidence, coverage: dict) -> tuple[str, float, list[str]]:
    reasons: list[str] = []
    if ev.external_success:
        b = sum(e["bytes"] for e in ev.external_success)
        reasons.append(f"{len(ev.external_success)} external request(s) received {b:,} bytes of a sensitive object")
        return "LIKELY_EXFILTRATED", 0.93, reasons
    missing = [k for k, ok in coverage.items() if not ok]
    if missing:
        reasons.append("log source missing or incomplete: " + ", ".join(missing))
        return "INSUFFICIENT_EVIDENCE", 0.5, reasons
    if ev.external_attempts:
        codes = sorted({str(e.get("status")) for e in ev.external_attempts})
        reasons.append(f"{len(ev.external_attempts)} external request(s), status codes {', '.join(codes)}, "
                       "zero bytes of any sensitive object served")
        return "ACCESS_ATTEMPTED_NOT_SUCCESSFUL", 0.88, reasons
    if ev.internal or ev.partner:
        reasons.append(f"{len(ev.internal)} internal and {len(ev.partner)} known-partner request(s); no unknown external origin")
        return "ACCESSED_INTERNAL_ONLY", 0.85, reasons
    reasons.append("no request to the exposed paths in any log source during the exposure window")
    return "EXPOSED_NOT_ACCESSED", 0.8, reasons
