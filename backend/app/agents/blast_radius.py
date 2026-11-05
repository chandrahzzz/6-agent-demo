"""Blast Radius Agent: which records, where else they live, and how they are reachable.

A fingerprint match means the data is PRESENT at a location. Whether that copy is
accessible is a separate question answered by the Adversarial Verification Agent.
The CDN edge is modelled as an exposure PATH, not a data store: this agent has no
cache-inspection capability, so cached copies are reported as UNVERIFIED here.
"""
from __future__ import annotations

from sqlalchemy import select

from .. import connectors
from ..core.db import session_scope
from ..models import Asset, AssetRelationship, BlastRadius, Finding, Incident, SubjectSet
from .base import AgentOutput, Ctx


def known_locations(inv: dict) -> list[dict]:
    locs = []
    for b in inv["buckets"]:
        for o in b["objects"]:
            if o["key"].endswith((".csv", ".md", ".txt", ".json")):
                locs.append({"kind": "object", "ref": f"{b['name']}/{o['key']}"})
    for t in inv["tables"]:
        if t["name"] in ("customers", "marketing_campaign_members", "health_claims"):
            locs.append({"kind": "table", "ref": t["name"]})
    locs += [{"kind": "vendor", "ref": "northwind/contacts"}, {"kind": "vendor", "ref": "quicksummarize/uploads"}]
    return locs


def analyse(ctx: Ctx) -> AgentOutput:
    with session_scope() as db:
        inc = db.get(Incident, ctx.incident_id)
        etype, scope = inc.exposure_type, dict(inc.scope or {})
        fnds = db.execute(select(Finding).where(Finding.incident_id == inc.id,
                                                Finding.finding_type == "PUBLIC_OBJECT_WITH_IDENTIFIERS")).scalars().all()
        exposed = [(f.details["bucket"], f.details["key"]) for f in fnds]

    subjects: set[str] = set()
    categories: dict[str, int] = {}
    if etype == "CONSENT_MISMATCH":
        ctx.step("Fingerprinting withdrawn-consent subjects held at the vendor (inside the worker)")
        job = next(j for j in connectors.worker("GET", "/checks/consent-sync", params={"include_fingerprints": True})
                   if j["job_id"] == scope["job_id"])
        fps = job.get("withdrawn_at_vendor_fingerprints") or []
        subjects |= set(fps)
        categories = {"email": len(fps), "phone": len(fps)}
        with session_scope() as db:
            db.add(SubjectSet(incident_id=ctx.incident_id, label=f"withdrawn-at-vendor:{scope['vendor_store']}", fingerprints=fps))
    elif etype == "SHADOW_AI_UPLOAD":
        ctx.step("Fingerprinting the payloads held by the unapproved AI tool (inside the worker)")
        v = next(x for x in connectors.worker("GET", "/checks/egress", params={"include_fingerprints": True}) if x["vendor"] == scope["vendor"])
        fps = v.get("subject_fingerprints") or []
        subjects |= set(fps)
        categories = dict(v.get("categories") or {})
        with session_scope() as db:
            db.add(SubjectSet(incident_id=ctx.incident_id, label=f"received-by:{scope['vendor_store']}", fingerprints=fps))
    else:
        ctx.step(f"Fingerprinting {len(exposed)} exposed object(s) inside the worker")
    for b, k in exposed:
        r = connectors.worker("POST", "/scan/object", json={"bucket": b, "key": k, "include_fingerprints": True})
        fps = r.get("subject_fingerprints") or []
        subjects |= set(fps)
        for c, n in r["categories"].items():
            categories[c] = max(categories.get(c, 0), n)
        with session_scope() as db:
            db.add(SubjectSet(incident_id=ctx.incident_id, label=f"exposed:s3://{b}/{k}", fingerprints=fps))

    inv = connectors.worker("GET", "/inventory")
    locs = known_locations(inv)
    ctx.step(f"Searching {len(locs)} known locations for {len(subjects):,} subject fingerprints")
    res = connectors.worker("POST", "/fingerprints/search", json={"subject_fingerprints": sorted(subjects), "locations": locs},
                            timeout=300)["results"]
    consent = connectors.worker("POST", "/consent/breakdown", json={"subject_fingerprints": sorted(subjects)})

    public = {b["name"] for b in inv["buckets"] if b["public"]}
    locations, unverified = [], []
    for r in res:
        bucket = r["ref"].split("/", 1)[0] if r["kind"] == "object" else None
        rec = {"location": {"object": f"s3://{r['ref']}", "table": f"db://meridian/{r['ref']}",
                            "vendor": f"vendor://{r['ref']}"}[r["kind"]],
               "kind": r["kind"], "checked": r["checked"], "matches": r["matches"], "present": r["present"],
               "exposed_object": (bucket, r["ref"].split("/", 1)[1]) in exposed if bucket else False,
               "bucket_public": bucket in public if bucket else None,
               "role": ("system of record" if r["ref"] == "customers" else "exposed copy" if bucket in public
                        else "copy" if r["present"] else "searched, no match")}
        if not r["checked"]:
            rec["error"] = r.get("error")
            unverified.append({"location": rec["location"], "reason": f"could not be inspected ({r.get('error')})"})
        if r["kind"] == "vendor" and r["present"]:
            rec["role"] = "third-party copy"
        locations.append(rec)
    for b, k in exposed:
        unverified.append({"location": f"cdn://cdn.meridian.sandbox/{b}/{k}",
                           "reason": "CDN edge cache contents are not inspectable by blast radius; checked by adversarial verification"})
    with_data = [loc for loc in locations if loc["present"]]

    if etype in ("CONSENT_MISMATCH", "SHADOW_AI_UPLOAD"):
        src = scope.get("source_table") or "employee upload (personal API key)"
        dst = scope["vendor_store"]
        paths = [{"path": [src, scope.get("job_id") or "direct upload", f"vendor://{dst}"]}]
        graph = {"nodes": [
            {"id": "src", "label": src, "kind": "table" if scope.get("source_table") else "network", "status": "SYSTEM_OF_RECORD",
             "ref": src, "connector": "worker", "mock": True},
            {"id": "via", "label": scope.get("job_id") or (", ".join(scope.get("api_keys", [])) or "upload"), "kind": "cdn",
             "status": "PATH", "ref": "integration", "connector": "worker", "mock": True},
            {"id": "dst", "label": dst, "kind": "bucket", "status": "EXPOSED", "ref": f"vendor://{dst}", "connector": "mock-vendor",
             "mock": True}],
            "edges": [{"id": "e1", "source": "src", "target": "via", "kind": "read_by", "exposure_path": True},
                      {"id": "e2", "source": "via", "target": "dst", "kind": "sent_to", "exposure_path": True}]}
    else:
        paths = [{"path": ["Internet (anonymous)", "cdn.meridian.sandbox", b, k], "bucket": b, "object": k} for b, k in exposed]
        graph = _graph(locations, exposed, public)
    facts = {"record_count": len(subjects), "locations_with_data": len(with_data), "categories": sorted(categories),
             "consent": consent, "unverified": len(unverified)}
    summary = ctx.summarise("blast.summary", facts)
    with session_scope() as db:
        db.add(BlastRadius(incident_id=ctx.incident_id, record_count=len(subjects), data_categories=categories,
                           locations=locations, unverified=unverified, exposure_paths=paths, consent=consent, graph=graph))
    return AgentOutput(summary=summary, confidence=0.95 if not [u for u in unverified if not u["location"].startswith("cdn://")] else 0.75,
                       evidence_refs=[loc["location"] for loc in with_data],
                       data={"record_count": len(subjects), "categories": categories, "consent": consent,
                             "locations_with_data": [loc["location"] for loc in with_data], "unverified": unverified})


def _graph(locations: list[dict], exposed: list[tuple[str, str]], public: set[str]) -> dict:
    """React Flow-ready graph built from the asset registry + this incident's findings."""
    with session_scope() as db:
        assets = {a.id: a for a in db.execute(select(Asset)).scalars()}
        rels = db.execute(select(AssetRelationship)).scalars().all()
    exposed_buckets = {b for b, _ in exposed}
    data_buckets = {loc["location"][5:].split("/", 1)[0] for loc in locations if loc["kind"] == "object" and loc["present"]}
    keep = {a.id for a in assets.values() if a.kind in ("cdn", "network")
            or (a.kind == "bucket" and a.name in (exposed_buckets | data_buckets))}
    nodes, edges = [], []
    for aid in keep:
        a = assets[aid]
        status = ("EXPOSED" if a.name in exposed_buckets and a.name in public else
                  "PUBLIC" if a.name in public else "DATA_PRESENT" if a.name in data_buckets else
                  "PATH" if a.kind in ("cdn", "network") else "OK")
        nodes.append({"id": aid, "label": a.name, "kind": a.kind, "status": status, "ref": a.ref,
                      "connector": a.connector, "mock": a.is_mock})
    for loc in locations:
        if loc["kind"] == "table" and loc["present"]:
            nid = "t:" + loc["location"]
            nodes.append({"id": nid, "label": loc["location"].split("/")[-1], "kind": "table",
                          "status": "SYSTEM_OF_RECORD", "ref": loc["location"], "connector": "worker:postgres", "mock": True})
    for r in rels:
        if r.src_id in keep and r.dst_id in keep:
            hot = assets[r.dst_id].name in exposed_buckets or assets[r.src_id].kind == "network"
            edges.append({"id": r.id, "source": r.src_id, "target": r.dst_id, "kind": r.kind, "exposure_path": hot})
    return {"nodes": nodes, "edges": edges}
