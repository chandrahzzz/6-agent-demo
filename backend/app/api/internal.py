"""Internal endpoints. /internal/minio-audit is network-restricted to customer_net (excluding the
docker gateway, through which host-published traffic arrives) and requires the audit token."""
from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Request

from ..core.config import settings
from ..core.errors import ApiError
from ..investigation import ingest

router = APIRouter(prefix="/internal", include_in_schema=False)


def _allowed(ip: str | None) -> bool:
    if not ip:
        return False
    addr = ipaddress.ip_address(ip)
    for cidr in settings().internal_cidrs.split(","):
        net = ipaddress.ip_network(cidr.strip())
        if addr in net and addr != next(net.hosts()):  # .1 is the docker bridge gateway
            return True
    return False


@router.post("/minio-audit")
async def minio_audit(request: Request) -> dict:
    if not _allowed(request.client.host if request.client else None):
        raise ApiError(403, "forbidden", "Not reachable from this network.")
    import hmac

    sent = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(sent, settings().minio_audit_token):
        raise ApiError(401, "unauthenticated", "Bad audit token.")
    payload = await request.json()
    n = ingest.ingest_minio(payload)
    return {"stored": n}
