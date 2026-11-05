"""Approval tokens: HMAC-signed proof, verified independently by the worker, that a human
approved this exact action with these exact parameters."""
from __future__ import annotations

import hashlib
import hmac
from datetime import timedelta

from mallya_common.canonical import canonical

from ..core.config import settings
from ..models import Approval, RemediationAction, now


def params_sha256(params: dict) -> str:
    return hashlib.sha256(canonical(params)).hexdigest()


def mint(action: RemediationAction, approval: Approval) -> dict:
    body = {"action_id": action.id, "action_type": action.action_type, "params_sha256": params_sha256(action.params),
            "approval_id": approval.id, "approved_by": approval.user_email,
            "expires_at": (now() + timedelta(minutes=15)).isoformat()}
    sig = hmac.new(settings().approval_signing_key.encode(), canonical(body), hashlib.sha256).hexdigest()
    return {**body, "signature": sig}
