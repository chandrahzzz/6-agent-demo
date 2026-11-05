"""Basic in-process token-bucket rate limiting for auth and action endpoints (single instance)."""
from __future__ import annotations

import threading
import time

from fastapi import Request

from .errors import ApiError

_lock = threading.Lock()
_buckets: dict[tuple[str, str], tuple[float, float]] = {}


def limiter(name: str, rate_per_min: int, burst: int):
    def dep(request: Request) -> None:
        ip = request.client.host if request.client else "unknown"
        key = (name, ip)
        now = time.monotonic()
        with _lock:
            tokens, last = _buckets.get(key, (float(burst), now))
            tokens = min(burst, tokens + (now - last) * rate_per_min / 60.0)
            if tokens < 1:
                _buckets[key] = (tokens, now)
                raise ApiError(429, "rate_limited", "Too many requests. Slow down and retry shortly.")
            _buckets[key] = (tokens - 1, now)
    return dep


login_limit = limiter("login", rate_per_min=10, burst=5)
action_limit = limiter("action", rate_per_min=120, burst=30)
