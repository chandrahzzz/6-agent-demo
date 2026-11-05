from __future__ import annotations

import os
import time

import httpx
import pytest

BASE = os.environ.get("MALLYA_API", "http://localhost:8000/api/v1")
DEMO_PASSWORD = "mallya-demo-2026"


def login(email: str) -> httpx.Client:
    c = httpx.Client(base_url=BASE, timeout=60)
    r = c.post("/auth/login", json={"email": email, "password": DEMO_PASSWORD})
    assert r.status_code == 200, r.text
    return c


@pytest.fixture
def analyst() -> httpx.Client:
    return login("analyst@meridian.demo")


@pytest.fixture
def viewer() -> httpx.Client:
    return login("viewer@meridian.demo")


def wait_for(fn, timeout: float = 300, interval: float = 2.0, what: str = "condition"):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {what}; last={last!r}")


def wait_drill_idle(c: httpx.Client, drill_id: str, timeout: float = 300) -> dict:
    return wait_for(lambda: (lambda d: d if not d["running"] and d["status"] != "CREATED" else None)(c.get(f"/drills/{drill_id}").json()),
                    timeout, what=f"drill {drill_id}")


def wait_incident_idle(c: httpx.Client, incident_id: str, timeout: float = 300) -> dict:
    time.sleep(1)
    return wait_for(lambda: (lambda d: d if not d["busy"] else None)(c.get(f"/incidents/{incident_id}").json()),
                    timeout, what=f"incident {incident_id}")
