"""Action dependency helpers. Pure functions over objects with code / approval_status /
execution_status / depends_on, so they are unit-tested without a database."""
from __future__ import annotations

OPEN_DECISIONS = ("PENDING", "HELD", "APPROVED")
WAITING = ("NOT_STARTED", "FAILED")


def is_open(a) -> bool:
    """Still able to take effect: not rejected/superseded and not yet succeeded."""
    return a.approval_status in OPEN_DECISIONS and a.execution_status != "SUCCEEDED"


def execution_plan(actions) -> tuple[list[str], dict[str, list[dict]]]:
    """Which approved actions would run now, in dependency order, and why the others would not.

    Returns (ordered codes that will run, {code: [{"code": dep, "state": why}]} for approved
    actions that are blocked by a dependency that is neither done nor runnable in this pass).
    """
    by_code = {a.code: a for a in actions}
    candidates = sorted((a for a in actions if a.approval_status == "APPROVED" and a.execution_status in WAITING),
                        key=lambda a: a.code)
    order: list[str] = []
    progress = True
    while progress:
        progress = False
        for a in candidates:
            if a.code in order:
                continue
            deps = [by_code.get(d) for d in (a.depends_on or [])]
            if all(d is not None and (d.execution_status == "SUCCEEDED" or d.code in order) for d in deps):
                order.append(a.code)
                progress = True
    blocked: dict[str, list[dict]] = {}
    for a in candidates:
        if a.code in order:
            continue
        reasons = []
        for d in a.depends_on or []:
            dep = by_code.get(d)
            if dep is None:
                reasons.append({"code": d, "state": "MISSING"})
            elif dep.execution_status != "SUCCEEDED" and dep.code not in order:
                state = dep.approval_status if dep.approval_status != "APPROVED" else dep.execution_status
                reasons.append({"code": d, "state": state})
        blocked[a.code] = reasons
    return order, blocked


def describe_blocked(blocked: dict[str, list[dict]]) -> str:
    parts = []
    for code, reasons in blocked.items():
        why = ", ".join(f"{r['code']} is {r['state'].lower().replace('_', ' ')}" for r in reasons) or "a dependency is unmet"
        parts.append(f"{code} waits for its dependency ({why})")
    return "; ".join(parts)
