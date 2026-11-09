"""Remediation dependency planning (pure, no database)."""
from types import SimpleNamespace as A

from app.remediation.deps import describe_blocked, execution_plan, is_open


def act(code, approval="PENDING", execution="NOT_STARTED", deps=()):
    return A(code=code, approval_status=approval, execution_status=execution, depends_on=list(deps))


def test_purge_waits_for_pending_dependency():
    order, blocked = execution_plan([act("ACT-03"), act("ACT-05", "APPROVED", deps=["ACT-03"])])
    assert order == []
    assert blocked == {"ACT-05": [{"code": "ACT-03", "state": "PENDING"}]}
    assert "ACT-03 is pending" in describe_blocked(blocked)


def test_approving_both_runs_dependency_first_even_with_higher_code():
    # a re-proposed replica fix (ACT-10) gets a higher code than the purge (ACT-05) waiting for it
    order, blocked = execution_plan([act("ACT-05", "APPROVED", deps=["ACT-10"]), act("ACT-10", "APPROVED")])
    assert order == ["ACT-10", "ACT-05"] and blocked == {}


def test_rejected_dependency_is_reported_not_silently_skipped():
    order, blocked = execution_plan([act("ACT-03", "REJECTED"), act("ACT-05", "APPROVED", deps=["ACT-03"])])
    assert order == [] and blocked["ACT-05"] == [{"code": "ACT-03", "state": "REJECTED"}]


def test_succeeded_dependency_unblocks():
    order, _ = execution_plan([act("ACT-03", "APPROVED", "SUCCEEDED"), act("ACT-05", "APPROVED", deps=["ACT-03"])])
    assert order == ["ACT-05"]


def test_open_excludes_rejected_superseded_and_done():
    assert is_open(act("A", "PENDING")) and is_open(act("A", "HELD")) and is_open(act("A", "APPROVED"))
    assert not is_open(act("A", "REJECTED")) and not is_open(act("A", "SUPERSEDED"))
    assert not is_open(act("A", "APPROVED", "SUCCEEDED"))
