"""Common agent harness: typed records, timing, retries, SSE events, audit + evidence.

Agents expose only a short decision summary (never chain-of-thought). Summaries are
written through the privacy gateway, so even the local template provider is accounted for.
"""
from __future__ import annotations

import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field

from pydantic import BaseModel, Field

from .. import connectors
from ..audit.log import audit
from ..core import events
from ..core.db import session_scope
from ..evidence import chain
from ..models import AgentExecution, now
from ..privacy import gateway

AGENTS = {
    "exposure_hunter": "Exposure Hunter",
    "investigation": "Investigation Agent",
    "blast_radius": "Blast Radius Agent",
    "remediation": "Remediation Agent",
    "adversarial_verification": "Adversarial Verification Agent",
    "compliance_evidence": "Compliance Evidence Agent",
}


class AgentOutput(BaseModel):
    """Every agent returns this envelope. `data` holds the agent-specific typed result."""
    summary: str
    confidence: float | None = Field(default=None, ge=0, le=1)
    evidence_refs: list[str] = []
    data: dict = {}


@dataclass
class Ctx:
    agent: str
    incident_id: str | None
    drill_id: str | None
    execution_id: str
    t0: float = field(default_factory=time.monotonic)

    def step(self, message: str, **data) -> None:
        events.emit("agent.step", message, drill_id=self.drill_id, incident_id=self.incident_id, agent=self.agent,
                    execution_id=self.execution_id, data=data)

    def summarise(self, purpose: str, facts: dict) -> str:
        return gateway.complete(self.agent, purpose, {"task": purpose, "facts": facts}, incident_id=self.incident_id)


class AgentFailed(Exception):
    pass


def run(agent: str, fn: Callable[[Ctx], AgentOutput], *, incident_id: str | None, drill_id: str | None,
        input: dict | None = None, retries: int = 2) -> AgentOutput:
    with session_scope() as db:
        ex = AgentExecution(agent=agent, incident_id=incident_id, drill_id=drill_id, input=input or {}, status="RUNNING")
        db.add(ex)
        db.flush()
        exec_id = ex.id
    events.emit("agent.started", f"{AGENTS[agent]} started", drill_id=drill_id, incident_id=incident_id,
                agent=agent, execution_id=exec_id)
    t0 = time.monotonic()
    last_err: Exception | None = None
    for attempt in range(1, retries + 2):
        ctx = Ctx(agent, incident_id, drill_id, exec_id)
        try:
            out = fn(ctx)
            out = AgentOutput.model_validate(out)
            dur = round((time.monotonic() - t0) * 1000, 1)
            with session_scope() as db:
                ex = db.get(AgentExecution, exec_id)
                ex.status, ex.attempt, ex.finished_at, ex.duration_ms = "COMPLETED", attempt, now(), dur
                ex.confidence, ex.decision_summary = out.confidence, out.summary
                ex.output, ex.evidence_refs = out.data, out.evidence_refs
            events.emit("agent.completed", out.summary, drill_id=drill_id, incident_id=incident_id, agent=agent,
                        execution_id=exec_id, data={"duration_ms": dur, "confidence": out.confidence,
                                                    "evidence_refs": out.evidence_refs})
            if incident_id:
                chain.append(incident_id, "agent.completed", f"agent:{agent}",
                             {"agent": agent, "execution_id": exec_id, "summary": out.summary,
                              "confidence": out.confidence, "duration_ms": dur, "evidence_refs": out.evidence_refs})
            audit("agent.completed", actor=f"agent:{agent}", target_type="incident", target_id=incident_id,
                  details={"execution_id": exec_id, "duration_ms": dur})
            return out
        except (connectors.ConnectorError, TimeoutError) as exc:
            last_err = exc
            events.emit("agent.retry", f"attempt {attempt} failed ({exc}); retrying", drill_id=drill_id,
                        incident_id=incident_id, agent=agent, execution_id=exec_id)
            time.sleep(min(4, 1.5 * attempt))
        except gateway.PrivacyPolicyViolation as exc:
            last_err = exc
            break
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            traceback.print_exc()
            break
    dur = round((time.monotonic() - t0) * 1000, 1)
    msg = f"{type(last_err).__name__}: {last_err}"[:500]
    with session_scope() as db:
        ex = db.get(AgentExecution, exec_id)
        ex.status, ex.finished_at, ex.duration_ms, ex.error = "FAILED", now(), dur, msg
    events.emit("agent.failed", f"{AGENTS[agent]} failed: {msg}", drill_id=drill_id, incident_id=incident_id,
                agent=agent, execution_id=exec_id)
    if incident_id:
        chain.append(incident_id, "agent.failed", f"agent:{agent}", {"agent": agent, "execution_id": exec_id, "error": msg})
    raise AgentFailed(msg) from last_err
