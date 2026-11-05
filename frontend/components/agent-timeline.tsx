"use client";

import { Bot, CheckCircle2, CircleDashed, Loader2, XCircle } from "lucide-react";

import { ms, utc } from "@/lib/format";
import type { AgentEvent, AgentExecution } from "@/lib/types";
import { cn } from "@/lib/utils";

export const AGENT_LABEL: Record<string, string> = {
  exposure_hunter: "Exposure Hunter", investigation: "Investigation Agent", blast_radius: "Blast Radius Agent",
  remediation: "Remediation Agent", adversarial_verification: "Adversarial Verification Agent", compliance_evidence: "Compliance Evidence Agent",
};

/** Vertical timeline of agent executions; `steps` (live SSE events) are shown under the matching execution. */
export function AgentTimeline({ executions, steps = [] }: { executions: AgentExecution[]; steps?: AgentEvent[] }) {
  if (!executions.length) {
    return <p className="flex items-center gap-2 text-meta text-fg-subtle"><Bot className="size-4" aria-hidden /> No agent has run yet.</p>;
  }
  return (
    <ol className="relative space-y-0" aria-label="Agent run">
      {executions.map((e, i) => {
        const Icon = e.status === "COMPLETED" ? CheckCircle2 : e.status === "FAILED" ? XCircle : e.status === "RUNNING" ? Loader2 : CircleDashed;
        const mySteps = steps.filter((s) => s.execution_id === e.id && s.kind === "agent.step");
        return (
          <li key={e.id} className="animate-reveal relative grid grid-cols-[24px_1fr] gap-3 pb-5 last:pb-0" style={{ animationDelay: `${Math.min(i, 10) * 40}ms` }}>
            {i < executions.length - 1 && <span aria-hidden className="absolute top-6 bottom-0 left-[11px] w-px bg-line" />}
            <Icon aria-hidden className={cn("mt-0.5 size-6 rounded-full bg-background p-0.5",
              e.status === "COMPLETED" && "text-ok", e.status === "FAILED" && "text-critical", e.status === "RUNNING" && "animate-spin text-info")} />
            <div className="min-w-0">
              <div className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5">
                <p className="text-sm font-medium text-fg">{AGENT_LABEL[e.agent] ?? e.agent}</p>
                <span className="font-mono text-xs text-fg-subtle">{utc(e.started_at, false)}</span>
                {e.duration_ms !== null && <span className="font-mono text-xs text-fg-subtle">{ms(e.duration_ms)}</span>}
                {e.confidence !== null && <span className="font-mono text-xs text-fg-subtle">conf {Math.round(e.confidence * 100)}%</span>}
                {e.attempt > 1 && <span className="font-mono text-xs text-warning">attempt {e.attempt}</span>}
              </div>
              {e.decision_summary && <p className="mt-1 text-meta text-fg-muted">{e.decision_summary}</p>}
              {e.error && <p className="mt-1 font-mono text-xs text-critical">{e.error}</p>}
              {mySteps.length > 0 && (
                <ul className="mt-1.5 space-y-0.5 border-l border-line pl-3">
                  {mySteps.map((s) => <li key={s.id} className="font-mono text-xs text-fg-subtle">{utc(s.ts, false)} {s.message}</li>)}
                </ul>
              )}
              {e.evidence_refs?.length > 0 && (
                <p className="mt-1 truncate font-mono text-[0.6875rem] text-fg-subtle" title={e.evidence_refs.join("\n")}>evidence: {e.evidence_refs.slice(0, 3).join(" · ")}{e.evidence_refs.length > 3 ? ` +${e.evidence_refs.length - 3}` : ""}</p>
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
