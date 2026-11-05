"use client";

import { Bot } from "lucide-react";
import Link from "next/link";

import { AGENT_LABEL } from "@/components/agent-timeline";
import { Metric, PageHeader, Panel } from "@/components/panel";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/states";
import { StatusChip } from "@/components/status";
import { ms, num, utc } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { AgentExecution, Page } from "@/lib/types";

const ROLE: Record<string, string> = {
  exposure_hunter: "Discovers assets, inspects permissions, runs deterministic detectors in the worker. Never uses the LLM as a detector.",
  investigation: "Correlates CDN + origin audit logs, IAM events and git history into an access verdict and root cause.",
  blast_radius: "Searches every known location with keyed fingerprints; maps records to consent; marks what it could not inspect.",
  remediation: "Proposes fixes for the cause, runs the safety check, executes approved actions only.",
  adversarial_verification: "Independent of remediation. Attacks the fix from outside and hunts for leftover copies.",
  compliance_evidence: "Drafts notices for human review and builds the signed, hash-chained evidence pack.",
};

type Summary = { agent: string; label: string; executions: number; failed: number; mean_duration_ms: number | null; last: AgentExecution | null };

export default function AgentsPage() {
  const s = useApi<{ items: Summary[] }>(["agents"], "/agents");
  const ex = useApi<Page<AgentExecution>>(["agents", "executions"], "/agents/executions?page_size=40");
  return (
    <>
      <PageHeader eyebrow="Orchestrated with LangGraph" title="Agents" description="Six agents with typed inputs and outputs, retries, timings and short decision summaries." />
      {s.isLoading && <LoadingBlock rows={4} />}
      {s.isError && <ErrorState error={s.error} retry={() => s.refetch()} />}
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {s.data?.items.map((a) => (
          <Panel key={a.agent} title={a.label} actions={a.last ? <StatusChip status={a.last.status} /> : undefined}>
            <p className="text-meta text-fg-muted">{ROLE[a.agent]}</p>
            <div className="mt-3 grid grid-cols-3 gap-2">
              <Metric className="px-3 py-2" label="Runs" value={num(a.executions)} />
              <Metric className="px-3 py-2" label="Failed" value={num(a.failed)} tone={a.failed ? "text-critical" : undefined} />
              <Metric className="px-3 py-2" label="Mean" value={ms(a.mean_duration_ms)} />
            </div>
          </Panel>
        ))}
      </div>
      <Panel title="Recent executions" className="mt-6" bodyClassName="p-0">
        {ex.isLoading ? <div className="p-4"><LoadingBlock rows={5} /></div> : !ex.data?.items.length ? (
          <div className="p-4"><EmptyState icon={Bot} title="No executions yet" /></div>
        ) : (
          <ul className="divide-y divide-line">{ex.data.items.map((e) => (
            <li key={e.id} className="grid gap-1 px-4 py-2.5 sm:grid-cols-[13rem_1fr_auto] sm:items-baseline sm:gap-4">
              <span className="text-meta text-fg">{AGENT_LABEL[e.agent]}<span className="block font-mono text-xs text-fg-subtle">{utc(e.started_at)} · {ms(e.duration_ms)}</span></span>
              <span className="text-meta text-fg-muted">{e.decision_summary ?? e.error}</span>
              <span className="flex items-center gap-2">{e.incident_id && <Link className="font-mono text-xs text-brand hover:underline" href={`/incidents/${e.incident_id}`}>incident</Link>}<StatusChip status={e.status} /></span>
            </li>
          ))}</ul>
        )}
      </Panel>
    </>
  );
}
