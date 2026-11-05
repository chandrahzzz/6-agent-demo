"use client";

import { ArrowLeft, ArrowRight, Radio } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useMemo } from "react";

import { AgentTimeline } from "@/components/agent-timeline";
import { PageHeader, Panel } from "@/components/panel";
import { ErrorState, LoadingBlock } from "@/components/states";
import { StatusChip } from "@/components/status";
import { Button } from "@/components/ui/button";
import { utc } from "@/lib/format";
import { useApi, useEventStream } from "@/lib/hooks";
import type { AgentExecution, Drill } from "@/lib/types";
import { cn } from "@/lib/utils";

export default function LiveRunPage() {
  const { id } = useParams<{ id: string }>();
  const drill = useApi<Drill>(["drill", id], `/drills/${id}`, { live: true, interval: 2000 });
  const running = drill.data?.status === "RUNNING" || drill.data?.status === "CREATED" || drill.data?.running;
  const { events, state } = useEventStream(`/api/v1/drills/${id}/events`);
  const execs = useApi<{ items: AgentExecution[] }>(["drill", id, "agents", drill.data?.incident_id ?? "none"],
    drill.data?.incident_id ? `/incidents/${drill.data.incident_id}/agents` : null, { live: !!running, interval: 2000 });

  // Executions known from SSE before the incident exists (the Hunter runs first).
  const timeline = useMemo<AgentExecution[]>(() => {
    const fromApi = execs.data?.items ?? [];
    const known = new Set(fromApi.map((e) => e.id));
    const byExec = new Map<string, AgentExecution>();
    for (const ev of events) {
      if (!ev.execution_id || known.has(ev.execution_id) || !ev.agent) continue;
      const cur = byExec.get(ev.execution_id) ?? { id: ev.execution_id, agent: ev.agent, status: "RUNNING", attempt: 1, started_at: ev.ts,
        finished_at: null, duration_ms: null, confidence: null, decision_summary: null, evidence_refs: [], error: null, incident_id: null, drill_id: id };
      if (ev.kind === "agent.completed") Object.assign(cur, { status: "COMPLETED", decision_summary: ev.message, duration_ms: (ev.data.duration_ms as number) ?? null,
        confidence: (ev.data.confidence as number) ?? null, evidence_refs: (ev.data.evidence_refs as string[]) ?? [] });
      if (ev.kind === "agent.failed") Object.assign(cur, { status: "FAILED", error: ev.message });
      byExec.set(ev.execution_id, cur);
    }
    return [...fromApi, ...byExec.values()].sort((a, b) => a.started_at.localeCompare(b.started_at));
  }, [events, execs.data, id]);
  const beats = events.filter((e) => e.kind === "beat" || e.kind.startsWith("drill."));

  if (drill.isLoading) return <LoadingBlock rows={6} />;
  if (drill.isError) return <ErrorState error={drill.error} retry={() => drill.refetch()} />;
  const d = drill.data!;
  return (
    <>
      <Button asChild variant="ghost" size="sm" className="-ml-2 mb-3 gap-1.5 text-fg-muted">
        <Link href="/drills"><ArrowLeft className="size-4" aria-hidden /> Breach Drill Lab</Link>
      </Button>
      <PageHeader eyebrow={`Live agent run · ${d.scenario_id}`} title={d.demo ? "Demo Mode" : `Drill ${d.scenario_id}`}
        description={`Variant ${String(d.params.access_variant ?? "—")} · seed ${d.seed} · started ${utc(d.started_at ?? d.created_at)}${d.auto_approve ? " · presenter auto-approve ON (recorded in evidence)" : ""}`}
        actions={<>
          <span className={cn("inline-flex items-center gap-1.5 font-mono text-xs", state === "open" ? "text-ok" : "text-fg-subtle")}>
            <Radio className={cn("size-3.5", state === "open" && running && "animate-pulse-dot")} aria-hidden /> {state === "open" ? "live" : state}
          </span>
          <StatusChip status={d.status} />
          {d.incident_id && <Button asChild size="sm" className="gap-1.5"><Link href={`/incidents/${d.incident_id}`}>Open incident <ArrowRight className="size-3.5" aria-hidden /></Link></Button>}
        </>} />
      {d.error && <div className="mb-4"><ErrorState error={new Error(d.error)} /></div>}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
        <Panel title="Six agents" meta="Server-Sent Events from the agent runtime; replayed on reconnect.">
          <AgentTimeline executions={timeline} steps={events} />
        </Panel>
        <Panel title="Story beats" bodyClassName="p-0">
          <ol className="max-h-[640px] divide-y divide-line overflow-y-auto" aria-live="polite">
            {beats.length === 0 && <li className="px-4 py-3 text-meta text-fg-subtle">Waiting for the first event…</li>}
            {beats.map((b) => (
              <li key={b.id} className="animate-reveal px-4 py-2.5">
                <p className="font-mono text-xs text-fg-subtle">{utc(b.ts, false)}</p>
                <p className={cn("text-meta", b.message.includes("VERIFIED_FIXED") ? "text-ok" : b.message.includes("PARTIALLY_FIXED") ? "text-warning" : "text-fg")}>{b.message}</p>
              </li>
            ))}
          </ol>
        </Panel>
      </div>
    </>
  );
}
