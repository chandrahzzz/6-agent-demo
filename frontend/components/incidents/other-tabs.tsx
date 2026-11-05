"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { FileText, ListTree, ScanSearch } from "lucide-react";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";

import { AgentTimeline } from "@/components/agent-timeline";
import { KV, Mono, Panel } from "@/components/panel";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/states";
import { StatusChip } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { post } from "@/lib/api";
import { ms, num, short, utc } from "@/lib/format";
import { canApprove, useApi, useMe } from "@/lib/hooks";
import type { AgentExecution, Draft, EvidenceEvent, EvidencePack, Finding, Incident, Obligation, TimelineItem } from "@/lib/types";
import { cn } from "@/lib/utils";

/* ---------------------------------------------------------------- overview */
export function OverviewTab({ inc, live }: { inc: Incident; live: boolean }) {
  const agents = useApi<{ items: AgentExecution[] }>(["inc", inc.id, "agents"], `/incidents/${inc.id}/agents`, { live });
  const timings = Object.entries(inc.timings ?? {}).filter(([k]) => k.endsWith("_ms"));
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_400px]">
      <div className="space-y-4">
        <Panel title="Summary">
          <p className="text-sm text-fg">{inc.summary}</p>
          <dl className="mt-3 grid gap-x-8 md:grid-cols-2">
            <div>
              <KV k="Detected (UTC)" v={utc(inc.detected_at)} mono />
              <KV k="Exposure began" v={utc(inc.exposure_started_at)} mono />
              <KV k="Verified fixed" v={utc(inc.verified_fixed_at)} mono />
            </div>
            <div>
              <KV k="Assets in scope" v={(inc.scope.buckets ?? []).join(", ") || "—"} mono />
              <KV k="Scenario" v={inc.scenario_id ?? "—"} mono />
              <KV k="Evidence events" v={num(inc.counts?.evidence_events)} mono />
            </div>
          </dl>
        </Panel>
        <Panel title="Agent run" meta="Short decision summaries only; no chain-of-thought is stored or shown.">
          {agents.isLoading ? <LoadingBlock rows={4} /> : agents.isError ? <ErrorState error={agents.error} /> : <AgentTimeline executions={agents.data?.items ?? []} />}
        </Panel>
      </div>
      <div className="space-y-4">
        <Panel title="Risk score" meta="Deterministic, explainable prioritisation. Not a breach probability.">
          <p className="font-mono text-3xl tabular-nums text-fg">{inc.risk_score}<span className="text-sm text-fg-subtle"> / 100</span>
            <StatusChip status={inc.severity} className="ml-3 align-middle" /></p>
          <ul className="mt-4 space-y-2.5">
            {inc.risk_factors.map((f) => (
              <li key={f.factor}>
                <div className="flex justify-between text-meta"><span className="text-fg-muted">{f.factor}</span>
                  <span className="font-mono tabular-nums text-fg">{f.points}<span className="text-fg-subtle">/{f.max}</span></span></div>
                <div className="mt-1 h-1.5 rounded-full bg-surface-3" aria-hidden>
                  <div className="h-full rounded-full bg-fg-muted" style={{ width: `${(f.points / f.max) * 100}%` }} />
                </div>
                <p className="mt-0.5 text-xs text-fg-subtle">{f.why}</p>
              </li>
            ))}
          </ul>
        </Panel>
        <Panel title="Measured timings" meta="Monotonic clock per stage; UTC for audit.">
          {timings.length ? (
            <dl>{timings.map(([k, v]) => <KV key={k} k={k.replace("_ms", "").replaceAll("_", " ")} v={ms(v)} mono />)}</dl>
          ) : <p className="text-meta text-fg-subtle">No stage has completed yet.</p>}
        </Panel>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- findings */
export function FindingsTab({ incidentId }: { incidentId: string }) {
  const q = useApi<{ items: Finding[]; suppressed: Finding[] }>(["inc", incidentId, "findings"], `/incidents/${incidentId}/findings`);
  if (q.isLoading) return <LoadingBlock rows={4} />;
  if (q.isError) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const { items = [], suppressed = [] } = q.data ?? {};
  const decoys = suppressed.filter((f) => f.finding_type === "DECOY_REJECTED");
  return (
    <div className="space-y-4">
      {items.length === 0 && <EmptyState icon={ScanSearch} title="No findings" />}
      {items.map((f) => (
        <Panel key={f.id} title={f.title} actions={<StatusChip status={f.severity} />} meta={<span className="font-mono">{f.asset_ref} · {f.detector}</span>}>
          {f.record_count !== null && <p className="text-meta text-fg-muted">{num(f.record_count)} records · categories {Object.entries(f.data_categories).map(([k, v]) => `${k} ${num(v)}`).join(", ")}</p>}
          {Object.keys(f.masked_samples).length > 0 && (
            <div className="mt-3 flex flex-wrap gap-2">
              {Object.entries(f.masked_samples).flatMap(([cat, s]) => s.map((x) => (
                <span key={cat + x} className="rounded-sm border border-line bg-background px-2 py-1 font-mono text-xs text-fg-muted"><span className="text-fg-subtle">{cat}</span> {x}</span>
              )))}
              <span className="self-center text-xs text-fg-subtle">masked samples only — raw values never leave the worker</span>
            </div>
          )}
          {f.details.columns && (
            <div className="mt-3 overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead><tr className="text-fg-subtle"><th className="py-1 pr-4 font-normal">column</th><th className="pr-4 font-normal">detector outcome</th><th className="pr-4 font-normal">match</th><th className="pr-4 font-normal">context</th><th className="font-normal">customer identifier</th></tr></thead>
                <tbody>{f.details.columns.filter((c) => c.category).map((c) => (
                  <tr key={c.column} className="border-t border-line/60"><td className="py-1 pr-4 text-fg">{c.column}</td><td className="pr-4 text-fg-muted">{c.category} · {c.outcome}</td>
                    <td className="pr-4">{num(c.matched)}/{num(c.total)}</td><td className="pr-4">{c.context_score.toFixed(2)}</td>
                    <td className={c.customer_identifier ? "text-critical" : "text-fg-subtle"}>{c.customer_identifier ? "yes" : "no"}</td></tr>
                ))}</tbody>
              </table>
            </div>
          )}
        </Panel>
      ))}
      {decoys.length > 0 && (
        <Panel title="Decoys correctly rejected" meta="Pattern matched, but column context and checksums show these are not customer identifiers." bodyClassName="p-0">
          <ul className="divide-y divide-line">
            {decoys.map((f) => (
              <li key={f.id} className="px-4 py-2.5">
                <span className="block font-mono text-xs text-fg">{f.asset_ref}</span>
                <span className="text-xs text-fg-subtle">{f.details.column?.column}: {f.details.column?.outcome} · {f.details.column?.reasons.join("; ")}</span>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  );
}

/* ---------------------------------------------------------------- evidence */
export function EvidenceTab({ incidentId, live }: { incidentId: string; live: boolean }) {
  const q = useApi<{ chain: { ok: boolean; events: number; head: string; problems: string[] }; events: EvidenceEvent[]; packs: EvidencePack[] }>(
    ["inc", incidentId, "evidence"], `/incidents/${incidentId}/evidence`, { live });
  const [open, setOpen] = useState<number | null>(null);
  if (q.isLoading) return <LoadingBlock rows={6} />;
  if (q.isError) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const d = q.data!;
  return (
    <div className="space-y-4">
      <div className="grid gap-3 md:grid-cols-3">
        <Panel title="Hash chain" bodyClassName="py-3"><StatusChip status={d.chain.ok ? "PASS" : "FAIL"} label={d.chain.ok ? "INTACT" : "BROKEN"} />
          <p className="mt-2 font-mono text-xs text-fg-muted">{d.chain.events} events · head {short(d.chain.head, 16)}</p></Panel>
        <Panel title="Signed packs" bodyClassName="py-3"><p className="font-mono text-2xl text-fg">{d.packs.length}</p>
          {d.packs[0] && <p className="font-mono text-xs text-fg-muted">latest key {d.packs[0].key_id}</p>}</Panel>
        <Panel title="Wording" bodyClassName="py-3"><p className="text-xs text-fg-muted">Cryptographically tamper-evident and audit-oriented. Not a statement of legal admissibility.</p></Panel>
      </div>
      {d.chain.problems.length > 0 && <ErrorState error={new Error(d.chain.problems.join("; "))} />}
      <Panel title="Evidence events" meta="event_hash = SHA-256(canonical(metadata + payload_hash + previous_event_hash))" bodyClassName="p-0">
        <ol className="divide-y divide-line">
          {d.events.map((e) => (
            <li key={e.seq}>
              <button type="button" onClick={() => setOpen(open === e.seq ? null : e.seq)} aria-expanded={open === e.seq}
                className="grid w-full grid-cols-[3rem_1fr] gap-x-3 px-4 py-2 text-left hover:bg-surface-2 sm:grid-cols-[3rem_9rem_1fr_auto]">
                <span className="font-mono text-xs text-fg-subtle">#{e.seq}</span>
                <span className="font-mono text-xs text-fg-subtle max-sm:hidden">{utc(e.ts, false)}</span>
                <span className="min-w-0 truncate text-meta text-fg">{e.event_type} <span className="text-fg-subtle">· {e.actor}</span></span>
                <Mono className="max-sm:col-start-2">{short(e.event_hash, 14)}</Mono>
              </button>
              {open === e.seq && (
                <div className="space-y-1 bg-background/60 px-4 py-3">
                  <KV k="previous_event_hash" v={e.previous_event_hash} mono />
                  <KV k="payload_hash" v={e.payload_hash} mono />
                  <KV k="event_hash" v={e.event_hash} mono />
                  <pre className="mt-2 max-h-64 overflow-auto rounded-sm border border-line p-2 font-mono text-xs text-fg-muted">{JSON.stringify(e.payload, null, 2)}</pre>
                </div>
              )}
            </li>
          ))}
        </ol>
      </Panel>
    </div>
  );
}

/* ---------------------------------------------------------------- timeline */
export function TimelineTab({ incidentId, live }: { incidentId: string; live: boolean }) {
  const q = useApi<{ items: TimelineItem[] }>(["inc", incidentId, "timeline"], `/incidents/${incidentId}/timeline`, { live });
  if (q.isLoading) return <LoadingBlock rows={6} />;
  if (q.isError) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const items = q.data?.items ?? [];
  if (!items.length) return <EmptyState icon={ListTree} title="No timeline yet" />;
  const tone = (k: string) => k.includes("external_success") ? "bg-critical" : k.includes("external") ? "bg-warning" : k === "commit" || k === "policy_change" ? "bg-info"
    : k.startsWith("verification") ? "bg-brand" : k.startsWith("remediation") || k.startsWith("approval") ? "bg-ok" : "bg-fg-subtle";
  return (
    <Panel title="Timeline (UTC)">
      <ol className="space-y-0">
        {items.map((t, i) => (
          <li key={i} className="relative grid grid-cols-[12px_1fr] gap-3 pb-3 sm:grid-cols-[12px_10.5rem_1fr]">
            {i < items.length - 1 && <span aria-hidden className="absolute top-3 bottom-0 left-[5px] w-px bg-line" />}
            <span aria-hidden className={cn("mt-1.5 size-[11px] rounded-full border-2 border-background", tone(t.kind))} />
            <span className="font-mono text-xs text-fg-subtle max-sm:col-start-2">{utc(t.ts)}</span>
            <span className="text-meta text-fg max-sm:col-start-2">{t.label}</span>
          </li>
        ))}
      </ol>
    </Panel>
  );
}

/* ---------------------------------------------------------------- drafts */
const obligationSchema = z.object({
  regime: z.string().min(1, "Choose a regime"),
  label: z.string().min(3, "Describe the obligation"),
  start_time: z.string().min(1, "Set the start time"),
  deadline_hours: z.coerce.number().positive("Must be positive").max(8760),
  note: z.string().max(2000).optional(),
});
type ObligationForm = z.input<typeof obligationSchema>;

function Countdown({ o }: { o: Obligation }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t); }, []);
  const due = new Date(o.start_time).getTime() + o.deadline_hours * 3600_000;
  const left = due - now;
  const h = Math.floor(Math.abs(left) / 3600_000), m = Math.floor((Math.abs(left) % 3600_000) / 60_000), s = Math.floor((Math.abs(left) % 60_000) / 1000);
  return <span className={cn("font-mono text-sm tabular-nums", left < 0 ? "text-critical" : left < 6 * 3600_000 ? "text-warning" : "text-fg")}>
    {left < 0 ? "overdue " : ""}{h}h {String(m).padStart(2, "0")}m {String(s).padStart(2, "0")}s</span>;
}

export function DraftsTab({ incidentId }: { incidentId: string }) {
  const q = useApi<{ items: Draft[]; obligations: Obligation[] }>(["inc", incidentId, "drafts"], `/incidents/${incidentId}/drafts`);
  const { data: me } = useMe();
  const qc = useQueryClient();
  const form = useForm<ObligationForm>({ resolver: zodResolver(obligationSchema), defaultValues: { regime: "", label: "", start_time: "", deadline_hours: "" as unknown as number } });
  const m = useMutation({
    mutationFn: (v: ObligationForm) => post(`/incidents/${incidentId}/obligations`, { ...v, start_time: new Date(v.start_time as string).toISOString() }),
    onSuccess: () => { toast.success("Obligation recorded; timer started"); form.reset(); qc.invalidateQueries({ queryKey: ["inc", incidentId, "drafts"] }); },
    onError: (e: Error) => toast.error(e.message),
  });
  if (q.isLoading) return <LoadingBlock rows={5} />;
  if (q.isError) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const { items = [], obligations = [] } = q.data ?? {};
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
      <div className="space-y-4">
        {items.length === 0 && <EmptyState icon={FileText} title="No drafts yet" />}
        {items.map((d) => (
          <Panel key={d.id} title={d.title} actions={<StatusChip status="PENDING" label={d.stamp} dot={false} className="max-w-full whitespace-normal" />}>
            <pre className="max-h-96 overflow-auto font-mono text-xs leading-5 whitespace-pre-wrap text-fg-muted">{d.body}</pre>
          </Panel>
        ))}
      </div>
      <div className="space-y-4">
        <Panel title="Obligations and timers" meta="MALLYA never decides that a law applies or sets a deadline. A timer starts only when a person records an obligation.">
          {obligations.length === 0 ? <p className="text-meta text-fg-subtle">No obligation recorded.</p> : (
            <ul className="space-y-3">{obligations.map((o) => (
              <li key={o.id} className="rounded-sm border border-line p-3">
                <p className="text-meta text-fg">{o.label} <span className="text-fg-subtle">· {o.regime}</span></p>
                <Countdown o={o} />
                <p className="mt-1 text-xs text-fg-subtle">set by {o.set_by} · start {utc(o.start_time)} · {o.deadline_hours}h</p>
              </li>
            ))}</ul>
          )}
        </Panel>
        {canApprove(me) && (
          <Panel title="Record an obligation">
            <form onSubmit={form.handleSubmit((v) => m.mutate(v))} className="space-y-3" noValidate>
              {([["regime", "Regime (e.g. CERT-In)", "text"], ["label", "Obligation, as decided by legal", "text"],
                ["start_time", "Clock starts (your local time)", "datetime-local"], ["deadline_hours", "Window in hours", "number"]] as const).map(([name, label, type]) => (
                <div key={name} className="space-y-1">
                  <Label htmlFor={`ob-${name}`}>{label}</Label>
                  <Input id={`ob-${name}`} type={type} {...form.register(name)} aria-invalid={!!form.formState.errors[name]} />
                  {form.formState.errors[name] && <p className="text-xs text-critical">{form.formState.errors[name]?.message}</p>}
                </div>
              ))}
              <Button type="submit" size="sm" disabled={m.isPending}>Record and start timer</Button>
            </form>
          </Panel>
        )}
      </div>
    </div>
  );
}
