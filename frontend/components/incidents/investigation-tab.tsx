"use client";

import { GitCommitHorizontal, SearchX } from "lucide-react";

import { DiffView } from "@/components/diff";
import { KV, Panel } from "@/components/panel";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/states";
import { StatusChip } from "@/components/status";
import { bytes, num, utc } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { AccessBrief, Action, Investigation } from "@/lib/types";
import { cn } from "@/lib/utils";

function AccessRows({ title, rows, tone }: { title: string; rows: AccessBrief[]; tone: string }) {
  if (!rows.length) return null;
  return (
    <div>
      <p className="label-instrument mb-1.5">{title} · {rows.length}</p>
      <ul className="overflow-hidden rounded-sm border border-line bg-background/60 font-mono text-xs">
        {rows.map((r, i) => (
          <li key={i} className="flex flex-wrap gap-x-3 gap-y-0.5 border-b border-line/60 px-3 py-1.5 last:border-0">
            <span className="text-fg-subtle">{utc(r.ts, false)}</span>
            <span className="min-w-0 flex-1 break-all text-fg">{r.method} {r.path}</span>
            <span className={tone}>{r.status}</span>
            <span className="text-fg-muted">{bytes(r.bytes)}</span>
            <span className="w-full text-fg-subtle sm:w-auto">{r.remote_ip} · {r.origin}{r.cache ? ` · cache ${r.cache}` : ""} · {r.source}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function InvestigationTab({ incidentId }: { incidentId: string }) {
  const q = useApi<Investigation>(["inc", incidentId, "investigation"], `/incidents/${incidentId}/investigation`);
  const acts = useApi<{ items: Action[] }>(["inc", incidentId, "remediation"], `/incidents/${incidentId}/remediation`);
  if (q.isLoading) return <LoadingBlock rows={6} />;
  if (q.isError) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const inv = q.data;
  if (!inv || !inv.verdict) return <EmptyState icon={SearchX} title="Investigation has not run yet" />;
  const ev = inv.evidence;
  const patches = (acts.data?.items ?? []).filter((a) => a.patch_diff);
  return (
    <div className="space-y-4">
      <Panel title="Access verdict" meta="Computed from real log evidence. Being public is never treated as proof of exfiltration.">
        <div className="flex flex-wrap items-center gap-3">
          <StatusChip status={inv.verdict} className="h-7 text-sm" />
          <span className="font-mono text-xs text-fg-subtle">confidence {Math.round(inv.confidence * 100)}%</span>
        </div>
        <p className="mt-3 max-w-3xl text-sm text-fg">{inv.summary}</p>
        <ul className="mt-2 space-y-0.5 text-meta text-fg-muted">{ev.reasons.map((r) => <li key={r}>· {r}</li>)}</ul>
        <div className="mt-4 flex flex-wrap gap-2">
          {Object.entries(inv.log_coverage).filter(([k]) => ["nginx", "minio_audit"].includes(k)).map(([k, v]) => (
            <span key={k} className={cn("rounded-sm border px-2 py-1 font-mono text-xs", v ? "border-ok/40 text-ok" : "border-dashed border-unverified/60 text-unverified")}>
              {k === "nginx" ? "CDN access log" : "MinIO audit log"}: {v ? "covered" : "gap"}
            </span>
          ))}
          <span className="rounded-sm border border-line px-2 py-1 font-mono text-xs text-fg-muted">
            origin hits matched {String(inv.log_coverage.audit_records)}/{String(inv.log_coverage.origin_hits)}
          </span>
          <span className="rounded-sm border border-line px-2 py-1 font-mono text-xs text-fg-muted">window from {utc(ev.window_start)}</span>
          <span className="rounded-sm border border-line px-2 py-1 font-mono text-xs text-fg-muted">{ev.probe_requests_excluded} MALLYA probe requests excluded</span>
        </div>
        <div className="mt-4 space-y-4">
          <AccessRows title="External · successful download of a real object" rows={ev.external_success} tone="text-critical" />
          <AccessRows title="External · attempts without object bytes" rows={ev.external_attempts} tone="text-warning" />
          <AccessRows title="Known partner" rows={ev.partner} tone="text-info" />
          <AccessRows title="Internal" rows={ev.internal.filter((r) => r.source === "nginx")} tone="text-fg-muted" />
        </div>
      </Panel>

      {inv.root_cause.map((rc) => {
        const patch = patches.find((a) => (a.params as { bucket?: string }).bucket === rc.bucket);
        return (
          <Panel key={rc.bucket} title={<span className="flex items-center gap-2"><GitCommitHorizontal className="size-4 text-fg-subtle" aria-hidden /> Root cause · <span className="font-mono">{rc.bucket}</span></span>}
            actions={<StatusChip status={rc.kind === "CONFIG_COMMIT" ? "DETECTED" : "PARTIALLY_FIXED"} label={rc.kind.replaceAll("_", " ")} dot={false} />}>
            <p className="text-sm text-fg">{rc.statement}</p>
            <dl className="mt-3 grid gap-x-8 md:grid-cols-2">
              {rc.commit && (
                <div>
                  <KV k="Commit" v={rc.commit.sha} mono />
                  <KV k="Author" v={rc.commit.author} mono />
                  <KV k="Authored (UTC)" v={utc(rc.commit.date)} mono />
                  <KV k="Message" v={`“${rc.commit.subject}”`} />
                </div>
              )}
              <div>
                {rc.policy_change_event && (
                  <>
                    <KV k="Policy change" v={`${rc.policy_change_event.target} → anonymous ${rc.policy_change_event.details.anonymous}`} mono />
                    <KV k="Applied by" v={`${rc.policy_change_event.principal} · ${utc(rc.policy_change_event.ts)}`} mono />
                  </>
                )}
                <KV k="Corroboration" v={rc.audit_corroboration.length ? rc.audit_corroboration.map((a) => `${a.api} by ${a.principal ?? "?"} at ${utc(a.ts, false)}`).join("; ") : "none in MinIO audit window"} mono />
                <KV k="Confidence" v={`${Math.round(rc.confidence * 100)}%`} mono />
              </div>
            </dl>
            {(rc.diff || patch) && (
              <div className="mt-4 grid gap-3 lg:grid-cols-2">
                <DiffView diff={rc.diff} title={rc.commit ? `Offending commit ${rc.commit.sha.slice(0, 8)} · buckets.yaml` : "Offending change"} />
                <DiffView diff={patch?.patch_diff} title={patch ? `MALLYA patch (${patch.code}) · buckets.yaml` : "No config patch"} />
              </div>
            )}
          </Panel>
        );
      })}

      <Panel title="Log sources" meta="Events in the exposure window by source">
        <div className="flex flex-wrap gap-4 font-mono text-xs">
          {Object.entries(ev.events_by_source).map(([k, v]) => <span key={k} className="text-fg-muted">{k}: <span className="text-fg">{num(v)}</span></span>)}
        </div>
      </Panel>
    </div>
  );
}
