"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Crosshair, RotateCw } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Panel } from "@/components/panel";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/states";
import { StatusChip } from "@/components/status";
import { Button } from "@/components/ui/button";
import { VerdictBanner } from "@/components/verdict-banner";
import { post } from "@/lib/api";
import { bytes, num, utc } from "@/lib/format";
import { canOperate, useApi, useMe } from "@/lib/hooks";
import type { CopyHunt, Probe, VerificationRun } from "@/lib/types";
import { cn } from "@/lib/utils";

const OUTCOME_TEXT: Record<string, string> = {
  ACCESSIBLE: "PUBLICLY ACCESSIBLE", DENIED: "BLOCKED", DNS_FAILURE: "DNS FAILURE · NOT A DENIAL", TIMEOUT: "TIMEOUT · NOT A DENIAL",
  CONNECTION_REFUSED: "REFUSED · NOT A DENIAL", SERVER_ERROR: "5XX · NOT A DENIAL", NOT_FOUND: "404 · INCONCLUSIVE",
};
const STATUS_TEXT: Record<number, string> = { 200: "OK", 206: "Partial", 403: "Forbidden", 401: "Unauthorized", 404: "Not Found", 500: "Server Error", 502: "Bad Gateway" };

function AttackRow({ p, i }: { p: Probe; i: number }) {
  const open = p.outcome === "ACCESSIBLE";
  const blocked = p.outcome === "DENIED";
  const legit = p.authenticated;
  return (
    <li className="animate-reveal border-b border-line/60 px-3 py-2 last:border-0" style={{ animationDelay: `${Math.min(i, 14) * 45}ms` }}>
      <div className="flex flex-wrap items-baseline gap-x-2 font-mono text-xs leading-5">
        <span className="text-fg-subtle">{utc(p.started_at, false)}</span>
        <span className={cn("rounded-[3px] px-1 text-[0.6875rem]", p.layer === "origin" ? "bg-info-soft text-info" : p.layer === "canary" ? "bg-surface-3 text-fg-muted" : legit ? "bg-ok-soft text-ok" : "bg-surface-3 text-fg-muted")}>
          {legit ? "AUTHORISED" : (p.layer ?? "edge").toUpperCase()}
        </span>
        <span className="min-w-0 break-all text-fg">{p.method} {p.path}</span>
      </div>
      <div className="mt-0.5 flex flex-wrap items-baseline gap-x-2 pl-[4.75rem] font-mono text-xs leading-5 max-sm:pl-0">
        <span className="text-fg-subtle" aria-hidden>→</span>
        <span className={cn(open && !legit && "text-critical", (blocked || (open && legit)) && "text-ok", !open && !blocked && "text-unverified")}>
          {p.status ?? "—"} {p.status ? STATUS_TEXT[p.status] ?? "" : ""}
        </span>
        <span className="text-fg-subtle">·</span>
        <span className={cn("font-medium", open && !legit && "text-critical", (blocked || (open && legit)) && "text-ok", !open && !blocked && "text-unverified")}>
          {legit ? (open ? "AUTHORISED ACCESS PRESERVED" : "AUTHORISED ACCESS BROKEN") : OUTCOME_TEXT[p.outcome] ?? p.outcome}
        </span>
        {p.served_from_cache && <span className="rounded-[3px] bg-warning-soft px-1 text-warning">CDN CACHE HIT</span>}
        {p.denial_source === "origin" && <span className="text-fg-subtle">origin AccessDenied</span>}
        <span className="ml-auto text-fg-subtle">{bytes(p.bytes)} · {p.duration_ms} ms</span>
      </div>
    </li>
  );
}

function CopyHuntTable({ rows }: { rows: CopyHunt[] }) {
  const relevant = rows.filter((r) => r.present || !r.checked);
  const clean = rows.length - relevant.length;
  return (
    <div>
      <ul className="divide-y divide-line">
        {relevant.map((r) => (
          <li key={r.location} className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 gap-y-1 px-4 py-2.5">
            <span className="min-w-0 font-mono text-xs break-all text-fg">{r.location}</span>
            <StatusChip status={r.status} className="row-span-2 self-center" />
            <span className="text-xs text-fg-subtle">
              fingerprint match {r.matches === null ? "n/a" : num(r.matches)} · accessible {r.accessible === null ? "unknown" : r.accessible ? "yes" : "no"}
              <span className="block text-fg-subtle/90">{r.evidence}</span>
            </span>
          </li>
        ))}
      </ul>
      {clean > 0 && <p className="border-t border-line px-4 py-2 text-xs text-fg-subtle">{clean} other location(s) searched: no fingerprint match.</p>}
    </div>
  );
}

export function VerificationTab({ incidentId, live }: { incidentId: string; live: boolean }) {
  const q = useApi<{ items: VerificationRun[] }>(["inc", incidentId, "verification"], `/incidents/${incidentId}/verification`, { live });
  const { data: me } = useMe();
  const qc = useQueryClient();
  const runs = q.data?.items ?? [];
  const [selId, setSelId] = useState<string | null>(null);
  const run = runs.find((r) => r.id === selId) ?? runs[runs.length - 1];
  const m = useMutation({
    mutationFn: () => post(`/verification/${incidentId}/run`),
    onSuccess: () => { toast.success("Verification started from external_net"); qc.invalidateQueries({ queryKey: ["inc", incidentId] }); },
    onError: (e: Error) => toast.error(e.message),
  });

  if (q.isLoading) return <LoadingBlock rows={6} />;
  if (q.isError) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  if (!run) {
    return <EmptyState icon={Crosshair} title="No verification yet"
      body="Verification runs after approved actions execute. It attacks the fix from outside the customer network and hunts for leftover copies." />;
  }
  const attacks = [...run.external_results, ...run.authorised_results];
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="label-instrument mr-1">Runs</span>
        {runs.map((r) => (
          <Button key={r.id} size="xs" variant={r.id === run.id ? "secondary" : "ghost"} onClick={() => setSelId(r.id)} aria-pressed={r.id === run.id}
            className="gap-1.5 font-mono">
            {r.ref} <StatusChip status={r.verdict ?? r.status} dot={false} className="h-4 border-0 bg-transparent px-0 text-[0.625rem]" />
          </Button>
        ))}
        {canOperate(me) && (
          <Button size="xs" variant="outline" className="ml-auto gap-1.5" onClick={() => m.mutate()} disabled={m.isPending || live}>
            <RotateCw className="size-3" aria-hidden /> Re-run verification
          </Button>
        )}
      </div>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
        <Panel title="External attack test" bodyClassName="p-0"
          meta={`From ${run.origin.network ?? "external_net"} ${run.origin.ips?.join(", ") ?? ""} · ${run.verifier_version ?? ""} · unauthenticated, through the public CDN`}>
          <ol className="max-h-[520px] overflow-y-auto bg-background/60" aria-label="Attack requests">
            {attacks.map((p, i) => <AttackRow key={`${p.probe_id}-${i}`} p={p} i={i} />)}
          </ol>
        </Panel>
        <Panel title="Copy and replica hunt" meta="Keyed-fingerprint search of every known location. Match = data present; accessibility tested separately." bodyClassName="p-0">
          <CopyHuntTable rows={run.copy_hunt} />
          {run.origin.network_selftest && (
            <div className="border-t border-line px-4 py-3">
              <p className="label-instrument mb-1">Verifier network self-test</p>
              <p className="mb-2 text-xs text-fg-subtle">From external_net the verifier must reach only the CDN edge.</p>
              <ul className="space-y-1 font-mono text-xs">
                {run.origin.network_selftest.map((c) => {
                  const edge = c.target.startsWith("cdn");
                  const good = edge ? c.reachable : !c.reachable;
                  return (
                    <li key={c.target} className="flex justify-between gap-3">
                      <span className="min-w-0 text-fg-muted">{c.target}<span className="block text-fg-subtle sm:ml-1 sm:inline">{edge ? "should be reachable" : "must be unreachable"}</span></span>
                      <span className={cn("shrink-0", good ? "text-ok" : "text-critical")}>{c.reachable ? "reachable" : c.result.toLowerCase().replace("_", " ")}</span>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}
        </Panel>
      </div>
      {run.verdict && <VerdictBanner verdict={run.verdict} residual={run.residual} reasons={run.reasons} runRef={run.ref} />}
    </div>
  );
}
