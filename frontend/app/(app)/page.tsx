"use client";

import { FlaskConical, LockKeyhole, ShieldCheck } from "lucide-react";
import Link from "next/link";

import { IncidentList } from "@/components/incidents/incident-list";
import { Metric, PageHeader, Panel } from "@/components/panel";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/states";
import { Button } from "@/components/ui/button";
import { ms, num } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { Dashboard } from "@/lib/types";
import { cn } from "@/lib/utils";

export default function DashboardPage() {
  const q = useApi<Dashboard>(["dashboard"], "/dashboard", { live: true, interval: 5000 });
  const d = q.data;
  return (
    <>
      <PageHeader eyebrow="Overview" title="Dashboard"
        description="Every number on this page is computed from stored incident, verification and benchmark runs." />
      {q.isError && <ErrorState error={q.error} retry={() => q.refetch()} />}
      {q.isLoading && <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">{Array.from({ length: 8 }).map((_, i) => <LoadingBlock key={i} rows={1} />)}</div>}
      {d && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
            <Metric label="Active incidents" value={num(d.active_incidents)} tone={d.active_incidents ? "text-warning" : undefined} />
            <Metric label="Critical exposures" value={num(d.critical_exposures)} tone={d.critical_exposures ? "text-critical" : undefined} />
            <Metric label="Assets monitored" value={num(d.assets)} hint={d.assets ? `${num(d.assets_exposed)} currently exposed` : "Run a drill to discover assets"} />
            <Metric label="Verified fixes" value={num(d.verified_fixes)} tone={d.verified_fixes ? "text-ok" : undefined}
              hint={`${num(d.verification_runs)} adversarial verification runs`} />
            <Metric label="Open verification checks" value={num(d.open_verification_checks)}
              hint="Latest verdict partially fixed, still exposed or unverified" />
            <Metric label="Mean time to detect" value={ms(d.mean_time_to_detect_ms)}
              hint={d.samples.detect ? `n = ${d.samples.detect} · scenario start → incident` : "No runs yet"} />
            <Metric label="Mean time to verified fix" value={ms(d.mean_time_to_verified_fix_ms)}
              hint={d.samples.verified_fix ? `n = ${d.samples.verified_fix} · wall clock incl. approval wait` : "No verified fixes yet"} />
            <Metric label="Benchmark composite" value={d.benchmark?.composite != null ? d.benchmark.composite.toFixed(1) : "—"}
              hint={d.benchmark ? "Project-defined score, not an industry standard" : "No benchmark run yet"} />
          </div>

          <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
            <Panel title="Recent incidents" actions={<Button asChild size="sm" variant="ghost"><Link href="/incidents">View all</Link></Button>} bodyClassName="p-0">
              {d.recent_incidents.length ? (
                <IncidentList items={d.recent_incidents} compact />
              ) : (
                <div className="p-4">
                  <EmptyState icon={FlaskConical} title="No incidents yet"
                    body="Run a breach drill. MALLYA plants a real exposure in the sandbox, attacks it, and lets the agents work."
                    action={<Button asChild size="sm"><Link href="/drills">Open Breach Drill Lab</Link></Button>} />
                </div>
              )}
            </Panel>
            <PrivacyStatus p={d.privacy} />
          </div>
        </div>
      )}
    </>
  );
}

function PrivacyStatus({ p }: { p: Dashboard["privacy"] }) {
  const audited = p.llm_calls + p.payloads_blocked;
  return (
    <Panel title="Privacy status" actions={<Button asChild size="sm" variant="ghost"><Link href="/privacy">Details</Link></Button>}>
      <div className="flex items-start gap-3">
        {p.headline_ok ? <ShieldCheck className="mt-0.5 size-5 text-ok" aria-hidden /> : <LockKeyhole className="mt-0.5 size-5 text-critical" aria-hidden />}
        <div>
          <p className={cn("text-base font-medium", p.headline_ok ? "text-fg" : "text-critical")}>
            {num(p.raw_identifiers_sent_to_ai)} raw identifiers sent to the AI
          </p>
          <p className="mt-1 text-xs text-fg-subtle">Computed over {num(audited)} gateway-audited model calls.</p>
        </div>
      </div>
      <dl className="mt-4 grid grid-cols-2 gap-3 border-t border-line pt-4">
        {[["Detected locally", p.detected_locally], ["Fingerprinted", p.fingerprinted], ["Payloads blocked", p.payloads_blocked],
          ["Privacy tests", p.tests ? `${p.tests.passed}/${p.tests.total}` : "not run"]].map(([k, v]) => (
          <div key={k as string}>
            <dt className="label-instrument">{k}</dt>
            <dd className="mt-1 font-mono text-sm tabular-nums text-fg">{typeof v === "number" ? num(v) : (v ?? "—")}</dd>
          </div>
        ))}
      </dl>
    </Panel>
  );
}
