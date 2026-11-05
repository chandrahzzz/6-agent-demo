"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Activity, Download, Play } from "lucide-react";
import { useMemo, useState } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { toast } from "sonner";

import { Metric, PageHeader, Panel } from "@/components/panel";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/states";
import { StatusChip } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { post } from "@/lib/api";
import { ms, utc } from "@/lib/format";
import { canApprove, useApi, useMe } from "@/lib/hooks";
import { cn } from "@/lib/utils";

type Ratio = { value: number | null; n: number };
type SetMetrics = {
  sample_size: number; failed_runs: number;
  detection: { tp: number; fp: number; fn: number; precision: number | null; recall: number | null; f1: number; decoy_false_positives: number };
  verdict_accuracy: Ratio; verdict_accuracy_attempt_vs_success: Ratio; root_cause_accuracy: Ratio; blast_radius_accuracy: Ratio;
  fingerprint_accuracy: Ratio; remediation_correctness: Ratio; approval_compliance: Ratio; idempotency: Ratio;
  verification_accuracy: Ratio; residual_exposure_detection: Ratio; lite_recommendations: Ratio;
  timings_mean_ms: Record<string, number>;
  composite: { value: number; parts: Record<string, number>; label: string };
};
type Run = { idx: number; set: string; scenario: string; params: Record<string, unknown>; duration_ms: number; failures: string[]; error?: string | null;
  skipped?: boolean; reason?: string; score?: { timings?: Record<string, number>; verdict?: { expected: string; got: string; correct: boolean };
    verification?: { first_got: string; final_got: string } } };
type Bench = { id: string; status: string; created_at: string; finished_at: string | null; config: Record<string, unknown>; runs: Run[];
  metrics: { main?: SetMetrics; holdout?: SetMetrics; llm_assisted?: SetMetrics; planned_runs?: number;
    holdout_frozen_detectors?: { frozen: boolean; tag?: string; changed?: string[]; reason?: string } } };

const pct = (r: Ratio) => (r.value === null ? "—" : `${Math.round(r.value * 100)}%`);

function MetricGrid({ m }: { m: SetMetrics }) {
  const d = m.detection;
  const tiles: [string, string, string][] = [
    ["Detection F1", d.f1.toFixed(2), `P ${d.precision ?? "—"} · R ${d.recall ?? "—"} · TP ${d.tp} FP ${d.fp} FN ${d.fn}`],
    ["Decoy false positives", String(d.decoy_false_positives), "SKU, invoice and QA-table decoys in every run"],
    ["Verdict accuracy", pct(m.verdict_accuracy), `n = ${m.verdict_accuracy.n} · attempt vs download ${pct(m.verdict_accuracy_attempt_vs_success)}`],
    ["Root-cause accuracy", pct(m.root_cause_accuracy), `n = ${m.root_cause_accuracy.n}`],
    ["Blast-radius accuracy", pct(m.blast_radius_accuracy), `n = ${m.blast_radius_accuracy.n} · exact record count`],
    ["Fingerprint accuracy", pct(m.fingerprint_accuracy), `n = ${m.fingerprint_accuracy.n} · match counts at known copies`],
    ["Remediation correctness", pct(m.remediation_correctness), `n = ${m.remediation_correctness.n}`],
    ["Approval compliance", pct(m.approval_compliance), `n = ${m.approval_compliance.n} · approval before execution`],
    ["Idempotency", pct(m.idempotency), `n = ${m.idempotency.n} · replayed approval does not act twice`],
    ["Verification accuracy", pct(m.verification_accuracy), `n = ${m.verification_accuracy.n} · first and final verdict`],
    ["Residual-exposure detection", pct(m.residual_exposure_detection), `n = ${m.residual_exposure_detection.n}`],
    ["Lite recommendations", pct(m.lite_recommendations), `n = ${m.lite_recommendations.n}`],
  ];
  return (
    <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
      {tiles.map(([l, v, h]) => <Metric key={l} label={l} value={v} hint={h} />)}
    </div>
  );
}

function TimingChart({ runs }: { runs: Run[] }) {
  const data = useMemo(() => {
    const by: Record<string, number[]> = {};
    for (const r of runs) {
      const t = r.score?.timings?.detect_to_verified_fix_wall_ms;
      if (t) (by[r.scenario] ??= []).push(t);
    }
    return Object.entries(by).map(([scenario, v]) => ({ scenario, seconds: +(v.reduce((a, b) => a + b, 0) / v.length / 1000).toFixed(1), n: v.length }))
      .sort((a, b) => b.seconds - a.seconds);
  }, [runs]);
  if (!data.length) return <p className="text-meta text-fg-subtle">No run reached VERIFIED_FIXED yet.</p>;
  return (
    <div className="h-[220px]" role="img" aria-label="Mean seconds from detection to verified fix, per scenario; values are listed in the run table below.">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ left: 8, right: 24, top: 4, bottom: 4 }} barCategoryGap={6}>
          <CartesianGrid horizontal={false} stroke="var(--border)" />
          <XAxis type="number" tick={{ fill: "var(--fg-subtle)", fontSize: 12 }} axisLine={false} tickLine={false} unit=" s" />
          <YAxis type="category" dataKey="scenario" width={72} tick={{ fill: "var(--fg-muted)", fontSize: 12, fontFamily: "var(--font-mono)" }}
            axisLine={false} tickLine={false} />
          <Tooltip cursor={{ fill: "var(--surface-2)" }}
            content={({ active, payload }) => active && payload?.[0] ? (
              <div className="rounded-sm border border-line bg-surface-2 px-3 py-2 text-xs shadow-soft">
                <p className="font-mono text-fg">{String(payload[0].payload.scenario)}</p>
                <p className="text-fg-muted">{String(payload[0].payload.seconds)} s mean · n = {String(payload[0].payload.n)}</p>
              </div>) : null} />
          <Bar dataKey="seconds" fill="var(--accent)" radius={[0, 4, 4, 0]} maxBarSize={18} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function RunTable({ runs }: { runs: Run[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[720px] text-left text-meta">
        <thead><tr className="border-b border-line">{["#", "Scenario", "Parameters", "Verdict", "First → final verification", "Time", "Result"].map((h) =>
          <th key={h} className="label-instrument px-3 py-2 font-normal">{h}</th>)}</tr></thead>
        <tbody>{runs.filter((r) => !r.skipped).map((r) => {
          const ok = !r.error && !r.failures.length;
          return (
            <tr key={`${r.set}-${r.idx}`} className="border-b border-line/60 align-top">
              <td className="px-3 py-2 font-mono text-xs text-fg-subtle">{r.idx}</td>
              <td className="px-3 py-2 font-mono text-xs text-fg">{r.scenario}</td>
              <td className="max-w-[260px] px-3 py-2 font-mono text-[0.6875rem] break-words text-fg-subtle">
                {Object.entries(r.params).map(([k, v]) => `${k}=${String(v)}`).join(" ")}</td>
              <td className="px-3 py-2">{r.score?.verdict ? <span className={cn("font-mono text-xs", r.score.verdict.correct ? "text-fg-muted" : "text-critical")}>{r.score.verdict.got ?? "—"}</span> : "—"}</td>
              <td className="px-3 py-2 font-mono text-xs text-fg-muted">{r.score?.verification ? `${r.score.verification.first_got} → ${r.score.verification.final_got}` : "—"}</td>
              <td className="px-3 py-2 font-mono text-xs text-fg-muted">{ms(r.duration_ms)}</td>
              <td className="px-3 py-2">{ok ? <StatusChip status="PASS" /> : (
                <div className="space-y-1"><StatusChip status="FAIL" />
                  {(r.error ? [r.error] : r.failures).map((f) => <p key={f} className="text-xs text-critical">{f}</p>)}</div>)}</td>
            </tr>
          );
        })}</tbody>
      </table>
    </div>
  );
}

function SetSection({ title, meta, m, runs }: { title: string; meta: React.ReactNode; m?: SetMetrics; runs: Run[] }) {
  if (!m) return null;
  const fails = runs.filter((r) => r.error || r.failures.length);
  return (
    <section className="space-y-4" aria-label={title}>
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div><h2 className="text-xl font-medium text-fg">{title}</h2><p className="text-meta text-fg-muted">{meta}</p></div>
        <div className="text-right">
          <p className="label-instrument">Composite</p>
          <p className="font-mono text-3xl tabular-nums text-fg">{m.composite.value.toFixed(1)}</p>
          <p className="text-xs text-fg-subtle">{m.composite.label}</p>
        </div>
      </div>
      <p className="font-mono text-xs text-fg-subtle">
        {Object.entries(m.composite.parts).map(([k, v]) => `${k.replace("_", " ")}: ${v}`).join(" · ")} · runs {m.sample_size} · failed {m.failed_runs}</p>
      <MetricGrid m={m} />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
        <Panel title="Detection to verified fix (mean seconds)" meta="Wall clock incl. presenter auto-approve; monotonic per stage.">
          <TimingChart runs={runs} />
        </Panel>
        <Panel title={`Failures (${fails.length})`} meta="Shown, never dropped." bodyClassName="p-0">
          {fails.length === 0 ? <p className="p-4 text-meta text-fg-subtle">No failures in this set.</p> : (
            <ul className="max-h-[260px] divide-y divide-line overflow-y-auto">{fails.map((r) => (
              <li key={`${r.set}-${r.idx}`} className="px-4 py-2"><span className="font-mono text-xs text-fg">#{r.idx} {r.scenario}</span>
                {(r.error ? [r.error] : r.failures).map((f) => <p key={f} className="text-xs text-critical">{f}</p>)}</li>))}</ul>
          )}
        </Panel>
      </div>
      <Panel title="Runs" bodyClassName="p-0"><RunTable runs={runs} /></Panel>
    </section>
  );
}

export default function BenchmarksPage() {
  const list = useApi<{ items: (Bench & { run_count: number })[] }>(["benchmarks"], "/benchmarks", { live: true, interval: 8000 });
  const [sel, setSel] = useState<string | null>(null);
  const id = sel ?? list.data?.items.find((b) => b.status === "COMPLETED")?.id ?? list.data?.items[0]?.id ?? null;
  const b = useApi<Bench>(["benchmark", id], id ? `/benchmarks/${id}` : null, { live: true, interval: 8000 });
  const { data: me } = useMe();
  const qc = useQueryClient();
  const [holdout, setHoldout] = useState(true);
  const start = useMutation({
    mutationFn: () => post<{ id: string }>("/benchmarks/run", { mode: "all", holdout, per_deep: 2 }),
    onSuccess: (r) => { toast.success("Benchmark started — this takes several minutes"); setSel(r.id); qc.invalidateQueries({ queryKey: ["benchmarks"] }); },
    onError: (e: Error) => toast.error(e.message),
  });
  const data = b.data;
  const fz = data?.metrics.holdout_frozen_detectors;
  return (
    <>
      <PageHeader eyebrow="Honest by design" title="Benchmarks"
        description="Every number comes from real drills against the sandbox. Failed runs are shown, never dropped. The same author wrote the scenarios and the detectors."
        actions={canApprove(me) && (
          <>
            <div className="flex items-center gap-2"><Switch id="ho" checked={holdout} onCheckedChange={setHoldout} /><Label htmlFor="ho" className="text-xs text-fg-muted">Include held-out set</Label></div>
            <Button size="sm" className="gap-1.5" onClick={() => start.mutate()} disabled={start.isPending}><Play className="size-3.5" aria-hidden /> Run benchmark</Button>
          </>
        )} />
      {list.isLoading && <LoadingBlock rows={4} />}
      {list.isError && <ErrorState error={list.error} retry={() => list.refetch()} />}
      {list.data && list.data.items.length === 0 && (
        <EmptyState icon={Activity} title="No benchmark runs yet" body="Run the benchmark to measure detection, verdicts, remediation and verification against hidden ground truth." />
      )}
      {list.data && list.data.items.length > 0 && (
        <div className="space-y-8">
          <div className="flex flex-wrap items-center gap-2">
            <span className="label-instrument mr-1">Runs</span>
            {list.data.items.map((x) => (
              <Button key={x.id} size="xs" variant={x.id === id ? "secondary" : "ghost"} aria-pressed={x.id === id} onClick={() => setSel(x.id)} className="gap-1.5 font-mono">
                {utc(x.created_at)} <StatusChip status={x.status} dot={false} className="h-4 border-0 bg-transparent px-0 text-[0.625rem]" />
                <span className="text-fg-subtle">{x.run_count} runs</span>
              </Button>
            ))}
          </div>
          {b.isLoading && <LoadingBlock rows={6} />}
          {data && (
            <>
              <Panel bodyClassName="flex flex-wrap items-center gap-x-6 gap-y-2 py-3">
                <StatusChip status={data.status} />
                <span className="font-mono text-xs text-fg-muted">{data.runs.length}/{data.metrics.planned_runs ?? "?"} runs · seed {String(data.config.benchmark_seed ?? "—")} · LLM {String(data.config.llm_provider ?? "local")}</span>
                <span className="ml-auto flex gap-2">
                  {(["csv", "json", "pdf"] as const).map((f) => (
                    <Button key={f} asChild size="xs" variant="outline"><a href={`/api/v1/benchmarks/${data.id}/export.${f}`}><Download className="size-3" aria-hidden /> {f.toUpperCase()}</a></Button>
                  ))}
                </span>
              </Panel>
              {!data.metrics.main && data.status === "RUNNING" && <LoadingBlock rows={3} />}
              <SetSection title="Main set" meta="Seeded variants of every scenario (attacker A/B, replica layout, cache state, record counts), decoys in every run."
                m={data.metrics.main} runs={data.runs.filter((r) => r.set === "main")} />
              <SetSection title="Held-out set"
                meta={<>Separate generator and seed. Detectors {fz?.frozen ? <>frozen at <span className="font-mono">{fz.tag}</span> (hashes match)</> :
                  <span className="text-critical">NOT frozen: {fz?.changed?.join(", ") || fz?.reason}</span>}.</>}
                m={data.metrics.holdout} runs={data.runs.filter((r) => r.set === "holdout")} />
              {data.runs.filter((r) => r.skipped).map((r) => <p key={r.reason} className="text-meta text-fg-subtle">{r.reason}</p>)}
            </>
          )}
        </div>
      )}
    </>
  );
}
