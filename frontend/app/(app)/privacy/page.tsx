"use client";

import { LockKeyhole, ShieldCheck, ShieldX } from "lucide-react";

import { Metric, PageHeader, Panel } from "@/components/panel";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/states";
import { StatusChip } from "@/components/status";
import { num, utc } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { Page, PrivacySummary } from "@/lib/types";
import { cn } from "@/lib/utils";

type TestRun = { ts: string; passed: number; total: number; source: string; results: { id: string; name: string; passed: boolean; detail: string }[] };
type Call = { id: string; ts: string; agent: string; provider: string; model: string; purpose: string; shared_fields: string[]; payload_bytes: number; blocked: boolean; dlp_findings: Record<string, number> };
type Violation = { id: string; ts: string; agent: string; rule: string; detectors: Record<string, number>; field_paths: string[]; action: string; is_test: boolean };

export default function PrivacyPage() {
  const s = useApi<PrivacySummary>(["privacy"], "/privacy/summary");
  const t = useApi<TestRun>(["privacy", "tests"], "/privacy/tests");
  const calls = useApi<Page<Call>>(["privacy", "calls"], "/privacy/llm-calls?page_size=25");
  const vio = useApi<Page<Violation>>(["privacy", "violations"], "/privacy/violations?page_size=25");
  const p = s.data;
  return (
    <>
      <PageHeader eyebrow="Zero raw identifiers to the LLM" title="Privacy Boundary"
        description="The customer-side worker reads, detects, masks and fingerprints locally. Only metadata crosses to the control plane, and every model call passes schema validation and outbound DLP first." />
      {s.isLoading && <LoadingBlock rows={3} />}
      {s.isError && <ErrorState error={s.error} retry={() => s.refetch()} />}
      {p && (
        <div className="space-y-6">
          <div className={cn("flex flex-wrap items-center gap-4 rounded-md border-2 px-5 py-4", p.headline_ok ? "border-ok/40 bg-ok-soft" : "border-critical/50 bg-critical-soft")}>
            {p.headline_ok ? <ShieldCheck className="size-8 text-ok" aria-hidden /> : <ShieldX className="size-8 text-critical" aria-hidden />}
            <div>
              <p className="font-mono text-2xl font-semibold text-fg">{num(p.raw_identifiers_sent_to_ai)} raw identifiers sent to the AI.</p>
              <p className="text-meta text-fg-muted">Computed from {num(p.llm_calls + p.payloads_blocked)} audited calls: payloads that passed DLP carried zero identifier candidates; blocked payloads never left.</p>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
            <Metric label="Detected locally" value={num(p.detected_locally)} hint={p.worker_available ? "by the customer-side worker" : "worker unavailable"} />
            <Metric label="Masked samples" value={num(p.masked)} />
            <Metric label="Fingerprinted" value={num(p.fingerprinted)} hint="HMAC-SHA256, versioned key" />
            <Metric label="LLM calls made" value={num(p.llm_calls)} hint={Object.entries(p.llm_calls_by_provider).map(([k, v]) => `${k} ${v}`).join(" · ") || "none"} />
            <Metric label="Payloads blocked" value={num(p.payloads_blocked)} hint="by schema check or outbound DLP" />
            <Metric label="Violations (non-test)" value={num(p.violations)} tone={p.violations ? "text-critical" : undefined} />
            <Metric label="Privacy tests" value={p.tests ? `${p.tests.passed}/${p.tests.total}` : "—"} tone={p.tests && p.tests.passed === p.tests.total ? "text-ok" : undefined}
              hint={p.tests ? `last run ${utc(p.tests.ts)}` : "run tools/privacy_suite.py"} />
          </div>
          <div className="grid gap-4 xl:grid-cols-2">
            <Panel title="Privacy test suite" meta={t.data?.source ? `${t.data.source} · ${utc(t.data.ts)}` : undefined} bodyClassName="p-0">
              {t.isLoading ? <div className="p-4"><LoadingBlock rows={4} /></div> : !t.data?.results ? (
                <div className="p-4"><EmptyState icon={LockKeyhole} title="Suite not run yet" body={<>Run <code className="font-mono">python tools/privacy_suite.py</code> from the repo root.</>} /></div>
              ) : (
                <ul className="divide-y divide-line">{t.data.results.map((r) => (
                  <li key={r.id} className="grid grid-cols-[auto_1fr] gap-x-3 px-4 py-2">
                    <StatusChip status={r.passed ? "PASS" : "FAIL"} className="row-span-2 self-start" />
                    <span className="text-meta text-fg">{r.name}</span>
                    <span className="text-xs text-fg-subtle">{r.detail}</span>
                  </li>
                ))}</ul>
              )}
            </Panel>
            <Panel title="Recent model calls" meta="Exactly which metadata fields were shared, per call" bodyClassName="p-0">
              {calls.isLoading ? <div className="p-4"><LoadingBlock rows={4} /></div> : !calls.data?.items.length ? (
                <p className="p-4 text-meta text-fg-subtle">No model calls yet.</p>
              ) : (
                <ul className="max-h-[480px] divide-y divide-line overflow-y-auto">{calls.data.items.map((c) => (
                  <li key={c.id} className="px-4 py-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs text-fg">{c.agent}</span><span className="font-mono text-xs text-fg-subtle">{c.purpose} · {c.provider}</span>
                      <span className="ml-auto">{c.blocked ? <StatusChip status="FAIL" label="BLOCKED" /> : <span className="font-mono text-xs text-fg-subtle">{c.payload_bytes} B</span>}</span>
                    </div>
                    <p className="mt-1 font-mono text-[0.6875rem] break-all text-fg-subtle">
                      {c.blocked ? `DLP: ${Object.entries(c.dlp_findings).map(([k, v]) => `${k}×${v}`).join(", ")}` : c.shared_fields.join(" · ")}
                    </p>
                  </li>
                ))}</ul>
              )}
            </Panel>
          </div>
          <Panel title="Privacy policy violations" meta="Types, counts and field paths only — never the value" bodyClassName="p-0">
            {!vio.data?.items.length ? <p className="p-4 text-meta text-fg-subtle">None recorded.</p> : (
              <ul className="divide-y divide-line">{vio.data.items.map((v) => (
                <li key={v.id} className="flex flex-wrap items-center gap-3 px-4 py-2 font-mono text-xs">
                  <span className="text-fg-subtle">{utc(v.ts)}</span><span className="text-fg">{v.rule}</span>
                  <span className="text-fg-muted">{Object.entries(v.detectors).map(([k, n]) => `${k}×${n}`).join(", ")} at {v.field_paths.join(", ")}</span>
                  <span className="ml-auto">{v.is_test ? <StatusChip status="OK" label="TEST" dot={false} /> : null} <StatusChip status="FAIL" label={v.action} /></span>
                </li>
              ))}</ul>
            )}
          </Panel>
        </div>
      )}
    </>
  );
}
