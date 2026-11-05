"use client";

import { useMutation } from "@tanstack/react-query";
import { Check, Copy, Download, ShieldCheck, Vault } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";

import { KV, PageHeader, Panel } from "@/components/panel";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/states";
import { StatusChip } from "@/components/status";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { ms, short, utc } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { EvidencePack } from "@/lib/types";

type Verify = { ok: boolean; checks: { status: string; check: string; detail: string }[]; command: string };

function CopyCommand({ cmd }: { cmd: string }) {
  const [done, setDone] = useState(false);
  return (
    <div className="flex items-center gap-2 rounded-sm border border-line bg-background px-3 py-2">
      <code className="min-w-0 flex-1 overflow-x-auto font-mono text-xs whitespace-nowrap text-fg">{cmd}</code>
      <Button size="icon-xs" variant="ghost" aria-label="Copy verify command" onClick={async () => {
        try { await navigator.clipboard.writeText(cmd); setDone(true); setTimeout(() => setDone(false), 1500); } catch { toast.error("Clipboard unavailable"); }
      }}>{done ? <Check className="size-3 text-ok" aria-hidden /> : <Copy className="size-3" aria-hidden />}</Button>
    </div>
  );
}

function PackCard({ p }: { p: EvidencePack }) {
  const [res, setRes] = useState<Verify | null>(null);
  const v = useMutation({ mutationFn: () => api<Verify>(`/evidence/packs/${p.id}/verify`), onSuccess: setRes, onError: (e: Error) => toast.error(e.message) });
  const base = `/api/v1/evidence/packs/${p.id}`;
  return (
    <Panel title={<span className="font-mono">{p.file_name}</span>}
      meta={<Link href={`/incidents/${p.incident_id}?tab=evidence`} className="hover:text-fg">{p.incident_ref} · {p.incident_title}</Link>}
      actions={<Button size="sm" variant="secondary" className="gap-1.5" onClick={() => v.mutate()} disabled={v.isPending}>
        <ShieldCheck className="size-4" aria-hidden /> {v.isPending ? "Verifying…" : "Verify now"}</Button>}>
      <div className="grid gap-x-8 lg:grid-cols-2">
        <dl>
          <KV k="Signature" v={`${p.algorithm} · key ${p.key_id}`} mono />
          <KV k="Manifest SHA-256" v={short(p.manifest_sha256, 32)} mono />
          <KV k="Chain" v={`${p.event_count} events · head ${short(p.head_event_hash, 20)}`} mono />
          <KV k="Pack SHA-256" v={short(p.file_sha256, 32)} mono />
          <KV k="Built" v={`${utc(p.created_at)} · ${ms(p.built_ms)}`} mono />
        </dl>
        <div className="space-y-3">
          <div>
            <p className="label-instrument mb-1.5">File integrity</p>
            <ul className="space-y-0.5 font-mono text-xs">{Object.entries(p.files).map(([n, h]) => (
              <li key={n} className="flex justify-between gap-3"><span className="text-fg">{n}</span><span className="text-fg-subtle">{h.slice(0, 16)}…</span></li>
            ))}</ul>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button asChild size="xs" variant="outline"><a href={`${base}/download`}><Download className="size-3" aria-hidden /> Pack (.zip)</a></Button>
            <Button asChild size="xs" variant="outline"><a href={`${base}/file/manifest.json`}>Signed manifest</a></Button>
            <Button asChild size="xs" variant="outline"><a href={`${base}/file/report.pdf`}>PDF report</a></Button>
            <Button asChild size="xs" variant="outline"><a href={`${base}/file/timeline.csv`}>Timeline CSV</a></Button>
            <Button asChild size="xs" variant="outline"><a href={`${base}/file/checksums.sha256`}>Checksums</a></Button>
          </div>
        </div>
      </div>
      <div className="mt-4 space-y-2">
        <p className="label-instrument">Verify independently</p>
        <CopyCommand cmd={`python tools/mallya_verify.py ${p.file_name}`} />
      </div>
      {res && (
        <div className="mt-4 animate-reveal rounded-sm border border-line bg-background/60 p-3" role="status">
          <ul className="space-y-1 font-mono text-xs">
            {res.checks.map((c) => (
              <li key={c.check} className="grid grid-cols-[3rem_8rem_1fr] gap-2">
                <span className={c.status === "PASS" ? "text-ok" : "text-critical"}>{c.status}</span>
                <span className="text-fg">{c.check}</span><span className="break-words text-fg-muted">{c.detail}</span>
              </li>
            ))}
          </ul>
          <p className="mt-2 font-mono text-xs"><StatusChip status={res.ok ? "PASS" : "FAIL"} label={`OVERALL ${res.ok ? "PASS" : "FAIL"}`} /></p>
        </div>
      )}
    </Panel>
  );
}

export default function EvidencePage() {
  const q = useApi<{ items: EvidencePack[]; signing: { key_id: string; algorithm: string; label: string } }>(["evidence"], "/evidence");
  return (
    <>
      <PageHeader eyebrow="Proof" title="Evidence Vault"
        description="Signed packs are cryptographically tamper-evident and audit-oriented. They are not a statement of legal admissibility or regulatory compliance." />
      {q.isLoading && <LoadingBlock rows={4} />}
      {q.isError && <ErrorState error={q.error} retry={() => q.refetch()} />}
      {q.data && (
        <div className="space-y-4">
          <Panel bodyClassName="flex flex-wrap items-center gap-x-6 gap-y-2 py-3">
            <span className="label-instrument">Active signing key</span>
            <span className="font-mono text-xs text-fg">{q.data.signing.algorithm} · {q.data.signing.key_id}</span>
            {q.data.signing.label !== "PRODUCTION" && <StatusChip status="PENDING" label={q.data.signing.label} dot={false} />}
            <span className="text-xs text-fg-subtle">Private key lives in a secrets volume; never in the database, the browser or git.</span>
          </Panel>
          {q.data.items.length === 0 ? (
            <EmptyState icon={Vault} title="No evidence packs yet" body="A signed pack is built automatically when an incident reaches VERIFIED_FIXED." />
          ) : q.data.items.map((p) => <PackCard key={p.id} p={p} />)}
        </div>
      )}
    </>
  );
}
