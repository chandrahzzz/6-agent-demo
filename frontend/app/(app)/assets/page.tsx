"use client";

import { Boxes } from "lucide-react";
import { useState } from "react";

import { PageHeader, Panel } from "@/components/panel";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/states";
import { StatusChip } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ago } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { Asset, Page } from "@/lib/types";

const KINDS = ["all", "bucket", "table", "vendor", "ai_tool", "cdn"] as const;

function attrs(a: Asset): string {
  const x = a.attributes;
  if (a.kind === "bucket") return `anonymous ${x.anonymous} · ${x.objects} objects${x.drift ? " · CONFIG DRIFT" : ""}`;
  if (a.kind === "table") return `${x.row_count} rows · ${(x.columns as string[]).length} columns`;
  if (a.kind === "vendor" || a.kind === "ai_tool") return `${x.approved ? "approved" : "UNAPPROVED"} · ${x.purpose}`;
  return "";
}

export default function AssetsPage() {
  const [kind, setKind] = useState<(typeof KINDS)[number]>("all");
  const q = useApi<Page<Asset>>(["assets", kind], `/assets?page_size=500${kind === "all" ? "" : `&kind=${kind}`}`);
  const conn = useApi<{ items: { name: string; label: string; mode: string }[] }>(["connectors"], "/connectors");
  return (
    <>
      <PageHeader eyebrow="Inventory" title="Assets" description="Discovered by the Exposure Hunter through the customer-side worker. Every connector here is a sandbox or mock." />
      <div className="mb-4 flex flex-wrap gap-1.5" role="group" aria-label="Filter by kind">
        {KINDS.map((k) => (
          <Button key={k} size="xs" variant={k === kind ? "secondary" : "ghost"} aria-pressed={k === kind} onClick={() => setKind(k)} className="font-mono">{k}</Button>
        ))}
      </div>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_300px]">
        <Panel bodyClassName="p-0">
          {q.isLoading && <div className="p-4"><LoadingBlock rows={6} /></div>}
          {q.isError && <div className="p-4"><ErrorState error={q.error} retry={() => q.refetch()} /></div>}
          {q.data && (q.data.items.length === 0 ? (
            <div className="p-4"><EmptyState icon={Boxes} title="No assets discovered yet" body="Assets are discovered when the Exposure Hunter runs (start a drill)." /></div>
          ) : (
            <>
              <div className="hidden md:block">
                <Table>
                  <TableHeader><TableRow className="hover:bg-transparent">
                    {["Asset", "Kind", "Connector", "Classification", "Status", "Updated"].map((h) => <TableHead key={h} className="label-instrument h-9 first:pl-4 last:pr-4">{h}</TableHead>)}
                  </TableRow></TableHeader>
                  <TableBody>{q.data.items.map((a) => (
                    <TableRow key={a.id}>
                      <TableCell className="py-2 pl-4"><span className="block font-mono text-xs text-fg">{a.name}</span><span className="text-xs text-fg-subtle">{attrs(a)}</span></TableCell>
                      <TableCell className="font-mono text-xs text-fg-muted">{a.kind}</TableCell>
                      <TableCell><span className="rounded-[3px] bg-surface-3 px-1.5 py-0.5 font-mono text-[0.6875rem] text-fg-muted">{a.is_mock ? "SANDBOX" : "LIVE"} · {a.connector}</span></TableCell>
                      <TableCell className="font-mono text-xs text-fg-muted">{a.classification ?? "—"}</TableCell>
                      <TableCell><StatusChip status={a.status} /></TableCell>
                      <TableCell className="pr-4 font-mono text-xs text-fg-subtle">{ago(a.updated_at)}</TableCell>
                    </TableRow>
                  ))}</TableBody>
                </Table>
              </div>
              <ul className="divide-y divide-line md:hidden">{q.data.items.map((a) => (
                <li key={a.id} className="space-y-1 px-4 py-3">
                  <div className="flex items-center justify-between gap-2"><span className="font-mono text-xs break-all text-fg">{a.name}</span><StatusChip status={a.status} /></div>
                  <p className="text-xs text-fg-subtle">{a.kind} · {a.is_mock ? "SANDBOX" : "LIVE"} {a.connector} · {attrs(a)}</p>
                </li>
              ))}</ul>
            </>
          ))}
        </Panel>
        <Panel title="Connectors" meta="Visibly labelled: nothing here touches a real system.">
          <ul className="space-y-2">{conn.data?.items.map((c) => (
            <li key={c.name} className="flex items-center justify-between gap-2 text-meta">
              <span className="text-fg">{c.label}</span>
              <StatusChip status={c.mode === "MOCK" ? "PENDING" : "PATH"} label={c.mode} dot={false} />
            </li>
          ))}</ul>
        </Panel>
      </div>
    </>
  );
}
