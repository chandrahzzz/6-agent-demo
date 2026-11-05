import Link from "next/link";

import { StatusChip } from "@/components/status";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ago, humanise } from "@/lib/format";
import type { Incident } from "@/lib/types";

/** Table on wide screens, stacked cards below 768px. */
export function IncidentList({ items, compact }: { items: Incident[]; compact?: boolean }) {
  return (
    <>
      <div className="hidden md:block">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="label-instrument h-9 pl-4">Incident</TableHead>
              <TableHead className="label-instrument h-9">Status</TableHead>
              <TableHead className="label-instrument h-9">Access verdict</TableHead>
              <TableHead className="label-instrument h-9 text-right">Risk</TableHead>
              {!compact && <TableHead className="label-instrument h-9">Type</TableHead>}
              <TableHead className="label-instrument h-9 pr-4 text-right">Detected</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((i) => (
              <TableRow key={i.id} className="group">
                <TableCell className="max-w-[420px] py-2.5 pl-4">
                  <Link href={`/incidents/${i.id}`} className="block rounded-sm focus-visible:outline-offset-4">
                    <span className="font-mono text-xs text-fg-subtle">{i.ref}</span>
                    <span className="block truncate text-sm text-fg group-hover:text-brand-strong">{i.title}</span>
                  </Link>
                </TableCell>
                <TableCell><StatusChip status={i.status} /></TableCell>
                <TableCell>{i.access_verdict ? <StatusChip status={i.access_verdict} dot={false} /> : <span className="text-fg-subtle">pending</span>}</TableCell>
                <TableCell className="text-right"><RiskPill score={i.risk_score} band={i.severity} /></TableCell>
                {!compact && <TableCell className="text-meta text-fg-muted">{humanise(i.exposure_type)}</TableCell>}
                <TableCell className="pr-4 text-right font-mono text-xs text-fg-subtle">{ago(i.detected_at)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <ul className="divide-y divide-line md:hidden">
        {items.map((i) => (
          <li key={i.id}>
            <Link href={`/incidents/${i.id}`} className="block space-y-2 px-4 py-3 hover:bg-surface-2">
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs text-fg-subtle">{i.ref}</span>
                <RiskPill score={i.risk_score} band={i.severity} />
              </div>
              <p className="text-sm text-fg">{i.title}</p>
              <div className="flex flex-wrap gap-2">
                <StatusChip status={i.status} />
                {i.access_verdict && <StatusChip status={i.access_verdict} dot={false} />}
              </div>
            </Link>
          </li>
        ))}
      </ul>
    </>
  );
}

export function RiskPill({ score, band }: { score: number; band: string }) {
  return (
    <span className="inline-flex items-baseline gap-1.5 font-mono text-xs">
      <span className="text-sm tabular-nums text-fg">{score}</span>
      <StatusChip status={band} dot={false} className="h-5 px-1.5 text-[0.6875rem]" />
    </span>
  );
}
