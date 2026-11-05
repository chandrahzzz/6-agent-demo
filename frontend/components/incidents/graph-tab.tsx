"use client";

import "@xyflow/react/dist/style.css";

import { Background, Controls, type Edge, Handle, MarkerType, type Node, type NodeProps, Position, ReactFlow } from "@xyflow/react";
import { Network } from "lucide-react";
import { useMemo } from "react";

import { Metric, Panel } from "@/components/panel";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/states";
import { StatusChip, toneBg, toneOf, toneText } from "@/components/status";
import { num } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { BlastRadius, GraphNode } from "@/lib/types";
import { cn } from "@/lib/utils";

const COL: Record<string, number> = { network: 0, cdn: 1, bucket: 2, table: 3 };

function AssetNode({ data }: NodeProps<Node<GraphNode>>) {
  const t = toneOf(data.status);
  return (
    <div className={cn("w-[208px] rounded-md border bg-surface px-3 py-2 shadow-soft", t === "critical" ? "border-critical/60" : t === "warning" ? "border-warning/50" : t === "ok" ? "border-ok/50" : "border-line-strong")}>
      <Handle type="target" position={Position.Left} className="!size-1.5 !border-0 !bg-line-strong" />
      <p className="label-instrument flex items-center justify-between">
        {data.kind}
        <span className="rounded-[3px] bg-surface-3 px-1 text-[0.5625rem] text-fg-muted">{data.mock ? "SANDBOX" : "LIVE"}</span>
      </p>
      <p className="mt-1 truncate font-mono text-xs text-fg" title={data.label}>{data.label}</p>
      <span className={cn("mt-1.5 inline-block rounded-[3px] px-1.5 py-0.5 font-mono text-[0.625rem]", toneBg[t], toneText[t])}>{data.status.replaceAll("_", " ")}</span>
      <Handle type="source" position={Position.Right} className="!size-1.5 !border-0 !bg-line-strong" />
    </div>
  );
}
const nodeTypes = { asset: AssetNode };

export function GraphTab({ incidentId }: { incidentId: string }) {
  const q = useApi<BlastRadius>(["inc", incidentId, "blast"], `/incidents/${incidentId}/blast-radius`);
  const br = q.data;
  const { nodes, edges } = useMemo(() => {
    if (!br?.graph) return { nodes: [] as Node[], edges: [] as Edge[] };
    const rows: Record<number, number> = {};
    const nodes: Node[] = br.graph.nodes.map((n) => {
      const c = COL[n.kind] ?? 2;
      rows[c] = (rows[c] ?? 0) + 1;
      return { id: n.id, type: "asset", data: n, position: { x: c * 280, y: (rows[c] - 1) * 120 + (c < 2 ? 100 : 0) } };
    });
    const edges: Edge[] = br.graph.edges.map((e) => ({
      id: e.id, source: e.source, target: e.target, label: e.kind.replaceAll("_", " "), animated: e.exposure_path,
      style: { stroke: e.exposure_path ? "var(--critical)" : "var(--border-strong)", strokeWidth: e.exposure_path ? 1.75 : 1 },
      labelStyle: { fill: "var(--fg-subtle)", fontSize: 10, fontFamily: "var(--font-mono)" },
      labelBgStyle: { fill: "var(--bg)" },
      markerEnd: { type: MarkerType.ArrowClosed, color: e.exposure_path ? "var(--critical)" : "var(--border-strong)" },
    }));
    return { nodes, edges };
  }, [br]);

  if (q.isLoading) return <LoadingBlock rows={6} />;
  if (q.isError) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  if (!br || !br.graph) return <EmptyState icon={Network} title="Blast radius has not run yet" />;
  const withData = br.locations.filter((l) => l.present);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
        <Metric label="Records affected" value={num(br.record_count)} hint="Distinct subjects by keyed fingerprint" />
        <Metric label="Withdrew marketing consent" value={num(br.consent.marketing_withdrawn)}
          hint={`of ${num(br.consent.subjects)} affected subjects`} />
        <Metric label="Locations holding the data" value={num(withData.length)} hint="Fingerprint match = present, not necessarily accessible" />
        <Metric label="Unverified locations" value={num(br.unverified.length)} tone={br.unverified.length ? "text-unverified" : undefined} hint="Could not be inspected by this agent" />
      </div>
      <Panel title="Asset graph" meta="Red animated edges are exposure paths from the internet." bodyClassName="p-0">
        <div className="hidden h-[460px] md:block" role="group" aria-label="Asset graph of exposure paths; the same assets are listed below.">
          <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.2 }} proOptions={{ hideAttribution: true }}
            nodesConnectable={false} colorMode="system" minZoom={0.4}>
            <Background gap={24} color="var(--bg-grid)" />
            <Controls showInteractive={false} className="!border-line !shadow-none" />
          </ReactFlow>
        </div>
        <ul className="divide-y divide-line md:border-t md:border-line" aria-label="Assets in the blast radius">
          {br.graph.nodes.map((n) => (
            <li key={n.id} className="flex items-center justify-between gap-3 px-4 py-2">
              <span className="min-w-0"><span className="label-instrument mr-2">{n.kind}</span><span className="font-mono text-xs break-all text-fg">{n.label}</span></span>
              <StatusChip status={n.status} />
            </li>
          ))}
        </ul>
      </Panel>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Where the affected records live" bodyClassName="p-0">
          <ul className="divide-y divide-line">
            {withData.map((l) => (
              <li key={l.location} className="flex items-center justify-between gap-3 px-4 py-2.5">
                <span className="min-w-0">
                  <span className="block font-mono text-xs break-all text-fg">{l.location}</span>
                  <span className="text-xs text-fg-subtle">{l.role}</span>
                </span>
                <span className="font-mono text-sm tabular-nums text-fg">{num(l.matches)}</span>
              </li>
            ))}
          </ul>
        </Panel>
        <Panel title="Unverified" meta="Shown honestly: these were not inspected by the Blast Radius Agent." bodyClassName="p-0">
          <ul className="divide-y divide-line">
            {br.unverified.map((u) => (
              <li key={u.location} className="px-4 py-2.5">
                <span className="block font-mono text-xs break-all text-fg">{u.location}</span>
                <span className="text-xs text-fg-subtle">{u.reason}</span>
              </li>
            ))}
          </ul>
        </Panel>
      </div>
    </div>
  );
}
