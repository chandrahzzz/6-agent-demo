"use client";

import { useMutation } from "@tanstack/react-query";
import { FlaskConical, Play } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";

import { PageHeader, Panel } from "@/components/panel";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/states";
import { StatusChip } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { post } from "@/lib/api";
import { ago } from "@/lib/format";
import { canOperate, useApi, useMe } from "@/lib/hooks";
import type { Drill, Page, Scenario } from "@/lib/types";

function ScenarioCard({ s, disabled }: { s: Scenario; disabled: boolean }) {
  const router = useRouter();
  const [variant, setVariant] = useState("A");
  const [auto, setAuto] = useState(false);
  const hasVariant = !!s.variants.access_variant;
  const m = useMutation({
    mutationFn: () => post<Drill>("/drills", { scenario_id: s.id, access_variant: hasVariant ? variant : "A", auto_approve: auto, reset: true }),
    onSuccess: (d) => { toast.success(`${s.id} started`); router.push(`/drills/${d.id}`); },
    onError: (e: Error) => toast.error(e.message),
  });
  return (
    <article className="flex flex-col rounded-md border border-line bg-surface">
      <header className="flex items-start justify-between gap-3 border-b border-line px-4 py-3">
        <div className="min-w-0">
          <p className="font-mono text-xs text-fg-subtle">{s.id}</p>
          <h3 className="text-sm font-medium text-fg">{s.name}</h3>
        </div>
        <StatusChip status={s.implemented ? "OK" : "NOT_STARTED"} label={s.tier === "deep" ? "DEEP" : "LITE"} dot={false} />
      </header>
      <div className="flex-1 space-y-2 px-4 py-3">
        <p className="text-meta text-fg-muted">{s.description || "Detection, verdict and recommended fix."}</p>
        {s.hard_part && <p className="text-xs text-fg-subtle">Hard part: {s.hard_part}</p>}
      </div>
      <footer className="flex flex-wrap items-end gap-3 border-t border-line px-4 py-3">
        {!s.implemented ? (
          <span className="text-xs text-fg-subtle">Not implemented yet — tracked in PROGRESS.md</span>
        ) : (
          <>
            {hasVariant && (
              <div className="space-y-1">
                <Label htmlFor={`v-${s.id}`} className="text-xs text-fg-subtle">Attacker variant</Label>
                <Select value={variant} onValueChange={setVariant}>
                  <SelectTrigger id={`v-${s.id}`} size="sm" className="w-[210px]"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="A">A · attempts, no download</SelectItem>
                    <SelectItem value="B">B · confirmed download</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}
            <div className="flex items-center gap-2 pb-1.5">
              <Switch id={`a-${s.id}`} checked={auto} onCheckedChange={setAuto} />
              <Label htmlFor={`a-${s.id}`} className="text-xs text-fg-muted">Presenter auto-approve</Label>
            </div>
            <Button size="sm" className="ml-auto gap-1.5" disabled={disabled || m.isPending} onClick={() => m.mutate()}>
              <Play className="size-3.5" aria-hidden /> Run drill
            </Button>
          </>
        )}
      </footer>
    </article>
  );
}

export default function DrillsPage() {
  const sc = useApi<{ items: Scenario[] }>(["scenarios"], "/scenarios");
  const drills = useApi<Page<Drill>>(["drills"], "/drills?page_size=20", { live: true, interval: 4000 });
  const { data: me } = useMe();
  const running = drills.data?.items.some((d) => d.status === "RUNNING");
  const deep = sc.data?.items.filter((s) => s.tier === "deep") ?? [];
  const lite = sc.data?.items.filter((s) => s.tier === "lite") ?? [];
  return (
    <>
      <PageHeader eyebrow="Sandbox" title="Breach Drill Lab"
        description="Each drill resets the Meridian Bank sandbox from its seed, plants a real exposure, sends real attacker traffic from outside, then lets the six agents work." />
      <div className="space-y-6">
        <Panel title="Recent drills" bodyClassName="p-0">
          {drills.isLoading ? <div className="p-4"><LoadingBlock rows={3} /></div> : drills.isError ? <div className="p-4"><ErrorState error={drills.error} /></div> :
            drills.data!.items.length === 0 ? <div className="p-4"><EmptyState icon={FlaskConical} title="No drills run yet" body="Pick a scenario below." /></div> : (
              <ul className="divide-y divide-line">
                {drills.data!.items.map((d) => (
                  <li key={d.id}>
                    <Link href={`/drills/${d.id}`} className="flex flex-wrap items-center gap-3 px-4 py-2.5 hover:bg-surface-2">
                      <span className="font-mono text-xs text-fg">{d.scenario_id}</span>
                      <span className="font-mono text-xs text-fg-subtle">variant {String(d.params.access_variant ?? "—")}{d.demo ? " · demo" : ""}{d.auto_approve ? " · auto-approve" : ""}</span>
                      <span className="ml-auto font-mono text-xs text-fg-subtle">{ago(d.created_at)}</span>
                      <StatusChip status={d.status} />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
        </Panel>
        {!canOperate(me) && <p className="text-meta text-fg-subtle">Your role can view drills but not start them.</p>}
        {sc.isError && <ErrorState error={sc.error} />}
        <section aria-labelledby="deep-h">
          <h2 id="deep-h" className="label-instrument mb-3">Deep scenarios · live remediation and adversarial verification</h2>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">{deep.map((s) => <ScenarioCard key={s.id} s={s} disabled={!canOperate(me) || !!running} />)}</div>
        </section>
        <section aria-labelledby="lite-h">
          <h2 id="lite-h" className="label-instrument mb-3">Lite scenarios · detection, verdict and recommendation</h2>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">{lite.map((s) => <ScenarioCard key={s.id} s={s} disabled={!canOperate(me) || !!running} />)}</div>
        </section>
      </div>
    </>
  );
}
