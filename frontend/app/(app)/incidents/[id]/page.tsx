"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Lock } from "lucide-react";
import Link from "next/link";
import { useParams, useRouter, useSearchParams } from "next/navigation";
import { Suspense } from "react";
import { toast } from "sonner";

import { RiskPill } from "@/components/incidents/incident-list";
import { GraphTab } from "@/components/incidents/graph-tab";
import { InvestigationTab } from "@/components/incidents/investigation-tab";
import { DraftsTab, EvidenceTab, FindingsTab, OverviewTab, TimelineTab } from "@/components/incidents/other-tabs";
import { RemediationTab } from "@/components/incidents/remediation-tab";
import { VerificationTab } from "@/components/incidents/verification-tab";
import { ErrorState, LoadingBlock } from "@/components/states";
import { StatusChip } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ApiError, post } from "@/lib/api";
import { canApprove, useApi, useMe } from "@/lib/hooks";
import type { Incident } from "@/lib/types";

const TABS = [
  ["overview", "Overview"], ["findings", "Findings"], ["investigation", "Investigation & Root Cause"], ["graph", "Asset Graph"],
  ["remediation", "Remediation"], ["verification", "Verification"], ["evidence", "Evidence"], ["timeline", "Timeline"], ["drafts", "Compliance Drafts"],
] as const;

function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const tab = useSearchParams().get("tab") ?? "overview";
  const q = useApi<Incident>(["inc", id], `/incidents/${id}`, { live: true, interval: 3000 });
  const { data: me } = useMe();
  const qc = useQueryClient();
  const close = useMutation({
    mutationFn: () => post(`/incidents/${id}/close`, { note: "closed from console" }),
    onSuccess: () => { toast.success("Incident closed"); qc.invalidateQueries({ queryKey: ["inc", id] }); },
    onError: (e: Error) => toast.error(e instanceof ApiError ? e.message : "Could not close"),
  });

  if (q.isLoading) return <LoadingBlock rows={8} />;
  if (q.isError) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const inc = q.data!;
  const live = !!inc.busy;
  const closable = inc.latest_verification === "VERIFIED_FIXED" && inc.status !== "CLOSED";

  return (
    <>
      <Button asChild variant="ghost" size="sm" className="-ml-2 mb-3 gap-1.5 text-fg-muted">
        <Link href="/incidents"><ArrowLeft className="size-4" aria-hidden /> Incidents</Link>
      </Button>
      <div className="mb-5 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <p className="label-instrument mb-1.5">{inc.ref} · {inc.exposure_type.replaceAll("_", " ")}</p>
          <h1 className="text-2xl font-medium tracking-tight text-fg">{inc.title}</h1>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <StatusChip status={inc.status} />
            {inc.access_verdict && <StatusChip status={inc.access_verdict} dot={false} />}
            <RiskPill score={inc.risk_score} band={inc.severity} />
            {live && <span className="font-mono text-xs text-info">agents running…</span>}
          </div>
        </div>
        {canApprove(me) && inc.status !== "CLOSED" && (
          <Tooltip>
            <TooltipTrigger asChild>
              <span tabIndex={closable ? -1 : 0}>
                <Button variant="outline" size="sm" className="gap-2" disabled={!closable || close.isPending} onClick={() => close.mutate()}>
                  <Lock className="size-4" aria-hidden /> Close as fixed
                </Button>
              </span>
            </TooltipTrigger>
            {!closable && <TooltipContent>Requires the latest verification to be VERIFIED_FIXED (currently {inc.latest_verification ?? "none"}).</TooltipContent>}
          </Tooltip>
        )}
      </div>

      <Tabs value={tab} onValueChange={(v) => router.replace(`/incidents/${id}?tab=${v}`, { scroll: false })}>
        <div className="-mx-4 mb-4 overflow-x-auto overflow-y-hidden border-b border-line px-4 sm:mx-0 sm:px-0">
          <TabsList className="h-10 w-max justify-start gap-1 rounded-none bg-transparent p-0">
            {TABS.map(([v, label]) => (
              <TabsTrigger key={v} value={v}
                className="relative h-10 rounded-none border-0 bg-transparent px-3 text-meta text-fg-muted shadow-none data-[state=active]:bg-transparent data-[state=active]:text-fg data-[state=active]:shadow-none dark:data-[state=active]:border-transparent dark:data-[state=active]:bg-transparent data-[state=active]:after:absolute data-[state=active]:after:inset-x-2 data-[state=active]:after:bottom-0 data-[state=active]:after:h-0.5 data-[state=active]:after:bg-brand">
                {label}
                {v === "remediation" && (inc.counts?.pending_approval ?? 0) > 0 && (
                  <span className="ml-1.5 rounded-[3px] bg-warning-soft px-1 font-mono text-[0.625rem] text-warning">{inc.counts?.pending_approval}</span>
                )}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>
        <TabsContent value="overview"><OverviewTab inc={inc} live={live} /></TabsContent>
        <TabsContent value="findings"><FindingsTab incidentId={id} /></TabsContent>
        <TabsContent value="investigation"><InvestigationTab incidentId={id} /></TabsContent>
        <TabsContent value="graph"><GraphTab incidentId={id} /></TabsContent>
        <TabsContent value="remediation"><RemediationTab incidentId={id} live={live} /></TabsContent>
        <TabsContent value="verification"><VerificationTab incidentId={id} live={live} /></TabsContent>
        <TabsContent value="evidence"><EvidenceTab incidentId={id} live={live} /></TabsContent>
        <TabsContent value="timeline"><TimelineTab incidentId={id} live={live} /></TabsContent>
        <TabsContent value="drafts"><DraftsTab incidentId={id} /></TabsContent>
      </Tabs>
    </>
  );
}

export default function IncidentPage() {
  return <Suspense><IncidentDetail /></Suspense>;
}
