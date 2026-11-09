"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ShieldAlert, Wrench } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";

import { DiffView } from "@/components/diff";
import { KV, Panel } from "@/components/panel";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/states";
import { StatusChip } from "@/components/status";
import { Button } from "@/components/ui/button";
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader,
  AlertDialogTitle, AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { post } from "@/lib/api";
import { blockedMessage, depStates, executionPlan, type DepState } from "@/lib/deps";
import { utc } from "@/lib/format";
import { canApprove, canOperate, useApi, useMe } from "@/lib/hooks";
import type { Action } from "@/lib/types";

function Result({ a }: { a: Action }) {
  const r = a.result as Record<string, unknown>;
  if (!a.executed_at) return null;
  const reg = r.regression_test as { blocked: boolean; bad_commit: string; method: string; violations: { message: string }[] } | undefined;
  return (
    <div className="mt-3 rounded-sm border border-line bg-background/60 p-3">
      <p className="label-instrument mb-1.5">Execution record · {utc(a.executed_at)}</p>
      {reg && (
        <p className="text-meta">
          <span className={reg.blocked ? "text-ok" : "text-critical"}>{reg.blocked ? "Regression test: BLOCKED" : "Regression test: NOT blocked"}</span>
          <span className="text-fg-muted"> — re-applying commit <span className="font-mono">{reg.bad_commit.slice(0, 8)}</span> ({reg.method}): {reg.violations?.[0]?.message}</span>
        </p>
      )}
      {Array.isArray(r.purged) && <p className="font-mono text-xs text-fg-muted">purged: {(r.purged as string[]).join(", ") || "nothing cached"}</p>}
      {"before" in r && <p className="font-mono text-xs text-fg-muted">anonymous: {String(r.before)} → {String(r.after)}</p>}
      {"commit" in r && r.commit ? <p className="font-mono text-xs text-fg-muted">commit {String(r.commit).slice(0, 12)} · sync {String((r.sync as { status?: string })?.status ?? "")}</p> : null}
      {"link_delivered_to" in r && <p className="font-mono text-xs text-fg-muted">presigned link ({String(r.link_expires_seconds)}s) delivered to {String(r.link_delivered_to)}</p>}
      {"error" in r && <p className="font-mono text-xs text-critical">{String(r.error)}</p>}
    </div>
  );
}

function ActionCard({ a, deps, selectable, checked, onCheck }: {
  a: Action; deps: DepState[]; selectable: boolean; checked: boolean; onCheck: (v: boolean) => void;
}) {
  const held = a.approval_status === "HELD";
  const superseded = a.approval_status === "SUPERSEDED";
  const waiting = !superseded && a.approval_status !== "REJECTED" && a.execution_status !== "SUCCEEDED"
    && deps.some((d) => d.state !== "SUCCEEDED");
  return (
    <article className={superseded ? "rounded-md border border-line bg-surface opacity-60" : "rounded-md border border-line bg-surface"}
      aria-labelledby={`act-${a.id}`}>
      <header className="flex flex-wrap items-center gap-3 border-b border-line px-4 py-3">
        {selectable && <Checkbox checked={checked} onCheckedChange={(v) => onCheck(v === true)} aria-label={`Select ${a.code}`} />}
        <span className="font-mono text-sm text-fg">{a.code}</span>
        <h3 id={`act-${a.id}`} className="min-w-0 flex-1 truncate font-mono text-meta text-fg-muted">{a.action_type} · {a.target}</h3>
        <span className="label-instrument">wave {a.wave}</span>
        <StatusChip status={a.approval_status} />
        <StatusChip status={a.execution_status} />
      </header>
      <div className="grid gap-x-8 px-4 py-3 lg:grid-cols-2">
        <dl>
          <KV k="Problem" v={a.problem} />
          <KV k="Change" v={a.change} />
          <KV k="Expected outcome" v={a.expected_outcome} />
          <KV k="Verification" v={a.verification_requirement} />
        </dl>
        <dl>
          <KV k="Risk" v={a.risk} />
          <KV k="Side effects" v={a.side_effects} />
          <KV k="Rollback" v={a.rollback_plan} />
          {deps.length > 0 && <KV k="Runs after" v={deps.map((d) => `${d.code} (${d.state.toLowerCase().replace("_", " ")})`).join(", ")} mono />}
        </dl>
      </div>
      {waiting && (
        <p role="status" className="mx-4 mb-3 rounded-sm border border-warning/40 bg-warning-soft p-3 text-meta text-fg">
          {blockedMessage(a.code, deps)}
        </p>
      )}
      {superseded && (
        <p className="mx-4 mb-3 text-meta text-fg-muted">
          Superseded: a later verification folded this into a single pending action, so it will not run.
        </p>
      )}
      {a.safety?.result && a.safety.result !== "N/A (config only)" && a.safety.result !== "N/A (preventive control)" && a.safety.result !== "N/A (cache)" && (
        <div className={held ? "mx-4 mb-3 rounded-sm border border-warning/40 bg-warning-soft p-3" : "mx-4 mb-3 rounded-sm border border-line p-3"}>
          <p className="label-instrument mb-1">Safety check · {a.safety.window ?? ""} {a.safety.events_examined !== undefined ? `· ${a.safety.events_examined} events read` : ""}</p>
          <p className="text-meta text-fg">
            {a.safety.result === "DEPENDENCY_FOUND"
              ? `Dependency found: ${a.safety.dependents?.map((d) => `${d.origin} (${d.reads} anonymous read${d.reads === 1 ? "" : "s"})`).join(", ")}. Safer alternative proposed instead of a plain lockdown.`
              : a.safety.result === "NO_DEPENDENCY" ? "No consumer depends on the access being removed." : a.safety.result}
          </p>
          {a.safety.unaffected?.map((u) => <p key={u.principal} className="text-xs text-fg-muted">{u.principal}: {u.reason}</p>)}
          {a.safety.reconsidered && <p className="mt-1 text-xs text-warning">{a.safety.reconsidered}</p>}
        </div>
      )}
      {a.patch_diff && <div className="px-4 pb-3"><DiffView diff={a.patch_diff} title="Proposed patch · infra-config/buckets.yaml" /></div>}
      <div className="px-4 pb-4">
        {a.approvals?.map((p) => (
          <p key={p.id} className="text-xs text-fg-muted">
            <span className={p.decision === "APPROVED" ? "text-ok" : "text-critical"}>{p.decision}</span> by <span className="font-mono">{p.user_email}</span> ({p.role}) · {utc(p.created_at)}
            {p.presenter_auto && <span className="ml-1 rounded-[3px] bg-warning-soft px-1 text-warning">presenter auto-approve</span>}
            {p.reason && <span> · “{p.reason}”</span>}
          </p>
        ))}
        <Result a={a} />
      </div>
    </article>
  );
}

export function RemediationTab({ incidentId, live }: { incidentId: string; live: boolean }) {
  const q = useApi<{ items: Action[] }>(["inc", incidentId, "remediation"], `/incidents/${incidentId}/remediation`, { live });
  const { data: me } = useMe();
  const qc = useQueryClient();
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [override, setOverride] = useState<{ open: boolean; reason: string }>({ open: false, reason: "" });
  const items = useMemo(() => q.data?.items ?? [], [q.data]);
  const decidable = items.filter((a) => a.approval_status === "PENDING" || a.approval_status === "HELD");
  const plan = useMemo(() => executionPlan(items), [items]);
  const byCode = useMemo(() => new Map(items.map((a) => [a.code, a])), [items]);
  const ready = items.filter((a) => plan.order.includes(a.code));
  const blockedCodes = Object.keys(plan.blocked);
  const selected = decidable.filter((a) => sel.has(a.id));
  const heldSelected = selected.some((a) => a.approval_status === "HELD");
  const refresh = () => qc.invalidateQueries({ queryKey: ["inc", incidentId] });

  const decide = useMutation({
    mutationFn: (v: { decision: "APPROVED" | "REJECTED"; reason?: string; override_hold?: boolean }) =>
      post("/approvals", { action_ids: selected.map((a) => a.id), ...v }),
    onSuccess: (_, v) => { toast.success(`${selected.map((a) => a.code).join(", ")} ${v.decision.toLowerCase()}`); setSel(new Set()); setOverride({ open: false, reason: "" }); refresh(); },
    onError: (e: Error) => toast.error(e.message),
  });
  const exec = useMutation({
    mutationFn: () => post<{ actions: string[] }>(`/incidents/${incidentId}/remediation/execute`),
    onSuccess: (r) => { toast.success(`Executing ${r.actions.join(", ")}; verification follows automatically`); refresh(); },
    onError: (e: Error) => toast.error(e.message),
  });

  if (q.isLoading) return <LoadingBlock rows={5} />;
  if (q.isError) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  if (!items.length) return <EmptyState icon={Wrench} title="No actions proposed yet" body="The Remediation Agent proposes actions after investigation and blast radius complete." />;

  return (
    <div className="space-y-4">
      <Panel bodyClassName="flex flex-wrap items-center gap-3 py-3">
        <ShieldAlert className="size-4 text-fg-subtle" aria-hidden />
        <p className="min-w-0 flex-1 text-meta text-fg-muted">
          Nothing executes without a recorded human approval. The worker independently verifies a signed approval token for every action.
        </p>
        {canApprove(me) ? (
          <>
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button size="sm" variant="ghost" disabled={!selected.length || decide.isPending} aria-describedby="sel-hint">Reject</Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Reject {selected.map((a) => a.code).join(", ")}?</AlertDialogTitle>
                  <AlertDialogDescription>
                    A rejection is final and is recorded in the evidence chain. The exposure stays open until another action fixes it.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction onClick={() => decide.mutate({ decision: "REJECTED", reason: "rejected in console" })}>Reject</AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
            <Button size="sm" variant="secondary" disabled={!selected.length || decide.isPending} aria-describedby="sel-hint"
              onClick={() => (heldSelected ? setOverride({ open: true, reason: "" }) : decide.mutate({ decision: "APPROVED" }))}>
              Approve {selected.length ? `(${selected.length})` : ""}
            </Button>
          </>
        ) : <span className="text-xs text-fg-subtle">Approval requires SECURITY_ANALYST or ADMIN</span>}
        {canOperate(me) && (
          <Button size="sm" disabled={!ready.length || exec.isPending || live} onClick={() => exec.mutate()}>
            Execute approved {ready.length ? `(${ready.length})` : ""}
          </Button>
        )}
        {canOperate(me) && !ready.length && blockedCodes.length > 0 && (
          <p className="w-full text-xs text-warning">
            Approved but blocked: {blockedCodes.map((c) => blockedMessage(c, plan.blocked[c])).join(" ")}
          </p>
        )}
        {canApprove(me) && !selected.length && decidable.length > 0 && (
          <p id="sel-hint" className="w-full text-xs text-fg-subtle">Select pending or held actions to approve or reject them.</p>
        )}
        {(decide.error || exec.error) && (
          <p role="alert" className="w-full text-xs text-critical">{(decide.error ?? exec.error)?.message}</p>
        )}
      </Panel>
      {items.map((a) => (
        <ActionCard key={a.id} a={a} deps={depStates(a, byCode)} selectable={canApprove(me) && (a.approval_status === "PENDING" || a.approval_status === "HELD")}
          checked={sel.has(a.id)} onCheck={(v) => setSel((s) => { const n = new Set(s); if (v) n.add(a.id); else n.delete(a.id); return n; })} />
      ))}
      <Dialog open={override.open} onOpenChange={(o) => setOverride((s) => ({ ...s, open: o }))}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Override the safety-check hold</DialogTitle>
            <DialogDescription>
              One or more selected actions are held because a legitimate consumer depends on the access being removed. Record why it is safe to proceed.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-1.5">
            <Label htmlFor="reason">Reason (at least 10 characters, recorded in the evidence chain)</Label>
            <Textarea id="reason" value={override.reason} onChange={(e) => setOverride((s) => ({ ...s, reason: e.target.value }))}
              placeholder="e.g. Northwind confirmed they will switch to the presigned link." />
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setOverride({ open: false, reason: "" })}>Cancel</Button>
            <Button disabled={override.reason.trim().length < 10 || decide.isPending}
              onClick={() => decide.mutate({ decision: "APPROVED", reason: override.reason.trim(), override_hold: true })}>Approve with override</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
