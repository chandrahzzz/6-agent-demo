"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { KV, PageHeader, Panel } from "@/components/panel";
import { ErrorState, LoadingBlock } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { put } from "@/lib/api";
import { canApprove, useApi, useMe } from "@/lib/hooks";

type S = { regulatory_context: string[]; available_regimes: Record<string, string>; llm_provider: string; environment: string; demo_mode: boolean };

export default function SettingsPage() {
  const q = useApi<S>(["settings"], "/settings");
  const { data: me } = useMe();
  const qc = useQueryClient();
  const [sel, setSel] = useState<string[]>([]);
  useEffect(() => { if (q.data) setSel(q.data.regulatory_context); }, [q.data]);
  const m = useMutation({
    mutationFn: () => put("/settings/regulatory-context", { regimes: sel }),
    onSuccess: () => { toast.success("Regulatory context saved"); qc.invalidateQueries({ queryKey: ["settings"] }); },
    onError: (e: Error) => toast.error(e.message),
  });
  return (
    <>
      <PageHeader eyebrow="Configuration" title="Settings" />
      {q.isLoading && <LoadingBlock rows={4} />}
      {q.isError && <ErrorState error={q.error} retry={() => q.refetch()} />}
      {q.data && (
        <div className="grid gap-4 xl:grid-cols-2">
          <Panel title="Regulatory context for drafts"
            meta="Chooses which draft notices the Compliance Evidence Agent prepares. It does not decide that any law applies.">
            <fieldset className="space-y-3" disabled={!canApprove(me)}>
              <legend className="sr-only">Regimes</legend>
              {Object.entries(q.data.available_regimes).map(([k, v]) => (
                <div key={k} className="flex items-start gap-3">
                  <Checkbox id={`r-${k}`} checked={sel.includes(k)} onCheckedChange={(c) => setSel((s) => (c ? [...s, k] : s.filter((x) => x !== k)))} />
                  <Label htmlFor={`r-${k}`} className="block leading-snug"><span className="font-mono text-meta text-fg">{k}</span><span className="block text-xs font-normal text-fg-muted">{v}</span></Label>
                </div>
              ))}
            </fieldset>
            {canApprove(me) && <Button size="sm" className="mt-4" onClick={() => m.mutate()} disabled={m.isPending}>Save</Button>}
          </Panel>
          <Panel title="Environment">
            <dl>
              <KV k="Environment" v={q.data.environment} mono />
              <KV k="Organisation" v="Meridian Bank (fictional, single tenant)" />
              <KV k="LLM provider" v={q.data.llm_provider === "local" ? "local · deterministic reasoning templates (no API key)" : q.data.llm_provider} mono />
              <KV k="Demo mode" v={q.data.demo_mode ? "enabled" : "disabled"} mono />
              <KV k="Your role" v={me?.role ?? "—"} mono />
            </dl>
            <p className="mt-4 text-xs text-fg-subtle">Demo accounts are for the sandbox only. MALLYA is a concept prototype and is not production-ready.</p>
          </Panel>
        </div>
      )}
    </>
  );
}
