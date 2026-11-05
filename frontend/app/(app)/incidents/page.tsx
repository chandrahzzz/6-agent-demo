"use client";

import { ShieldAlert } from "lucide-react";
import Link from "next/link";

import { IncidentList } from "@/components/incidents/incident-list";
import { PageHeader, Panel } from "@/components/panel";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/states";
import { Button } from "@/components/ui/button";
import { useApi } from "@/lib/hooks";
import type { Incident, Page } from "@/lib/types";

export default function IncidentsPage() {
  const q = useApi<Page<Incident>>(["incidents"], "/incidents?page_size=100", { live: true, interval: 5000 });
  return (
    <>
      <PageHeader eyebrow="Response" title="Incidents"
        description="An incident cannot be closed as fixed until its latest adversarial verification is VERIFIED_FIXED. The backend enforces this." />
      <Panel bodyClassName="p-0">
        {q.isLoading && <div className="p-4"><LoadingBlock rows={5} /></div>}
        {q.isError && <div className="p-4"><ErrorState error={q.error} retry={() => q.refetch()} /></div>}
        {q.data && (q.data.items.length ? <IncidentList items={q.data.items} /> : (
          <div className="p-4">
            <EmptyState icon={ShieldAlert} title="No incidents" body="Incidents appear when the Exposure Hunter finds a real exposure in the sandbox."
              action={<Button asChild size="sm"><Link href="/drills">Run a breach drill</Link></Button>} />
          </div>
        ))}
      </Panel>
    </>
  );
}
