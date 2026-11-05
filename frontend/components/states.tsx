import { AlertTriangle, type LucideIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

export function LoadingBlock({ rows = 4, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn("space-y-2", className)} aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-9 w-full bg-surface-2" style={{ opacity: 1 - i * 0.15 }} />
      ))}
    </div>
  );
}

export function EmptyState({ icon: Icon, title, body, action, className }: {
  icon: LucideIcon; title: string; body?: React.ReactNode; action?: React.ReactNode; className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-center justify-center rounded-md border border-dashed border-line-strong px-6 py-12 text-center", className)}>
      <Icon className="mb-3 size-5 text-fg-subtle" aria-hidden />
      <p className="text-sm font-medium text-fg">{title}</p>
      {body && <div className="mt-1 max-w-md text-meta text-fg-muted">{body}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function ErrorState({ error, retry }: { error: unknown; retry?: () => void }) {
  const msg = error instanceof Error ? error.message : "Something went wrong.";
  return (
    <div role="alert" className="flex items-start gap-3 rounded-md border border-critical/40 bg-critical-soft px-4 py-3">
      <AlertTriangle className="mt-0.5 size-4 shrink-0 text-critical" aria-hidden />
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium text-fg">Could not load this data</p>
        <p className="mt-0.5 text-meta break-words text-fg-muted">{msg}</p>
      </div>
      {retry && (
        <Button size="sm" variant="outline" onClick={retry}>
          Retry
        </Button>
      )}
    </div>
  );
}
