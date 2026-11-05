import { cn } from "@/lib/utils";

/** The base surface: 1px border, small radius, no heavy shadow. */
export function Panel({ title, meta, actions, children, className, bodyClassName, id }: {
  title?: React.ReactNode; meta?: React.ReactNode; actions?: React.ReactNode; children: React.ReactNode;
  className?: string; bodyClassName?: string; id?: string;
}) {
  return (
    <section id={id} className={cn("rounded-md border border-line bg-surface shadow-soft", className)} aria-labelledby={id ? `${id}-title` : undefined}>
      {(title || actions) && (
        <header className="flex min-h-11 flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-2">
          <div className="min-w-0">
            {title && <h2 id={id ? `${id}-title` : undefined} className="text-sm font-medium text-fg">{title}</h2>}
            {meta && <p className="text-xs text-fg-subtle">{meta}</p>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cn("p-4", bodyClassName)}>{children}</div>
    </section>
  );
}

export function Metric({ label, value, unit, hint, tone, className }: {
  label: string; value: React.ReactNode; unit?: string; hint?: React.ReactNode; tone?: string; className?: string;
}) {
  return (
    <div className={cn("rounded-md border border-line bg-surface px-4 py-3", className)}>
      <p className="label-instrument">{label}</p>
      <p className={cn("mt-2 font-mono text-2xl tabular-nums text-fg", tone)}>
        {value}
        {unit && <span className="ml-1 text-sm text-fg-subtle">{unit}</span>}
      </p>
      {hint && <p className="mt-1 text-xs text-fg-subtle">{hint}</p>}
    </div>
  );
}

export function KV({ k, v, mono }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return (
    <div className="grid grid-cols-[minmax(7rem,38%)_1fr] gap-3 py-1.5 text-meta">
      <dt className="text-fg-subtle">{k}</dt>
      <dd className={cn("min-w-0 break-words text-fg", mono && "font-mono text-xs leading-5")}>{v}</dd>
    </div>
  );
}

export function PageHeader({ title, eyebrow, description, actions }: {
  title: React.ReactNode; eyebrow?: string; description?: React.ReactNode; actions?: React.ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        {eyebrow && <p className="label-instrument mb-1.5">{eyebrow}</p>}
        <h1 className="text-2xl font-medium tracking-tight text-fg">{title}</h1>
        {description && <p className="mt-1 max-w-2xl text-sm text-fg-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Mono({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn("font-mono text-xs break-all text-fg-muted", className)}>{children}</span>;
}
