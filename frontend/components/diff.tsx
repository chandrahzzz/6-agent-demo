import { cn } from "@/lib/utils";

/** Unified diff, rendered line by line (git-style). */
export function DiffView({ diff, title, className }: { diff: string | null | undefined; title?: string; className?: string }) {
  const lines = (diff ?? "").split("\n").filter((l, i, a) => !(i === a.length - 1 && l === ""));
  return (
    <figure className={cn("min-w-0 overflow-hidden rounded-md border border-line bg-background", className)}>
      {title && <figcaption className="border-b border-line bg-surface-2 px-3 py-2 font-mono text-xs text-fg-muted">{title}</figcaption>}
      {lines.length === 0 ? (
        <p className="p-3 text-meta text-fg-subtle">No diff available.</p>
      ) : (
        <pre className="overflow-x-auto py-2 font-mono text-xs leading-5">
          {lines.map((l, i) => {
            const kind = l.startsWith("+++") || l.startsWith("---") ? "file" : l.startsWith("@@") ? "hunk" : l[0] === "+" ? "add" : l[0] === "-" ? "del" : "ctx";
            return (
              <div key={i} className={cn("px-3 whitespace-pre",
                kind === "add" && "bg-ok-soft text-ok", kind === "del" && "bg-critical-soft text-critical",
                kind === "hunk" && "text-info", kind === "file" && "text-fg-subtle", kind === "ctx" && "text-fg-muted")}>
                <span className="sr-only">{kind === "add" ? "added: " : kind === "del" ? "removed: " : ""}</span>
                {l || " "}
              </div>
            );
          })}
        </pre>
      )}
    </figure>
  );
}
