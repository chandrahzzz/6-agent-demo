import { CircleCheck, CircleDashed, OctagonAlert, TriangleAlert } from "lucide-react";

import { toneBg, toneOf, toneText } from "@/components/status";
import { cn } from "@/lib/utils";

const COPY: Record<string, { title: string; icon: typeof CircleCheck }> = {
  VERIFIED_FIXED: { title: "Verified fixed", icon: CircleCheck },
  PARTIALLY_FIXED: { title: "Partially fixed", icon: TriangleAlert },
  STILL_EXPOSED: { title: "Still exposed", icon: OctagonAlert },
  UNVERIFIED: { title: "Unverified", icon: CircleDashed },
  VERIFICATION_FAILED: { title: "Verification failed", icon: CircleDashed },
};

/** The big verdict reveal at the bottom of the verification screen. */
export function VerdictBanner({ verdict, residual, reasons, runRef }: { verdict: string; residual: string[]; reasons: string[]; runRef: string }) {
  const t = toneOf(verdict);
  const c = COPY[verdict] ?? COPY.UNVERIFIED;
  const Icon = c.icon;
  return (
    <div role="status" aria-live="polite" key={runRef}
      className={cn("animate-reveal rounded-md border-2 px-5 py-4", toneBg[t],
        t === "unverified" ? "border-dashed border-unverified/60" : t === "ok" ? "border-ok/50" : t === "warning" ? "border-warning/50" : "border-critical/50")}>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <Icon className={cn("size-7 shrink-0", toneText[t])} aria-hidden />
        <div className="min-w-0 flex-1">
          <p className="label-instrument">Adversarial verification · {runRef}</p>
          <p className={cn("font-mono text-2xl font-semibold", toneText[t])}>{verdict.replaceAll("_", " ")}</p>
        </div>
        <p className="text-meta text-fg-muted sm:max-w-sm sm:text-right">{c.title === "Verified fixed"
          ? "External access is denied on every known path, every copy is accounted for, and the authorised consumer still works."
          : `${c.title}. MALLYA does not accept the fix until an outside attack fails everywhere.`}</p>
      </div>
      {residual.length > 0 && (
        <p className="mt-3 border-t border-line pt-3 text-sm text-fg">
          <span className="font-medium">Residual exposure:</span>{" "}
          <span className="font-mono text-meta">{residual.join(", ")}</span>
        </p>
      )}
      {verdict !== "VERIFIED_FIXED" && reasons.length > 0 && (
        <ul className="mt-2 space-y-0.5 font-mono text-xs text-fg-muted">
          {reasons.slice(0, 6).map((r, i) => <li key={i}>· {r}</li>)}
        </ul>
      )}
    </div>
  );
}
