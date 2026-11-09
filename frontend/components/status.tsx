import { cn } from "@/lib/utils";

export type Tone = "critical" | "warning" | "ok" | "unverified" | "info" | "neutral";

const TONE: Record<string, Tone> = {
  // incident / verification verdicts
  STILL_EXPOSED: "critical", PARTIALLY_FIXED: "warning", VERIFIED_FIXED: "ok", UNVERIFIED: "unverified",
  VERIFICATION_FAILED: "unverified", CLOSED: "neutral",
  DETECTED: "info", INVESTIGATING: "info", AWAITING_APPROVAL: "warning", REMEDIATING: "info", VERIFYING: "info",
  // access verdicts
  LIKELY_EXFILTRATED: "critical", ACCESS_ATTEMPTED_NOT_SUCCESSFUL: "warning", ACCESSED_INTERNAL_ONLY: "info",
  EXPOSED_NOT_ACCESSED: "info", INSUFFICIENT_EVIDENCE: "unverified", FALSE_POSITIVE: "neutral",
  // severity bands
  Critical: "critical", High: "warning", Moderate: "info", Low: "neutral", Info: "neutral",
  // actions
  PENDING: "warning", HELD: "warning", APPROVED: "ok", REJECTED: "critical", NOT_STARTED: "neutral", RUNNING: "info",
  SUCCEEDED: "ok", FAILED: "critical", SKIPPED: "unverified", SUPERSEDED: "neutral",
  // probes / copy hunt
  DENIED: "ok", ACCESSIBLE: "critical", EXPOSED: "critical", PROTECTED: "ok", NO_MATCH: "neutral",
  THIRD_PARTY_COPY: "warning", DNS_FAILURE: "unverified", TIMEOUT: "unverified", CONNECTION_REFUSED: "unverified",
  SERVER_ERROR: "unverified", NOT_FOUND: "unverified", VERIFIED_PRIVATE: "ok", OK: "neutral", PUBLIC: "critical",
  DATA_PRESENT: "warning", SYSTEM_OF_RECORD: "neutral", PATH: "info",
  // agents / drills
  COMPLETED: "ok", CREATED: "neutral", COMPLETED_NO_INCIDENT: "neutral", PASS: "ok", FAIL: "critical",
};

export const toneOf = (s: string | null | undefined): Tone => (s ? (TONE[s] ?? "neutral") : "unverified");

export const toneText: Record<Tone, string> = {
  critical: "text-critical", warning: "text-warning", ok: "text-ok", unverified: "text-unverified", info: "text-info", neutral: "text-fg-muted",
};
export const toneBg: Record<Tone, string> = {
  critical: "bg-critical-soft", warning: "bg-warning-soft", ok: "bg-ok-soft", unverified: "bg-unverified-soft", info: "bg-info-soft",
  neutral: "bg-surface-2",
};
const toneBorder: Record<Tone, string> = {
  critical: "border-critical/40", warning: "border-warning/40", ok: "border-ok/40", unverified: "border-unverified/50 border-dashed",
  info: "border-info/35", neutral: "border-line",
};

const LABEL: Record<string, string> = { ACCESS_ATTEMPTED_NOT_SUCCESSFUL: "ATTEMPTED · NOT SUCCESSFUL" };

export function StatusChip({ status, label, className, dot = true }: { status: string | null | undefined; label?: string; className?: string; dot?: boolean }) {
  const t = toneOf(status);
  const text = label ?? (status ? (LABEL[status] ?? status.replaceAll("_", " ")) : "UNVERIFIED");
  return (
    <span
      className={cn(
        "inline-flex h-6 shrink-0 items-center gap-1.5 rounded-sm border px-2 font-mono text-xs leading-none whitespace-nowrap uppercase",
        toneBg[t], toneText[t], toneBorder[t], className,
      )}
    >
      {dot && <span aria-hidden className={cn("size-1.5 rounded-full bg-current", (status === "RUNNING" || status === "VERIFYING" || status === "INVESTIGATING" || status === "REMEDIATING") && "animate-pulse-dot")} />}
      {text}
    </span>
  );
}
