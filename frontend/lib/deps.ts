/** Mirrors backend/app/remediation/deps.py: which approved actions can run now, and what blocks the rest. */
type Act = { code: string; approval_status: string; execution_status: string; depends_on?: string[] | null };
export type DepState = { code: string; state: string };

const WAITING = ["NOT_STARTED", "FAILED"];

export function executionPlan(actions: Act[]): { order: string[]; blocked: Record<string, DepState[]> } {
  const byCode = new Map(actions.map((a) => [a.code, a]));
  const candidates = actions
    .filter((a) => a.approval_status === "APPROVED" && WAITING.includes(a.execution_status))
    .sort((a, b) => a.code.localeCompare(b.code));
  const order: string[] = [];
  let progress = true;
  while (progress) {
    progress = false;
    for (const a of candidates) {
      if (order.includes(a.code)) continue;
      const ok = (a.depends_on ?? []).every((d) => {
        const dep = byCode.get(d);
        return dep !== undefined && (dep.execution_status === "SUCCEEDED" || order.includes(dep.code));
      });
      if (ok) { order.push(a.code); progress = true; }
    }
  }
  const blocked: Record<string, DepState[]> = {};
  for (const a of candidates) {
    if (order.includes(a.code)) continue;
    blocked[a.code] = depStates(a, byCode).filter((d) => d.state !== "SUCCEEDED" && !order.includes(d.code));
  }
  return { order, blocked };
}

/** Current state of each dependency, as a person would read it. */
export function depStates(a: Act, byCode: Map<string, Act>): DepState[] {
  return (a.depends_on ?? []).map((d) => {
    const dep = byCode.get(d);
    if (!dep) return { code: d, state: "MISSING" };
    if (dep.execution_status === "SUCCEEDED") return { code: d, state: "SUCCEEDED" };
    return { code: d, state: dep.approval_status === "APPROVED" ? dep.execution_status : dep.approval_status };
  });
}

export function blockedMessage(code: string, deps: DepState[]): string {
  const dead = deps.filter((d) => d.state === "REJECTED" || d.state === "SUPERSEDED" || d.state === "MISSING");
  if (dead.length) {
    return `${code} cannot run: ${dead.map((d) => `${d.code} is ${d.state.toLowerCase()}`).join(", ")}. ` +
      "MALLYA re-proposes a fix after the next verification if the exposure is still there.";
  }
  const open = deps.filter((d) => d.state !== "SUCCEEDED");
  return `${code} waits for ${open.map((d) => `${d.code} (${d.state.toLowerCase().replace("_", " ")})`).join(", ")}. ` +
    "Approve it too; dependencies run first, then this one.";
}
