"use client";

import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";

import { api } from "./api";
import type { AgentEvent, Me } from "./types";

export function useMe() {
  return useQuery({ queryKey: ["me"], queryFn: () => api<Me>("/auth/me"), staleTime: 60_000 });
}

export const canApprove = (me?: Me) => me?.role === "ADMIN" || me?.role === "SECURITY_ANALYST";
export const canOperate = (me?: Me) => canApprove(me) || me?.role === "IMPLEMENTATION_ENGINEER";

/** GET helper with optional polling while `live` is true. */
export function useApi<T>(key: unknown[], path: string | null, opts: { live?: boolean; interval?: number } = {}) {
  return useQuery({
    queryKey: key,
    queryFn: () => api<T>(path as string),
    enabled: path !== null,
    refetchInterval: opts.live ? (opts.interval ?? 2500) : false,
  });
}

/** Server-Sent Events from the agent runtime (replays history, then streams). */
export function useEventStream(url: string | null) {
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [state, setState] = useState<"idle" | "connecting" | "open" | "error">("idle");
  const seen = useRef(new Set<number>());

  useEffect(() => {
    if (!url) return;
    seen.current = new Set();
    setEvents([]);
    setState("connecting");
    const es = new EventSource(url, { withCredentials: true });
    const onMsg = (e: MessageEvent) => {
      const ev = JSON.parse(e.data) as AgentEvent;
      if (seen.current.has(ev.id)) return;
      seen.current.add(ev.id);
      setEvents((prev) => [...prev, ev]);
    };
    const kinds = ["agent.started", "agent.step", "agent.completed", "agent.failed", "agent.retry", "beat", "drill.completed", "drill.failed"];
    kinds.forEach((k) => es.addEventListener(k, onMsg as EventListener));
    es.onopen = () => setState("open");
    es.onerror = () => setState(es.readyState === EventSource.CLOSED ? "error" : "connecting");
    return () => es.close();
  }, [url]);

  return { events, state };
}
