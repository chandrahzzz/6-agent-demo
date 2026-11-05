"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { post } from "@/lib/api";

const schema = z.object({
  email: z.string().email("Enter a valid email address"),
  password: z.string().min(1, "Enter your password"),
});
type Form = z.infer<typeof schema>;

const DEMO = [
  ["analyst@meridian.demo", "Security analyst · approves remediation"],
  ["engineer@meridian.demo", "Implementation engineer · runs drills"],
  ["admin@meridian.demo", "Admin"],
  ["viewer@meridian.demo", "Viewer · read only"],
];

function LoginForm() {
  const router = useRouter();
  const next = useSearchParams().get("next") || "/";
  const [error, setError] = useState<string | null>(null);
  const { register, handleSubmit, setValue, formState } = useForm<Form>({ resolver: zodResolver(schema) });
  const onSubmit = handleSubmit(async (v) => {
    setError(null);
    try {
      await post("/auth/login", v);
      router.replace(next.startsWith("/") ? next : "/");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Sign-in failed");
    }
  });

  return (
    <div className="grid min-h-dvh place-items-center px-4 py-10">
      <div className="w-full max-w-[400px]">
        <div className="mb-8 text-center">
          <p className="font-mono text-xl font-semibold tracking-[0.3em] text-fg">MALLYA</p>
          <p className="mt-2 label-instrument">Detect · Investigate · Remediate · Prove</p>
        </div>
        <form onSubmit={onSubmit} noValidate className="rounded-md border border-line bg-surface p-6 shadow-soft">
          <h1 className="text-xl font-medium text-fg">Sign in</h1>
          <p className="mt-1 text-meta text-fg-muted">Sandbox environment · Meridian Bank (fictional)</p>
          <div className="mt-6 space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="email">Email</Label>
              <Input id="email" type="email" autoComplete="username" aria-invalid={!!formState.errors.email}
                aria-describedby={formState.errors.email ? "email-err" : undefined} {...register("email")} />
              {formState.errors.email && <p id="email-err" className="text-xs text-critical">{formState.errors.email.message}</p>}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password">Password</Label>
              <Input id="password" type="password" autoComplete="current-password" aria-invalid={!!formState.errors.password}
                aria-describedby={formState.errors.password ? "pw-err" : undefined} {...register("password")} />
              {formState.errors.password && <p id="pw-err" className="text-xs text-critical">{formState.errors.password.message}</p>}
            </div>
            {error && <p role="alert" className="rounded-sm border border-critical/40 bg-critical-soft px-3 py-2 text-meta text-fg">{error}</p>}
            <Button type="submit" className="w-full" disabled={formState.isSubmitting}>
              {formState.isSubmitting ? "Signing in…" : "Sign in"}
            </Button>
          </div>
        </form>

        <div className="mt-4 rounded-md border border-dashed border-line-strong p-4">
          <p className="label-instrument">Demo credentials · demo-only, sandbox use</p>
          <p className="mt-2 text-xs text-fg-muted">
            Password for every account: <span className="font-mono text-fg">mallya-demo-2026</span>
          </p>
          <ul className="mt-3 space-y-1">
            {DEMO.map(([email, role]) => (
              <li key={email}>
                <button type="button" onClick={() => { setValue("email", email); setValue("password", "mallya-demo-2026"); }}
                  className="flex w-full items-baseline justify-between gap-3 rounded-sm px-2 py-1.5 text-left hover:bg-surface-2">
                  <span className="font-mono text-xs text-fg">{email}</span>
                  <span className="truncate text-xs text-fg-subtle">{role}</span>
                </button>
              </li>
            ))}
          </ul>
        </div>
        <p className="mt-6 text-center text-xs text-fg-subtle">A concept prototype built for Redacto.</p>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}
