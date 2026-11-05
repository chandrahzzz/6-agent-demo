"use client";

import { useMutation } from "@tanstack/react-query";
import { ChevronsLeft, ChevronsRight, LogOut, Menu, Moon, PlayCircle, Sun } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  AlertDialog, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { post } from "@/lib/api";
import { canOperate, useMe } from "@/lib/hooks";
import type { Drill } from "@/lib/types";
import { cn } from "@/lib/utils";

import { NAV } from "./nav";

function Wordmark({ compact }: { compact?: boolean }) {
  return (
    <Link href="/" className="flex items-center gap-2.5 rounded-sm" aria-label="MALLYA home">
      <svg viewBox="0 0 24 24" className="size-6 shrink-0 text-brand" aria-hidden>
        <path d="M4 18V6l8 7 8-7v12" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" />
        <path d="M4 18h16" stroke="currentColor" strokeWidth="1.8" opacity=".45" />
      </svg>
      {!compact && (
        <span className="font-mono text-sm font-semibold tracking-[0.22em] text-fg">MALLYA</span>
      )}
    </Link>
  );
}

function NavList({ collapsed, onNavigate }: { collapsed?: boolean; onNavigate?: () => void }) {
  const path = usePathname();
  return (
    <nav aria-label="Primary" className="flex flex-col gap-0.5">
      {NAV.map(({ href, label, icon: Icon }) => {
        const active = href === "/" ? path === "/" : path.startsWith(href);
        const link = (
          <Link
            key={href}
            href={href}
            onClick={onNavigate}
            aria-current={active ? "page" : undefined}
            className={cn(
              "group relative flex h-9 items-center gap-3 rounded-sm px-3 text-sm text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg",
              active && "bg-surface-2 text-fg",
              collapsed && "justify-center px-0",
            )}
          >
            {active && <span aria-hidden className="absolute inset-y-2 left-0 w-0.5 rounded-full bg-brand" />}
            <Icon className={cn("size-4 shrink-0", active ? "text-brand" : "text-fg-subtle group-hover:text-fg-muted")} aria-hidden />
            {collapsed ? <span className="sr-only">{label}</span> : <span className="truncate">{label}</span>}
          </Link>
        );
        return collapsed ? (
          <Tooltip key={href}>
            <TooltipTrigger asChild>{link}</TooltipTrigger>
            <TooltipContent side="right">{label}</TooltipContent>
          </Tooltip>
        ) : (
          link
        );
      })}
    </nav>
  );
}

function DemoButton() {
  const { data: me } = useMe();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [auto, setAuto] = useState(false);
  const m = useMutation({
    mutationFn: () => post<Drill>("/demo/start", { auto_approve: auto }),
    onSuccess: (d) => {
      setOpen(false);
      toast.success("Demo started: sandbox resetting, HERO-01 running");
      router.push(`/drills/${d.id}`);
    },
  });
  if (!canOperate(me)) return null;
  return (
    <>
      <Button size="sm" variant="outline" onClick={() => setOpen(true)} className="gap-2">
        <PlayCircle className="size-4 text-brand" aria-hidden />
        <span className="hidden sm:inline">Demo Mode</span>
        <span className="sm:hidden">Demo</span>
      </Button>
      <AlertDialog open={open} onOpenChange={(o) => { setOpen(o); if (!o) m.reset(); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Reset the sandbox and run Demo Mode?</AlertDialogTitle>
            <AlertDialogDescription>
              Resets the Meridian Bank sandbox from its seed and runs HERO-01 (public customer backup) end to end with real
              attacker traffic, real remediation and adversarial verification. It pauses for your approval.
              {" "}Current incidents in the sandbox are cleared.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="flex items-start justify-between gap-4 rounded-md border border-warning/40 bg-warning-soft p-3">
            <div>
              <Label htmlFor="auto" className="text-sm text-fg">Presenter auto-approve</Label>
              <p className="mt-1 text-xs text-fg-muted">
                Approves pending actions as <span className="font-mono">analyst@meridian.demo</span> and records that in the evidence.
                Actions held by the safety check are never auto-approved.
              </p>
            </div>
            <Switch id="auto" checked={auto} onCheckedChange={setAuto} />
          </div>
          {m.error && <p role="alert" className="text-xs text-critical">{m.error.message}</p>}
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <Button onClick={() => m.mutate()} disabled={m.isPending}>{m.isPending ? "Starting…" : "Reset sandbox and run"}</Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const dark = !mounted || resolvedTheme !== "light";
  return (
    <Button size="icon-sm" variant="ghost" onClick={() => setTheme(dark ? "light" : "dark")} aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}>
      {dark ? <Sun className="size-4" aria-hidden /> : <Moon className="size-4" aria-hidden />}
    </Button>
  );
}

function UserMenu() {
  const { data: me } = useMe();
  const router = useRouter();
  if (!me) return <div className="h-8 w-28" />;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" className="gap-2 px-2">
          <span aria-hidden className="grid size-6 place-items-center rounded-sm bg-surface-3 font-mono text-xs text-fg">
            {me.name.split(" ").map((p) => p[0]).join("").slice(0, 2)}
          </span>
          <span className="hidden text-left leading-tight md:block">
            <span className="block text-meta text-fg">{me.name}</span>
            <span className="block font-mono text-[0.625rem] text-fg-subtle">{me.role}</span>
          </span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-60">
        <DropdownMenuLabel>
          <span className="block text-sm">{me.email}</span>
          <span className="block font-mono text-xs font-normal text-fg-subtle">{me.role}{me.is_demo ? " · demo account" : ""}</span>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onSelect={async () => {
            await post("/auth/logout");
            router.replace("/login");
          }}
        >
          <LogOut className="size-4" aria-hidden /> Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobile, setMobile] = useState(false);
  useEffect(() => {
    try {
      setCollapsed(localStorage.getItem("mallya.sidebar") === "collapsed");
    } catch {
      /* storage unavailable */
    }
  }, []);
  const toggle = () => {
    setCollapsed((c) => {
      try {
        localStorage.setItem("mallya.sidebar", c ? "open" : "collapsed");
      } catch {
        /* ignore */
      }
      return !c;
    });
  };

  return (
    <div className="flex min-h-dvh">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-sm focus:bg-surface-2 focus:px-3 focus:py-2">
        Skip to content
      </a>
      <aside
        className={cn(
          "sticky top-0 hidden h-dvh shrink-0 flex-col border-r border-line bg-surface/95 lg:flex",
          collapsed ? "w-16" : "w-60",
        )}
      >
        <div className={cn("flex h-14 items-center border-b border-line", collapsed ? "justify-center" : "px-4")}>
          <Wordmark compact={collapsed} />
        </div>
        <div className="flex-1 overflow-y-auto p-2">
          <NavList collapsed={collapsed} />
        </div>
        <div className="border-t border-line p-2">
          <Button variant="ghost" size="sm" onClick={toggle} className={cn("w-full justify-start gap-3 text-fg-subtle", collapsed && "justify-center")}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"} aria-expanded={!collapsed}>
            {collapsed ? <ChevronsRight className="size-4" aria-hidden /> : <><ChevronsLeft className="size-4" aria-hidden /> Collapse</>}
          </Button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b border-line bg-background px-4 sm:gap-3">
          <Sheet open={mobile} onOpenChange={setMobile}>
            <SheetTrigger asChild>
              <Button size="icon-sm" variant="ghost" className="lg:hidden" aria-label="Open navigation">
                <Menu className="size-4" aria-hidden />
              </Button>
            </SheetTrigger>
            <SheetContent side="left" className="w-64 border-line bg-surface p-0">
              <SheetTitle className="sr-only">Navigation</SheetTitle>
              <div className="flex h-14 items-center border-b border-line px-4"><Wordmark /></div>
              <div className="p-2"><NavList onNavigate={() => setMobile(false)} /></div>
            </SheetContent>
          </Sheet>
          <div className="lg:hidden"><Wordmark compact /></div>
          <span className="inline-flex h-7 items-center gap-2 rounded-sm border border-line bg-surface px-2.5 font-mono text-xs text-fg-muted">
            <span aria-hidden className="size-1.5 rounded-full bg-warning" />
            SANDBOX<span className="hidden text-fg-subtle sm:inline">· Meridian Bank</span>
          </span>
          <div className="ml-auto flex items-center gap-1 sm:gap-2">
            <DemoButton />
            <ThemeToggle />
            <UserMenu />
          </div>
        </header>
        <main id="main" className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-6 sm:px-6 lg:px-8">{children}</main>
        <footer className="border-t border-line px-4 py-4 text-center text-xs text-fg-subtle sm:px-8">
          MALLYA · A concept prototype built for Redacto. Sandbox environment with synthetic data only — not a production system.
        </footer>
      </div>
    </div>
  );
}
