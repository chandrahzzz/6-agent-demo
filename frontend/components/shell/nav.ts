import { Activity, Bot, Boxes, FlaskConical, Gauge, LockKeyhole, Settings, ShieldAlert, Vault } from "lucide-react";

export const NAV = [
  { href: "/", label: "Dashboard", icon: Gauge },
  { href: "/incidents", label: "Incidents", icon: ShieldAlert },
  { href: "/drills", label: "Breach Drill Lab", icon: FlaskConical },
  { href: "/assets", label: "Assets", icon: Boxes },
  { href: "/benchmarks", label: "Benchmarks", icon: Activity },
  { href: "/evidence", label: "Evidence Vault", icon: Vault },
  { href: "/privacy", label: "Privacy Boundary", icon: LockKeyhole },
  { href: "/agents", label: "Agents", icon: Bot },
  { href: "/settings", label: "Settings", icon: Settings },
] as const;
