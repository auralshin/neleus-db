import type { ReactNode } from "react";
import type { Status, Mode } from "../lib/api";

export function Pill({ status, children }: { status: Status | "none"; children: ReactNode }) {
  return <span className={`pill ${status}`}>{children}</span>;
}

// enforce = red, monitor = amber. Used across Policies/Monitor/Violations.
export function ModeBadge({ mode }: { mode: Mode }) {
  return <span className={`badge ${mode === "enforce" ? "enforce" : "monitor"}`}>{mode}</span>;
}

// A violation was either blocked (enforced) or only logged.
export function EnforcedBadge({ enforced }: { enforced: boolean }) {
  return (
    <span className={`badge ${enforced ? "enforce" : "monitor"}`}>{enforced ? "BLOCKED" : "logged"}</span>
  );
}

export function Card({ num, label, note, tone }: { num: ReactNode; label: string; note?: string; tone?: "warn" }) {
  return (
    <div className="metric glass">
      <div className="metric-num">{num}</div>
      <div className="metric-label">{label}</div>
      {note && <div className={`metric-note ${tone ?? ""}`}>{note}</div>}
    </div>
  );
}

export function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="panel glass">
      <h3 className="panel-title">{title}</h3>
      {children}
    </section>
  );
}

export function Mono({ children }: { children: ReactNode }) {
  return <code className="mono">{children}</code>;
}

export function short(hash: string | null | undefined, n = 12): string {
  if (!hash) return "—";
  return hash.length > n ? hash.slice(0, n) + "…" : hash;
}
