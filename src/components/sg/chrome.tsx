import type { ReactNode } from "react";

import { cn } from "@/lib/utils";
import type { Severity, Verdict } from "@/lib/intel/types";
import { VERDICT_LABEL } from "@/lib/intel/types";

export function TerminalLabel({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("label-terminal flex items-center gap-2", className)}>
      <span className="text-muted-foreground/55">//</span>
      <span>{children}</span>
    </div>
  );
}

export function Panel({
  title,
  aside,
  children,
  className,
  tone = "default",
}: {
  title?: string;
  aside?: ReactNode;
  children: ReactNode;
  className?: string;
  tone?: "default" | "danger";
}) {
  return (
    <section
      className={cn(
        "glass-panel animate-rise relative overflow-hidden rounded-lg border",
        tone === "danger" ? "border-destructive/40" : "border-border",
        className,
      )}
    >
      {(title || aside) && (
        <header className="flex items-center justify-between gap-3 border-b border-border/70 px-4 py-2.5">
          {title ? <TerminalLabel>{title}</TerminalLabel> : <span />}
          {aside}
        </header>
      )}
      <div className="p-4 sm:p-5">{children}</div>
    </section>
  );
}

export function StatusDot({
  tone = "online",
  className,
}: {
  tone?: "online" | "danger" | "idle" | "warning" | "signal";
  className?: string;
}) {
  const color =
    tone === "danger"
      ? "bg-destructive"
      : tone === "signal"
        ? "bg-signal"
        : tone === "warning"
          ? "bg-warning"
          : tone === "idle"
            ? "bg-muted-foreground"
            : "bg-primary";
  return (
    <span
      className={cn(
        "inline-block size-1.5 shrink-0 rounded-full",
        color,
        tone !== "idle" && "animate-pulse-dot",
        className,
      )}
      aria-hidden
    />
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn("font-mono break-all text-sm", className)}>{children}</span>;
}

export function ScanLine() {
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden" aria-hidden>
      <div className="animate-scan h-8 w-full bg-gradient-to-b from-transparent via-primary/8 to-transparent" />
    </div>
  );
}

const VERDICT_TONE: Record<Verdict, string> = {
  safe: "border-success/50 text-success",
  low: "border-success/40 text-success/85",
  medium: "border-warning/50 text-warning",
  high: "border-destructive/60 text-destructive",
  critical: "border-destructive bg-destructive/10 text-destructive",
  unknown: "border-border-strong text-muted-foreground",
};

export function VerdictBadge({
  verdict,
  size = "md",
  className,
}: {
  verdict: Verdict | "not_applicable";
  size?: "sm" | "md" | "lg";
  className?: string;
}) {
  if (verdict === "not_applicable") {
    return (
      <span
        className={cn(
          "border border-border px-2 py-0.5 font-mono text-[0.6875rem] tracking-[0.14em] text-muted-foreground",
          className,
        )}
      >
        N/A
      </span>
    );
  }
  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 border font-mono tracking-[0.16em] uppercase",
        VERDICT_TONE[verdict],
        size === "lg"
          ? "px-3 py-1.5 text-sm"
          : size === "sm"
            ? "px-1.5 py-0.5 text-[0.625rem]"
            : "px-2 py-1 text-xs",
        className,
      )}
    >
      {VERDICT_LABEL[verdict]}
    </span>
  );
}

const SEVERITY_MARK: Record<Severity, { mark: string; className: string }> = {
  critical: { mark: "[!]", className: "text-destructive" },
  high: { mark: "[!]", className: "text-destructive" },
  medium: { mark: "[~]", className: "text-warning" },
  low: { mark: "[-]", className: "text-success/70" },
  info: { mark: "[+]", className: "text-muted-foreground" },
};

export function SeverityMark({ severity }: { severity: Severity }) {
  const { mark, className } = SEVERITY_MARK[severity];
  return <span className={cn("font-mono text-xs", className)}>{mark}</span>;
}

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <div className="border border-dashed border-border px-4 py-8 text-center font-mono text-xs tracking-[0.16em] text-muted-foreground uppercase">
      {children}
    </div>
  );
}
