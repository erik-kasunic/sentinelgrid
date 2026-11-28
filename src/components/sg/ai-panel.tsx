import { EmptyState, Panel, TerminalLabel } from "./chrome";
import type { AiAssessment, ProviderStatus, Verdict } from "@/lib/intel/types";

/** Text tone follows the deterministic verdict, never the AI's own opinion. */
const TONE: Record<Verdict, { text: string; border: string }> = {
  safe: { text: "text-success", border: "border-success/60" },
  low: { text: "text-success", border: "border-success/60" },
  medium: { text: "text-warning", border: "border-warning/60" },
  high: { text: "text-destructive", border: "border-destructive/60" },
  critical: { text: "text-destructive", border: "border-destructive/60" },
  unknown: { text: "text-foreground", border: "border-border" },
};

export function AiPanel({
  ai,
  status,
  verdict = "unknown",
}: {
  ai?: AiAssessment | null | undefined;
  status: ProviderStatus;
  verdict?: Verdict;
}) {
  const tone = TONE[verdict];
  return (
    <Panel
      title="AI SOC assessment"
      aside={
        <span className="font-mono text-[0.625rem] tracking-[0.14em] text-muted-foreground uppercase">
          explains evidence · never scores
        </span>
      }
    >
      {!ai ? (
        <EmptyState>
          {status.status === "not_configured"
            ? "AI analysis not configured"
            : status.status === "failed"
              ? `AI analysis failed${status.message ? `: ${status.message}` : ""}`
              : "No AI assessment available"}
        </EmptyState>
      ) : (
        <div className="space-y-5">
          <div className="grid gap-5 sm:grid-cols-2">
            <div className="space-y-2">
              <TerminalLabel>Analyst explanation</TerminalLabel>
              <p className={`text-sm leading-relaxed whitespace-pre-line ${tone.text} opacity-85`}>
                {ai.explanation}
              </p>
            </div>
            <div className="space-y-2">
              <TerminalLabel>Recommended action</TerminalLabel>
              <p className={`border-l-2 pl-3 text-sm leading-relaxed ${tone.border} ${tone.text}`}>
                {ai.recommended_action}
              </p>
            </div>
          </div>
        </div>
      )}
    </Panel>
  );
}
