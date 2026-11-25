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
          <p className={`text-sm leading-relaxed font-medium ${tone.text}`}>{ai.summary}</p>

          <div className="space-y-2">
            <TerminalLabel>Analyst explanation</TerminalLabel>
            <p className={`text-sm leading-relaxed whitespace-pre-line ${tone.text} opacity-85`}>
              {ai.explanation}
            </p>
          </div>

          <div className="space-y-2">
            <TerminalLabel>In plain language</TerminalLabel>
            <p className={`text-sm leading-relaxed ${tone.text} opacity-85`}>
              {ai.simple_explanation}
            </p>
          </div>

          <div className="space-y-2">
            <TerminalLabel>Recommended action</TerminalLabel>
            <p className={`border-l-2 pl-3 text-sm leading-relaxed ${tone.border} ${tone.text}`}>
              {ai.recommended_action}
            </p>
          </div>

          {ai.uncertainties.length > 0 && (
            <div className="space-y-2">
              <TerminalLabel>Uncertainties</TerminalLabel>
              <ul className="space-y-1">
                {ai.uncertainties.map((item) => (
                  <li key={item} className="text-xs text-muted-foreground">
                    <span className="mr-2 font-mono text-warning">?</span>
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="flex items-center gap-3 border-t border-border/60 pt-3">
            <span className="label-terminal">AI confidence</span>
            <div className="h-1 w-28 bg-muted">
              <div className="h-full bg-primary" style={{ width: `${ai.confidence}%` }} />
            </div>
            <span className="font-mono text-xs text-muted-foreground">{ai.confidence}%</span>
          </div>
        </div>
      )}
    </Panel>
  );
}
