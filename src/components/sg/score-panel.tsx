import { Panel, TerminalLabel, VerdictBadge } from "./chrome";
import type { Dimension, RiskScore, Verdict } from "@/lib/intel/types";
import { cn } from "@/lib/utils";

function barTone(band: Verdict) {
  if (band === "critical" || band === "high") return "bg-destructive";
  if (band === "medium") return "bg-warning";
  if (band === "unknown") return "bg-muted-foreground";
  return "bg-primary";
}

function scoreTone(band: Verdict) {
  if (band === "critical" || band === "high") return "text-destructive";
  if (band === "medium") return "text-warning";
  if (band === "unknown") return "text-muted-foreground";
  return "text-primary";
}

function scoreLabel(band: Verdict) {
  if (band === "critical" || band === "high") return "BAD — high risk";
  if (band === "medium") return "CAUTION — medium risk";
  if (band === "unknown") return "UNKNOWN — insufficient evidence";
  return "GOOD — low risk";
}

export function ScorePanel({
  score,
  verdict,
  dimensions,
}: {
  score: RiskScore;
  verdict: Verdict;
  dimensions: Dimension[];
}) {
  const insufficient = score.basis === "insufficient";

  return (
    <Panel
      title="Risk assessment"
      tone={verdict === "critical" || verdict === "high" ? "danger" : "default"}
      aside={<VerdictBadge verdict={verdict} size="lg" />}
    >
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
        <div>
          <div className="flex flex-col items-center gap-1 py-2 text-center">
            <span
              className={cn(
                "font-mono text-7xl leading-none font-bold",
                insufficient ? "text-muted-foreground" : scoreTone(score.band),
              )}
            >
              {insufficient ? "--" : score.total}
            </span>
            <span className="font-mono text-sm text-muted-foreground">/ 100 risk score</span>
            <span
              className={cn(
                "mt-1 font-mono text-[0.6875rem] tracking-[0.18em] uppercase",
                insufficient ? "text-muted-foreground" : scoreTone(score.band),
              )}
            >
              {insufficient ? scoreLabel("unknown") : scoreLabel(score.band)}
            </span>
          </div>

          <div className="mt-4 h-1.5 w-full bg-muted">
            <div
              className={cn("h-full transition-[width] duration-700", barTone(score.band))}
              style={{ width: insufficient ? "0%" : `${score.total}%` }}
            />
          </div>

          <p className="mt-4 text-sm text-muted-foreground">
            {insufficient
              ? (score.note ??
                "Evidence coverage was insufficient to assess this target. UNKNOWN is not the same as safe.")
              : (score.note ??
                "Score is calculated deterministically from provider evidence. The AI assessment cannot change it.")}
          </p>

          <div className="mt-5 space-y-3">
            <TerminalLabel>Score breakdown</TerminalLabel>
            {score.lines.length === 0 ? (
              <div className="border border-success/25 bg-success/5 p-3 font-mono text-xs text-success">
                0 risk indicators found in completed checks
              </div>
            ) : (
              <ul className="space-y-2">
                {score.lines.map((line) => (
                  <li key={line.category} className="font-mono text-xs">
                    <div className="flex items-baseline justify-between gap-3">
                      <span className="text-muted-foreground">{line.label}</span>
                      <span
                        className={line.points > 0 ? "text-foreground" : "text-muted-foreground"}
                      >
                        +{line.points} / {line.max}
                      </span>
                    </div>
                    <div className="mt-1 h-0.5 w-full bg-muted">
                      <div
                        className={cn(
                          "h-full",
                          line.points > 0 ? barTone(score.band) : "bg-transparent",
                        )}
                        style={{ width: `${(line.points / line.max) * 100}%` }}
                      />
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        <div className="space-y-3">
          <TerminalLabel>Risk dimensions</TerminalLabel>
          <div className="grid gap-3 sm:grid-cols-2">
            {dimensions.map((dimension) => (
              <div key={dimension.name} className="border border-border bg-background/50 p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[0.6875rem] tracking-[0.14em] text-muted-foreground uppercase">
                    {dimension.name}
                  </span>
                  <VerdictBadge verdict={dimension.state} size="sm" />
                </div>
                <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                  {dimension.note}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </Panel>
  );
}
