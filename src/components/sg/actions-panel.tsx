import { EmptyState, Panel } from "./chrome";
import type { Recommendation } from "@/lib/intel/types";

export function ActionsPanel({ recommendations }: { recommendations: Recommendation[] }) {
  return (
    <Panel title="Recommended actions">
      {recommendations.length === 0 ? (
        <EmptyState>No actions recommended</EmptyState>
      ) : (
        <ol className="space-y-3">
          {recommendations.map((item) => (
            <li key={item.step} className="flex gap-3">
              <span className="mt-0.5 flex size-6 shrink-0 items-center justify-center border border-primary/50 font-mono text-xs text-primary">
                {item.step}
              </span>
              <div>
                <p className="text-sm text-foreground">{item.text}</p>
                {item.rationale && (
                  <p className="mt-1 text-xs text-muted-foreground">{item.rationale}</p>
                )}
              </div>
            </li>
          ))}
        </ol>
      )}
    </Panel>
  );
}
