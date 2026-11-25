import { Panel } from "./chrome";
import { PROVIDER_STATUS_LABEL, providerName } from "@/lib/intel/provider-meta";
import type { ProviderStatus } from "@/lib/intel/types";
import { cn } from "@/lib/utils";

const TONE: Record<ProviderStatus["status"], string> = {
  completed: "text-primary",
  failed: "text-destructive",
  not_configured: "text-warning",
  not_applicable: "text-muted-foreground",
  rate_limited: "text-warning",
};

const MARK: Record<ProviderStatus["status"], string> = {
  completed: "[ok]",
  failed: "[fail]",
  not_configured: "[--]",
  not_applicable: "[n/a]",
  rate_limited: "[quota]",
};

export function ProviderPanel({
  statuses,
  aiStatus,
}: {
  statuses: ProviderStatus[];
  aiStatus: ProviderStatus;
}) {
  const rows = [...statuses, aiStatus];
  return (
    <Panel title="Intelligence sources">
      <ul className="divide-y divide-border/60">
        {rows.map((row) => (
          <li key={row.provider} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 py-2.5">
            <span className={cn("w-14 shrink-0 font-mono text-xs", TONE[row.status])}>
              {MARK[row.status]}
            </span>
            <span className="font-mono text-sm text-foreground">
              {row.provider === "ai" ? "AI analyst" : providerName(row.provider)}
            </span>
            <span className={cn("font-mono text-[0.625rem] tracking-[0.14em]", TONE[row.status])}>
              {PROVIDER_STATUS_LABEL[row.status]}
            </span>
            {typeof row.durationMs === "number" && (
              <span className="font-mono text-[0.625rem] text-muted-foreground">
                {row.durationMs}ms
              </span>
            )}
            {row.message && (
              <span className="w-full text-xs text-muted-foreground sm:ml-14">{row.message}</span>
            )}
          </li>
        ))}
      </ul>
    </Panel>
  );
}
