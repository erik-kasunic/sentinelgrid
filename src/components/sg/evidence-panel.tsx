import { ExternalLink } from "lucide-react";

import { EmptyState, Panel, SeverityMark } from "./chrome";
import { providerName } from "@/lib/intel/provider-meta";
import type { Evidence } from "@/lib/intel/types";

export function EvidencePanel({ evidence }: { evidence: Evidence[] }) {
  return (
    <Panel
      title="Evidence"
      aside={
        <span className="font-mono text-[0.625rem] tracking-[0.14em] text-muted-foreground uppercase">
          {evidence.length} item{evidence.length === 1 ? "" : "s"}
        </span>
      }
    >
      {evidence.length === 0 ? (
        <EmptyState>No evidence returned by any source</EmptyState>
      ) : (
        <ul className="space-y-2.5">
          {evidence.map((item, index) => (
            <li
              key={`${item.provider}-${item.label}-${index}`}
              className="flex gap-3 border border-border/70 bg-background/40 p-3"
            >
              <SeverityMark severity={item.severity} />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                  <span className="text-sm text-foreground">{item.label}</span>
                  <span className="font-mono text-[0.625rem] tracking-[0.14em] text-primary-dim uppercase">
                    {providerName(item.provider)}
                  </span>
                  {typeof item.confidence === "number" && (
                    <span className="font-mono text-[0.625rem] text-muted-foreground">
                      confidence {item.confidence}%
                    </span>
                  )}
                </div>
                {item.detail && (
                  <p className="mt-1 font-mono text-xs break-all text-muted-foreground">
                    {item.detail}
                  </p>
                )}
                <div className="mt-1.5 flex flex-wrap items-center gap-3">
                  {item.observedAt && (
                    <span className="font-mono text-[0.625rem] text-muted-foreground">
                      observed {new Date(item.observedAt).toLocaleString()}
                    </span>
                  )}
                  {(item.links?.length ?? 0) > 0 &&
                    item.links!.map((link) => (
                      <a
                        key={link.url}
                        href={link.url}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="inline-flex items-center gap-1 font-mono text-[0.625rem] text-primary hover:underline"
                      >
                        {providerName(link.label)} site <ExternalLink className="size-3" />
                      </a>
                    ))}
                  {item.sourceUrl && (
                    <a
                      href={item.sourceUrl}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="inline-flex items-center gap-1 font-mono text-[0.625rem] text-primary hover:underline"
                    >
                      source <ExternalLink className="size-3" />
                    </a>
                  )}
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
