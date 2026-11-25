import { Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { Copy, Download, FileText, Lock } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "./app-shell";
import { EmptyState, Mono, Panel, TerminalLabel, VerdictBadge } from "./chrome";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/hooks/useAuth";
import { buildQuery, collectIocs, SIEM_LABEL, type SiemPlatform } from "@/lib/intel/detection";
import type { InvestigationResult } from "@/lib/intel/types";
import {
  getInvestigation,
  listInvestigations,
  type CaseSummary,
} from "@/lib/investigations.functions";
import { cn } from "@/lib/utils";

const PLATFORMS = Object.keys(SIEM_LABEL) as SiemPlatform[];

export function CaseWorkbench({ mode }: { mode: "siem" | "report" }) {
  const { signedIn, loading: authLoading } = useAuth();
  const list = useServerFn(listInvestigations);
  const load = useServerFn(getInvestigation);
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [platform, setPlatform] = useState<SiemPlatform>("sentinel");
  const [wide, setWide] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!signedIn) return;
    void list({ data: { limit: 100 } }).then((r) => {
      setCases(r.cases);
      const first = r.cases[0];
      if (first) setSelected((s) => s ?? first.id);
    });
  }, [signedIn, list]);

  useEffect(() => {
    if (!selected) return;
    setResult(null);
    void load({ data: { id: selected } }).then((r) =>
      r.ok ? setResult(r.result) : toast.error(r.error),
    );
  }, [selected, load]);

  const iocs = useMemo(() => (result ? collectIocs(result, wide) : null), [result, wide]);
  const query = useMemo(
    () => (result && iocs ? buildQuery(platform, result, iocs) : ""),
    [platform, result, iocs],
  );

  const title = mode === "siem" ? "SIEM & Detection" : "Incident reports";

  if (authLoading)
    return (
      <AppShell>
        <div className="p-8" />
      </AppShell>
    );
  if (!signedIn)
    return (
      <AppShell>
        <div className="mx-auto max-w-xl px-6 py-24 text-center">
          <Lock className="mx-auto mb-4 size-8 text-primary" />
          <h1 className="text-2xl font-semibold">{title}</h1>
          <p className="mt-3 text-muted-foreground">
            {mode === "siem"
              ? "Generate hunting queries and detection rules from your saved cases."
              : "Export saved cases as formal PDF incident reports."}{" "}
            Available for signed-in analysts.
          </p>
          <Button asChild className="mt-6">
            <Link to="/auth">Sign in</Link>
          </Button>
        </div>
      </AppShell>
    );

  return (
    <AppShell>
      <div className="mx-auto w-full max-w-6xl space-y-6 px-4 py-8 md:px-8">
        <div>
          <TerminalLabel>{mode === "siem" ? "detection engineering" : "reporting"}</TerminalLabel>
          <h1 className="mt-2 text-2xl font-semibold">{title}</h1>
        </div>

        {cases.length === 0 ? (
          <EmptyState>No saved cases yet — run an investigation first</EmptyState>
        ) : (
          <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
            <Panel title="Cases">
              <div className="max-h-[60vh] space-y-1 overflow-y-auto">
                {cases.map((c) => (
                  <button
                    key={c.id}
                    onClick={() => setSelected(c.id)}
                    className={cn(
                      "flex w-full items-center justify-between gap-2 border px-3 py-2 text-left text-sm transition-colors",
                      selected === c.id
                        ? "border-primary/60 bg-primary/10"
                        : "border-transparent hover:bg-secondary",
                    )}
                  >
                    <span className="min-w-0 truncate font-mono text-xs">
                      {c.title || c.initial_target}
                    </span>
                    <VerdictBadge verdict={c.verdict} size="sm" />
                  </button>
                ))}
              </div>
            </Panel>

            {!result || !iocs ? (
              <Panel title="Loading">
                <EmptyState>Loading case…</EmptyState>
              </Panel>
            ) : mode === "siem" ? (
              <Panel
                title="Hunting queries"
                aside={
                  <label className="flex items-center gap-2 font-mono text-xs text-muted-foreground">
                    <input
                      type="checkbox"
                      checked={wide}
                      onChange={(e) => setWide(e.target.checked)}
                    />
                    include unflagged related nodes
                  </label>
                }
              >
                <div className="mb-3 flex flex-wrap gap-2">
                  {PLATFORMS.map((p) => (
                    <Button
                      key={p}
                      size="sm"
                      variant={p === platform ? "default" : "outline"}
                      onClick={() => setPlatform(p)}
                    >
                      {SIEM_LABEL[p]}
                    </Button>
                  ))}
                </div>
                <p className="mb-2 font-mono text-xs text-muted-foreground">
                  {iocs.ips.length} IP · {iocs.domains.length} domain · {iocs.urls.length} URL ·{" "}
                  {iocs.hashes.length} hash
                </p>
                <pre className="max-h-[55vh] overflow-auto border border-border bg-background/80 p-4 font-mono text-xs leading-relaxed whitespace-pre-wrap">
                  {query}
                </pre>
                <div className="mt-3 flex gap-2">
                  <Button
                    size="sm"
                    onClick={() =>
                      void navigator.clipboard.writeText(query).then(() => toast.success("Copied"))
                    }
                  >
                    <Copy className="mr-1 size-4" />
                    Copy
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      const blob = new Blob([query], { type: "text/plain" });
                      const a = document.createElement("a");
                      a.href = URL.createObjectURL(blob);
                      a.download = `sentinelgrid-${platform}.${platform === "sigma" ? "yml" : platform === "suricata" ? "rules" : "txt"}`;
                      a.click();
                    }}
                  >
                    <Download className="mr-1 size-4" />
                    Download
                  </Button>
                </div>
                <p className="mt-3 text-xs text-muted-foreground">
                  Review before deploying — shared hosting and CDN IPs can cause false positives.
                </p>
              </Panel>
            ) : (
              <Panel title="PDF incident report">
                <div className="flex items-center gap-3">
                  <VerdictBadge verdict={result.verdict} />
                  <Mono>{result.title ?? result.target}</Mono>
                </div>
                <ul className="mt-4 space-y-1 text-sm text-muted-foreground">
                  <li>· Executive summary, verdict and deterministic score</li>
                  <li>
                    · {result.riskScore.lines.length} score rules · {result.evidence.length}{" "}
                    evidence items · {result.recommendations.length} response steps
                  </li>
                  <li>· {result.providerStatus.length} intelligence sources with status</li>
                  <li>
                    · Appendix:{" "}
                    {iocs.ips.length + iocs.domains.length + iocs.urls.length + iocs.hashes.length}{" "}
                    defanged IOCs and {result.relationships.length} relationships
                  </li>
                </ul>
                <Button
                  className="mt-6"
                  disabled={busy}
                  onClick={async () => {
                    setBusy(true);
                    try {
                      const { downloadPdfReport } = await import("@/lib/intel/pdf-report");
                      await downloadPdfReport(result);
                    } catch (e) {
                      console.error(e);
                      toast.error("Could not build the PDF.");
                    } finally {
                      setBusy(false);
                    }
                  }}
                >
                  <FileText className="mr-1 size-4" />
                  {busy ? "Building…" : "Download PDF report"}
                </Button>
              </Panel>
            )}
          </div>
        )}
      </div>
    </AppShell>
  );
}
