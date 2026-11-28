import { Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { Download, Save } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";

import { ActionsPanel } from "./actions-panel";
import { AiPanel } from "./ai-panel";
import { Mono, Panel, TerminalLabel, VerdictBadge } from "./chrome";
import { EvidencePanel } from "./evidence-panel";
import { GraphPanel } from "./graph-panel";
import { InfraPanel } from "./infra-panel";
import { GeoMapPanel } from "./geo-map-panel";
import { FreshnessBanner } from "./freshness-banner";
import { FolderPicker } from "./folder-picker";
import { InvestigateForm } from "./investigate-form";
import { ProviderPanel } from "./provider-panel";
import { ScorePanel } from "./score-panel";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/hooks/useAuth";
import { storeLocalResult } from "@/lib/intel/result-store";
import { TARGET_TYPE_LABEL, type InvestigationResult } from "@/lib/intel/types";
import { saveInvestigation } from "@/lib/investigations.functions";

export function ResultView({ result }: { result: InvestigationResult }) {
  const { signedIn } = useAuth();
  const save = useServerFn(saveInvestigation);
  const [saved, setSaved] = useState(Boolean(result.saved));
  const [saving, setSaving] = useState(false);
  const [caseId, setCaseId] = useState<string | null>(
    result.savedCaseId ?? (result.saved ? result.id : null),
  );
  const autoSaved = useRef(false);

  // Signed-in analysts get every investigation saved automatically as a case.
  useEffect(() => {
    if (!signedIn || saved || autoSaved.current) return;
    autoSaved.current = true;
    void onSave(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [signedIn, saved]);

  const onSave = async (auto = false) => {
    setSaving(true);
    try {
      const response = await save({
        data: { result: result as unknown as Record<string, unknown> },
      });
      if (!response.ok) {
        toast.error(response.error);
        return;
      }
      setSaved(true);
      setCaseId(response.id);
      // Remember the case id so a reload of this page never saves a duplicate.
      storeLocalResult({ ...result, saved: true, savedCaseId: response.id });
      if (!auto) toast.success("Investigation saved to your cases.");
    } catch (error) {
      console.error(error);
      toast.error("Could not save this investigation.");
    } finally {
      setSaving(false);
    }
  };

  const related = result.iocs.filter((ioc) => !ioc.primary);

  const onDownloadPdf = async () => {
    try {
      const { downloadPdfReport } = await import("@/lib/intel/pdf-report");
      await downloadPdfReport(result);
    } catch (e) {
      console.error(e);
      toast.error("Could not build the PDF.");
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-5">
        <div className="min-w-0">
          <TerminalLabel>{TARGET_TYPE_LABEL[result.targetType]} investigation</TerminalLabel>
          <h1 className="mt-2 font-mono text-xl break-all text-foreground sm:text-2xl">
            {result.target}
          </h1>
          <p className="mt-2 font-mono text-[0.625rem] tracking-[0.14em] text-muted-foreground uppercase">
            {new Date(result.createdAt).toLocaleString()} · case {result.id.slice(0, 8)}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => void onDownloadPdf()}
            className="font-mono text-xs"
          >
            <Download className="size-3.5" /> Report (PDF)
          </Button>
          {signedIn && caseId && <FolderPicker caseId={caseId} />}
          {signedIn ? (
            <Button
              size="sm"
              onClick={() => void onSave()}
              disabled={saving || saved}
              className="font-mono text-xs"
            >
              <Save className="size-3.5" /> {saved ? "Saved" : saving ? "Saving…" : "Save case"}
            </Button>
          ) : (
            <Button asChild size="sm" variant="outline" className="font-mono text-xs">
              <Link to="/auth">Sign in to save</Link>
            </Button>
          )}
        </div>
      </div>

      <FreshnessBanner result={result} />

      {!signedIn && (
        <p className="border border-border bg-card/50 px-4 py-3 text-xs text-muted-foreground">
          This investigation exists only in your current browser session. Sign in to keep it as a
          case with its evidence, relationships and source statuses.
        </p>
      )}

      <ScorePanel
        score={result.riskScore}
        verdict={result.verdict}
        dimensions={result.dimensions}
      />

      <div className="grid gap-6 lg:grid-cols-2">
        <AiPanel ai={result.ai} status={result.aiStatus} verdict={result.verdict} />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <EvidencePanel evidence={result.evidence} />
        <div className="space-y-6">
          <ActionsPanel recommendations={result.recommendations} />
        </div>
      </div>

      <GeoMapPanel infrastructure={result.infrastructure} />

      <GraphPanel target={result.target} relationships={result.relationships} />

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="space-y-6">
          <InfraPanel
            infrastructure={result.infrastructure}
            domainProfile={result.domainProfile}
            malware={result.malware}
          />
          <ProviderPanel statuses={result.providerStatus} aiStatus={result.aiStatus} />
          {related.length > 0 && (
            <Panel title="Related indicators">
              <ul className="space-y-1.5">
                {related.map((ioc) => (
                  <li key={`${ioc.type}-${ioc.value}`} className="flex items-baseline gap-2">
                    <span className="font-mono text-[0.625rem] tracking-[0.14em] text-primary-dim uppercase">
                      {ioc.type}
                    </span>
                    <Mono className="text-muted-foreground">{ioc.value}</Mono>
                  </li>
                ))}
              </ul>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
