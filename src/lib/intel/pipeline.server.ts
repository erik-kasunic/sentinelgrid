// Investigation pipeline:
// classify -> normalize -> extract IOCs -> parallel enrich -> correlate ->
// deterministic score -> evidence -> AI assessment -> recommendations.

import { classifyAs, extractIocs, hostOf, isIpLiteral, isPrivateIp } from "./classify";
import {
  buildRecommendations,
  dedupeRelationships,
  relatedIocs,
  sortEvidence,
} from "./correlate.server";
import { runAiAnalysis } from "./ai.server";
import type { ProviderContext, ProviderSignals } from "./providers/provider.server";
import { PROVIDERS, THREAT_PROVIDERS } from "./providers/registry.server";
import { buildDimensions, computeScore, mergeSignals } from "./score.server";
import type {
  Evidence,
  DomainProfileData,
  InfrastructureData,
  InvestigationResult,
  MalwareData,
  ProviderStatus,
  Relationship,
  TargetType,
} from "./types";

export interface RunOptions {
  target: string;
  targetType: TargetType;
  /** Skip the AI step (used when re-scoring stored evidence). */
  withAi?: boolean;
  /** Analyst's own VirusTotal key for this request only (never stored). */
  vtKey?: string | undefined;
}

export async function runInvestigation(options: RunOptions): Promise<InvestigationResult> {
  const { canonical } = classifyAs(options.target, options.targetType);
  const targetType = options.targetType;
  const iocs = extractIocs(canonical, targetType);

  const host =
    targetType === "url" ? hostOf(canonical) : targetType === "domain" ? canonical : null;
  const domain = host && !isIpLiteral(host) ? host : undefined;
  // Pivot: domains/URLs resolve to their primary IP so GeoIP + AbuseIPDB run automatically.
  let ip: string | undefined = targetType === "ip" ? canonical : undefined;
  if (!ip && host && isIpLiteral(host)) ip = host;
  if (!ip && domain) ip = await resolvePrimaryIp(domain);
  if (ip && isPrivateIp(ip)) ip = undefined; // never enrich internal addresses
  const ctx: ProviderContext = {
    target: canonical,
    targetType,
    iocs,
    domain,
    ip,
    vtKey: options.vtKey,
  };
  const degraded: string[] = [];
  const guard = await import("./guard.server");

  const evidence: Evidence[] = [];
  const relationships: Relationship[] = [];
  const providerStatus: ProviderStatus[] = [];
  const signals: ProviderSignals[] = [];
  let infrastructure: InfrastructureData = {};
  let domainProfile: DomainProfileData = {};
  let malware: MalwareData | undefined;

  await Promise.all(
    PROVIDERS.map(async (provider) => {
      if (!provider.supports(targetType)) {
        providerStatus.push({
          provider: provider.name,
          status: "not_applicable",
          message: `Not applicable to ${targetType} indicators`,
        });
        return;
      }
      if (!provider.isConfigured()) {
        providerStatus.push({
          provider: provider.name,
          status: "not_configured",
          message: "API key not configured",
        });
        return;
      }
      const bucket = provider.budgetKey ?? provider.name;
      const usesOwnKey = bucket === "virustotal" && Boolean(options.vtKey);
      if (!usesOwnKey) {
        let budget = await guard.providerHasBudget(bucket);
        if (!budget.ok && budget.reason === "per-minute limit reached") {
          // Back off once for per-minute limits (VirusTotal 4/min) before skipping.
          await new Promise((r) => setTimeout(r, 15_000));
          budget = await guard.providerHasBudget(bucket);
        }
        if (!budget.ok) {
          degraded.push(provider.name);
          providerStatus.push({
            provider: provider.name,
            status: "rate_limited",
            message: `Skipped: ${budget.reason}`,
          });
          return;
        }
        for (let i = 0; i < (provider.cost ?? 1); i++) await guard.recordProviderUse(bucket);
      }
      const started = Date.now();
      try {
        const output = await provider.run(ctx);
        providerStatus.push({
          provider: provider.name,
          status: "completed",
          durationMs: Date.now() - started,
        });
        if (output.evidence) evidence.push(...output.evidence);
        if (output.relationships) {
          const at = new Date().toISOString();
          relationships.push(
            ...output.relationships.map((r) => ({
              ...r,
              source: r.source ?? provider.label,
              observedAt: r.observedAt ?? at,
            })),
          );
        }
        if (output.signals) signals.push(output.signals);
        if (output.infrastructure) {
          infrastructure = { ...infrastructure, ...pruneUndefined(output.infrastructure) };
        }
        if (output.domainProfile) {
          domainProfile = { ...domainProfile, ...pruneUndefined(output.domainProfile) };
        }
        if (output.malware) {
          malware = {
            families: output.malware.families ?? malware?.families ?? [],
            tags: output.malware.tags ?? malware?.tags ?? [],
            fileType: output.malware.fileType ?? malware?.fileType,
            fileSize: output.malware.fileSize ?? malware?.fileSize,
            firstSeen: output.malware.firstSeen ?? malware?.firstSeen,
          };
        }
      } catch (error) {
        // A failing provider never fails the investigation.
        console.error(`provider ${provider.name} failed`, error);
        providerStatus.push({
          provider: provider.name,
          status: "failed",
          message: error instanceof Error ? error.message : "Unknown provider error",
          durationMs: Date.now() - started,
        });
      }
    }),
  );

  const order = PROVIDERS.map((p) => p.name);
  providerStatus.sort((a, b) => order.indexOf(a.provider) - order.indexOf(b.provider));

  const merged = mergeSignals(signals);
  const riskScore = computeScore(merged, providerStatus, THREAT_PROVIDERS);
  const graph = dedupeRelationships(relationships);
  const related = relatedIocs(graph, iocs);
  const dimensions = buildDimensions(riskScore, merged, targetType, providerStatus, malware);

  const result: InvestigationResult = {
    id: crypto.randomUUID(),
    target: canonical,
    targetType,
    createdAt: new Date().toISOString(),
    iocs: [...iocs, ...related],
    riskScore,
    verdict: riskScore.basis === "insufficient" ? "unknown" : riskScore.band,
    verdictBasis: riskScore.basis,
    dimensions,
    evidence: sortEvidence(evidence),
    relationships: graph,
    infrastructure: Object.keys(infrastructure).length > 0 ? infrastructure : undefined,
    domainProfile: Object.keys(domainProfile).length > 0 ? domainProfile : undefined,
    malware,
    recommendations: buildRecommendations(riskScore, merged, targetType, canonical, related),
    providerStatus,
    degradedProviders: degraded.length ? degraded : undefined,
    ai: null,
    aiStatus: { provider: "ai_analyst", status: "not_configured" },
    saved: false,
    title: `${targetType.toUpperCase()} · ${canonical}`,
  };

  if (options.withAi !== false) {
    const ai = await runAiAnalysis(result);
    result.ai = ai.assessment;
    result.aiStatus = { provider: "ai_analyst", status: ai.status, message: ai.message };
  }

  return result;
}

async function resolvePrimaryIp(domain: string): Promise<string | undefined> {
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
      {
        headers: { accept: "application/dns-json" },
        signal: AbortSignal.timeout(4000),
      },
    );
    if (!res.ok) return undefined;
    const data = (await res.json()) as { Answer?: { type: number; data: string }[] };
    return data.Answer?.find((a) => a.type === 1)?.data;
  } catch {
    return undefined;
  }
}

function pruneUndefined<T extends object>(input: T): Partial<T> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    if (value !== undefined && value !== null) out[key] = value;
  }
  return out as Partial<T>;
}
