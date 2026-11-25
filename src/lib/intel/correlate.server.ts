// Correlation engine: turns per-provider output into one deduplicated entity
// graph and evidence-driven recommendations.

import type { MergedSignals } from "./score.server";
import type { Evidence, Ioc, Recommendation, Relationship, RiskScore, TargetType } from "./types";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;

export function dedupeRelationships(relationships: Relationship[]): Relationship[] {
  // Same link from several providers: keep one edge, list every source.
  const byKey = new Map<string, Relationship>();
  for (const rel of relationships) {
    if (rel.fromValue === rel.toValue) continue;
    const key = `${rel.fromValue}|${rel.kind}|${rel.toValue}`;
    const prev = byKey.get(key);
    if (!prev) {
      byKey.set(key, { ...rel });
      continue;
    }
    const sources = new Set([
      ...(prev.source?.split(", ") ?? []),
      ...(rel.source?.split(", ") ?? []),
    ]);
    prev.source = [...sources].join(", ") || undefined;
    prev.flagged = prev.flagged || rel.flagged;
  }
  return [...byKey.values()];
}

export function sortEvidence(evidence: Evidence[]): Evidence[] {
  return [...evidence].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

/** Related indicators worth pivoting into, derived from the relationship graph. */
export function relatedIocs(relationships: Relationship[], iocs: Ioc[]): Ioc[] {
  const known = new Set(iocs.map((i) => i.value));
  const out: Ioc[] = [];
  for (const rel of relationships) {
    const type = rel.toType;
    if (type !== "ip" && type !== "domain" && type !== "url" && type !== "hash") continue;
    if (known.has(rel.toValue)) continue;
    known.add(rel.toValue);
    out.push({ value: rel.toValue, type: type as TargetType, primary: false });
  }
  return out;
}

export function buildRecommendations(
  score: RiskScore,
  signals: MergedSignals,
  targetType: TargetType,
  target: string,
  related: Ioc[],
): Recommendation[] {
  const items: { text: string; rationale?: string | undefined }[] = [];

  if (score.basis === "insufficient") {
    items.push({
      text: `Treat ${target} as unverified rather than safe.`,
      rationale: score.note,
    });
    items.push({
      text: "Configure the reputation sources so this indicator can be scored.",
      rationale: "No threat-reputation source answered for this investigation.",
    });
  }

  items.push({
    text: `Search your firewall, proxy, DNS and SIEM logs for ${target}.`,
    rationale: "Establishes whether the indicator has been seen in your environment at all.",
  });

  if (score.total >= 40 || signals.knownMalicious.length > 0) {
    items.push({
      text: "Identify every endpoint or user that communicated with this indicator.",
      rationale: "Evidence of malicious activity means exposure needs to be scoped.",
    });
  }

  if (signals.knownMalicious.length > 0) {
    items.push({
      text: "Block the indicator at the perimeter and on endpoint protection.",
      rationale: `Named as malicious by ${signals.knownMalicious.map((k) => k.source).join(", ")}.`,
    });
  } else if (score.total >= 60) {
    items.push({
      text: "Block or sinkhole the indicator pending confirmation.",
      rationale: `Deterministic score ${score.total}/100 places this in the high band.`,
    });
  }

  if (targetType === "hash") {
    items.push({
      text: "Hunt for the file hash across endpoint telemetry and email attachments.",
      rationale: "File indicators usually arrive by download or attachment.",
    });
  }

  if (related.length > 0) {
    items.push({
      text: `Pivot into the ${related.length} related indicator${related.length === 1 ? "" : "s"} discovered here.`,
      rationale: related
        .slice(0, 4)
        .map((r) => r.value)
        .join(", "),
    });
  }

  if (score.basis === "evaluated" && score.total < 20) {
    items.push({
      text: "Close the case as low risk unless local telemetry contradicts these findings.",
      rationale: "The sources that answered found no malicious evidence.",
    });
  }

  return items.map((item, index) => ({ step: index + 1, ...item }));
}
