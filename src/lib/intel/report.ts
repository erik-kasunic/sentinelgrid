import { providerName, PROVIDER_STATUS_LABEL } from "./provider-meta";
import { TARGET_TYPE_LABEL, VERDICT_LABEL, type InvestigationResult } from "./types";

/** Deterministic markdown report built only from evidence present in the result. */
export function buildReport(result: InvestigationResult): string {
  const lines: string[] = [];
  const insufficient = result.verdictBasis === "insufficient";

  lines.push(`# SentinelGrid investigation report`);
  lines.push("");
  lines.push(`- Target: \`${result.target}\``);
  lines.push(`- Type: ${TARGET_TYPE_LABEL[result.targetType]}`);
  lines.push(`- Verdict: ${VERDICT_LABEL[result.verdict]}`);
  lines.push(
    `- Risk score: ${insufficient ? "not assessed (insufficient evidence)" : `${result.riskScore.total}/100`}`,
  );
  lines.push(`- Generated: ${new Date(result.createdAt).toISOString()}`);
  lines.push("");

  lines.push("## Score breakdown");
  for (const line of result.riskScore.lines) {
    lines.push(`- ${line.label}: +${line.points} of ${line.max}`);
  }
  if (result.riskScore.note) lines.push(`- Note: ${result.riskScore.note}`);
  lines.push("");

  lines.push("## Risk dimensions");
  for (const dimension of result.dimensions) {
    const state =
      dimension.state === "not_applicable" ? "NOT APPLICABLE" : VERDICT_LABEL[dimension.state];
    lines.push(`- ${dimension.name}: ${state} — ${dimension.note}`);
  }
  lines.push("");

  lines.push("## Indicators");
  for (const ioc of result.iocs) {
    lines.push(`- \`${ioc.value}\` (${ioc.type}${ioc.primary ? ", primary" : ""})`);
  }
  lines.push("");

  lines.push("## Evidence");
  if (result.evidence.length === 0) {
    lines.push("- No evidence returned by any source.");
  } else {
    for (const item of result.evidence) {
      const bits = [`[${item.severity.toUpperCase()}]`, providerName(item.provider), item.label];
      lines.push(`- ${bits.join(" · ")}${item.detail ? ` — ${item.detail}` : ""}`);
    }
  }
  lines.push("");

  if (result.relationships.length > 0) {
    lines.push("## Relationships");
    for (const rel of result.relationships) {
      lines.push(`- ${rel.fromValue} → ${rel.kind} → ${rel.toValue}`);
    }
    lines.push("");
  }

  if (result.domainProfile) {
    const profile = result.domainProfile;
    lines.push("## Domain profile");
    if (profile.organization) lines.push(`- Organization: ${profile.organization}`);
    if (profile.emailPattern) lines.push(`- Email pattern: ${profile.emailPattern}`);
    if (profile.emailCount !== undefined)
      lines.push(`- Indexed email records: ${profile.emailCount}`);
    if (profile.personalEmailCount !== undefined || profile.genericEmailCount !== undefined) {
      lines.push(
        `- Personal / generic counts: ${profile.personalEmailCount ?? 0} / ${profile.genericEmailCount ?? 0}`,
      );
    }
    if (profile.acceptAll !== undefined)
      lines.push(`- Accept-all domain: ${profile.acceptAll ? "yes" : "no"}`);
    if (profile.disposable !== undefined)
      lines.push(`- Disposable domain: ${profile.disposable ? "yes" : "no"}`);
    if (profile.webmail !== undefined)
      lines.push(`- Webmail domain: ${profile.webmail ? "yes" : "no"}`);
    lines.push("");
  }

  lines.push("## Intelligence source status");
  for (const status of [...result.providerStatus, result.aiStatus]) {
    lines.push(
      `- ${status.provider === "ai" ? "AI analyst" : providerName(status.provider)}: ${PROVIDER_STATUS_LABEL[status.status]}${status.message ? ` — ${status.message}` : ""}`,
    );
  }
  lines.push("");

  if (result.ai) {
    lines.push("## AI SOC assessment");
    lines.push(result.ai.summary);
    lines.push("");
    lines.push(result.ai.explanation);
    lines.push("");
    lines.push(`Recommended action: ${result.ai.recommended_action}`);
    if (result.ai.uncertainties.length > 0) {
      lines.push("");
      lines.push("Uncertainties:");
      for (const item of result.ai.uncertainties) lines.push(`- ${item}`);
    }
    lines.push("");
  }

  lines.push("## Recommended actions");
  for (const rec of result.recommendations) {
    lines.push(`${rec.step}. ${rec.text}${rec.rationale ? ` (${rec.rationale})` : ""}`);
  }
  lines.push("");
  lines.push(
    "Scoring is deterministic and derived only from the evidence listed above. UNKNOWN indicates insufficient evidence, not safety.",
  );

  return lines.join("\n");
}

export function downloadReport(result: InvestigationResult): void {
  const blob = new Blob([buildReport(result)], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `sentinelgrid-${result.targetType}-${result.target.replace(/[^a-z0-9.-]/gi, "_").slice(0, 60)}.md`;
  anchor.click();
  URL.revokeObjectURL(url);
}
