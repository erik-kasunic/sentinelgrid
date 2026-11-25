import { RISKY_TLDS } from "./providers/heuristics.server";
import { crossDomainDestination } from "./redirect-chain";
// Deterministic scoring engine. Pure functions over normalized signals: the same
// evidence always produces the same number, and the AI never touches it.

import type { ProviderSignals } from "./providers/provider.server";
import type {
  Dimension,
  MalwareData,
  ProviderStatus,
  RiskScore,
  ScoreLine,
  TargetType,
  Verdict,
} from "./types";

export interface MergedSignals {
  virustotal?: NonNullable<ProviderSignals["virustotal"]>;
  abuseipdb?: NonNullable<ProviderSignals["abuseipdb"]>;
  knownMalicious: { source: string; detail: string }[];
  infrastructure: NonNullable<ProviderSignals["infrastructure"]>;
  heuristics: NonNullable<ProviderSignals["heuristics"]>;
}

export function mergeSignals(all: ProviderSignals[]): MergedSignals {
  const merged: MergedSignals = { knownMalicious: [], infrastructure: {}, heuristics: {} };
  for (const signals of all) {
    if (signals.virustotal) merged.virustotal = signals.virustotal;
    if (signals.abuseipdb) merged.abuseipdb = signals.abuseipdb;
    if (signals.knownMalicious) merged.knownMalicious.push(...signals.knownMalicious);
    if (signals.heuristics) merged.heuristics = { ...merged.heuristics, ...signals.heuristics };
    if (signals.infrastructure) {
      merged.infrastructure = { ...merged.infrastructure, ...signals.infrastructure };
    }
  }
  return merged;
}

const CAP = {
  virustotal: 40,
  abuseipdb: 25,
  known_malicious: 20,
  infrastructure: 10,
  heuristics: 25,
  other: 5,
};

export function bandFor(total: number): Verdict {
  if (total >= 80) return "critical";
  if (total >= 60) return "high";
  if (total >= 40) return "medium";
  if (total >= 20) return "low";
  return "safe";
}

export function computeScore(
  signals: MergedSignals,
  providerStatus: ProviderStatus[],
  threatProviders: string[],
): RiskScore {
  const lines: ScoreLine[] = [];

  // VirusTotal evidence: 0-40
  const vt = signals.virustotal;
  const ageDays = signals.infrastructure.domainAgeDays;
  // Long-established domain (5+ years) with a tiny minority of flags = vendor outliers.
  const veteranDomain = typeof ageDays === "number" && ageDays >= 5 * 365;
  if (vt && vt.total > 0) {
    const outlier =
      veteranDomain &&
      vt.malicious <= 3 &&
      vt.malicious / vt.total < 0.05 &&
      signals.knownMalicious.length === 0;
    // Outliers are down-weighted, never discarded: a compromised old site must still surface.
    const points = Math.min(
      CAP.virustotal,
      outlier ? vt.malicious * 4 + vt.suspicious : vt.malicious * 10 + vt.suspicious * 3,
    );
    lines.push({
      category: "virustotal",
      label: `VirusTotal detections (${vt.malicious} malicious, ${vt.suspicious} suspicious of ${vt.total})${
        outlier && vt.malicious > 0
          ? " — few flags on a long-established domain, down-weighted (verify for compromise)"
          : ""
      }`,
      points,
      max: CAP.virustotal,
    });
  }

  // AbuseIPDB reputation: 0-25
  const abuse = signals.abuseipdb;
  if (abuse) {
    const points = Math.round((Math.min(100, Math.max(0, abuse.confidence)) / 100) * CAP.abuseipdb);
    lines.push({
      category: "abuseipdb",
      label: `AbuseIPDB abuse confidence ${abuse.confidence}% (${abuse.reports} reports)`,
      points,
      max: CAP.abuseipdb,
    });
  }

  // Known malicious indicator: 0-20
  if (signals.knownMalicious.length > 0) {
    // An exact URL confirmed online by a curated threat feed is active malware:
    // it must land in HIGH regardless of how many scanners have caught up.
    const activeExact = signals.knownMalicious.some(
      (k) => /exact URL/i.test(k.source) && /status online/i.test(k.detail),
    );
    const max = activeExact ? 65 : CAP.known_malicious;
    lines.push({
      category: "known_malicious",
      label: `Known malicious indicator — ${signals.knownMalicious
        .map((k) => k.source)
        .join(", ")}${activeExact ? " — active (online) malware URL" : ""}`,
      points: max,
      max,
    });
  }

  // Infrastructure indicators: 0-10
  const infra = signals.infrastructure;
  let infraPoints = 0;
  const infraReasons: string[] = [];
  if (typeof infra.domainAgeDays === "number" && infra.domainAgeDays < 30) {
    infraPoints += 6;
    infraReasons.push(`domain registered ${infra.domainAgeDays}d ago`);
  }
  if (infra.suspiciousDomainStatus?.length) {
    infraPoints += 4;
    infraReasons.push(`registry status ${infra.suspiciousDomainStatus.join("/")}`);
  }
  // Datacenter/CDN hosting is normal (8.8.8.8, Cloudflare, AWS), so it only adds
  // weight when another source already flags the indicator.
  const corroborated =
    (vt?.malicious ?? 0) > 0 ||
    (signals.abuseipdb?.confidence ?? 0) >= 25 ||
    signals.knownMalicious.length > 0;
  if (infra.hostingProvider && corroborated && !(typeof ageDays === "number" && ageDays >= 365)) {
    infraPoints += 3;
    infraReasons.push("hosting/datacenter range");
  }
  if (infraPoints > 0) {
    lines.push({
      category: "infrastructure",
      label: `Infrastructure indicators — ${infraReasons.join(", ")}`,
      points: Math.min(CAP.infrastructure, infraPoints),
      max: CAP.infrastructure,
    });
  }

  // Phishing heuristics: 0-25 (lexical + redirect behaviour)
  const h = signals.heuristics;
  let hPoints = 0;
  const hReasons: string[] = [];
  const youngish = !(typeof ageDays === "number" && ageDays >= 365);
  if (h.riskyTld) {
    hPoints += 6;
    hReasons.push(`high-abuse TLD .${h.riskyTld}`);
  }
  if (h.shortRandomDomain && youngish) {
    hPoints += 3;
    hReasons.push("random-looking domain label");
  }
  if (h.randomPath && youngish) {
    hPoints += 4;
    hReasons.push("random token path");
  }
  if (h.rawIpHost) {
    hPoints += 10;
    hReasons.push("raw IP host");
  }
  if (h.nonStandardPort) {
    hPoints += 8;
    hReasons.push(`non-standard port :${h.nonStandardPort}`);
  }
  if (h.dropperPath && h.rawIpHost) {
    hPoints += 7;
    hReasons.push(`dropper-style path ${h.dropperPath}`);
  }
  if (hPoints > 0) {
    lines.push({
      category: "heuristics",
      label: `Phishing heuristics — ${hReasons.join(", ")}`,
      points: Math.min(CAP.heuristics, hPoints),
      max: CAP.heuristics,
    });
  }

  // Policy risk: open proxy / anonymizer categorised by 2+ vendors (or 1 with a flag).
  const proxyCats = vt?.proxyCategories ?? [];
  if (proxyCats.length >= 2 || (proxyCats.length === 1 && (vt?.malicious ?? 0) > 0)) {
    lines.push({
      category: "heuristics",
      label: `Open web proxy / anonymizer — ${proxyCats.length} vendor categories (security-filter bypass)`,
      points: 36,
      max: 36,
    });
  }

  // Provider-reported redirect chain: 0-15. Only cross-registrable-domain hops
  // to a new, flagged or high-abuse destination count; http->https / www = 0.
  if (h.redirectChain) {
    const dest = crossDomainDestination(h.redirectChain.hops);
    if (dest) {
      const reasons: string[] = [];
      const tld = dest.split(".").pop() ?? "";
      if (RISKY_TLDS.has(tld)) reasons.push(`high-abuse TLD .${tld}`);
      if (signals.knownMalicious.length > 0 || (vt?.malicious ?? 0) > 0)
        reasons.push("flagged by a provider");
      if (reasons.length > 0) {
        lines.push({
          category: "heuristics",
          label: `Redirects to unrelated domain ${dest} (${reasons.join(", ")}) — via ${h.redirectChain.source}`,
          points: Math.min(15, 10 + (reasons.length - 1) * 5),
          max: 15,
        });
      }
    }
  }

  // Other evidence: 0-5
  let otherPoints = 0;
  const otherReasons: string[] = [];
  if (typeof vt?.reputation === "number" && vt.reputation < 0) {
    otherPoints += Math.min(3, Math.ceil(Math.abs(vt.reputation) / 10));
    otherReasons.push(`negative VirusTotal community reputation (${vt.reputation})`);
  }
  if (infra.doesNotResolve) {
    otherPoints += 2;
    otherReasons.push("domain does not resolve");
  }
  if (otherPoints > 0) {
    lines.push({
      category: "other",
      label: `Other evidence — ${otherReasons.join(", ")}`,
      points: Math.min(CAP.other, otherPoints),
      max: CAP.other,
    });
  }

  const total = Math.min(
    100,
    lines.reduce((sum, line) => sum + line.points, 0),
  );

  const relevantThreat = providerStatus.filter((p) => threatProviders.includes(p.provider));
  const answered = relevantThreat.filter((p) => p.status === "completed");
  const dnsAnswered = providerStatus.some((p) => p.provider === "dns" && p.status === "completed");
  const rdapAnswered = providerStatus.some(
    (p) => p.provider === "rdap" && p.status === "completed",
  );
  const establishedDomain =
    dnsAnswered &&
    rdapAnswered &&
    infra.doesNotResolve !== true &&
    typeof infra.domainAgeDays === "number" &&
    infra.domainAgeDays >= 365 &&
    !infra.suspiciousDomainStatus?.length;
  // A source "analysed" the indicator only when it returned real verdict data.
  // "No record" / "not listed" answers are completed lookups, not an analysis.
  const analysed =
    (vt !== undefined && vt.total > 0) ||
    abuse !== undefined ||
    signals.knownMalicious.length > 0 ||
    total > 0;
  const basis = analysed || establishedDomain ? "evaluated" : "insufficient";

  return {
    total,
    max: 100,
    band: bandFor(total),
    basis,
    lines,
    note:
      basis === "insufficient"
        ? relevantThreat.length === 0
          ? "No threat-reputation source covers this indicator type, so maliciousness could not be assessed."
          : answered.length > 0
            ? "The reputation sources answered but have never analysed this indicator, so maliciousness could not be assessed."
            : "No threat-reputation source answered (not configured or failed), so maliciousness could not be assessed."
        : !analysed && establishedDomain
          ? "No risk indicators found. The domain resolves, is at least one year old, and has no suspicious registry status. No reputation source has analysed it."
          : undefined,
  };
}

const INFRA_PROVIDERS = ["dns", "rdap", "geoip", "shodan", "censys"];

export function buildDimensions(
  score: RiskScore,
  signals: MergedSignals,
  targetType: TargetType,
  providerStatus: ProviderStatus[],
  malware?: MalwareData,
): Dimension[] {
  const threat: Dimension = {
    name: "THREAT",
    state: score.basis === "insufficient" ? "unknown" : score.band,
    note:
      score.basis === "insufficient"
        ? "Insufficient evidence to judge maliciousness."
        : score.total === 0
          ? "No malicious evidence found by the sources that answered."
          : `${score.total}/100 from reputation and abuse evidence.`,
  };

  // AbuseIPDB reports the usage type (hosting/datacenter), so it counts as an
  // infrastructure answer too. Otherwise an IP whose GeoIP lookup failed showed
  // UNKNOWN here while the score still added infrastructure points.
  const infraAnswered =
    providerStatus.some((p) => INFRA_PROVIDERS.includes(p.provider) && p.status === "completed") ||
    signals.infrastructure.hostingProvider !== undefined;
  const infraStrong =
    Boolean(signals.infrastructure.suspiciousDomainStatus?.length) ||
    (typeof signals.infrastructure.domainAgeDays === "number" &&
      signals.infrastructure.domainAgeDays < 30);
  const infraScored = score.lines.some((l) => l.category === "infrastructure" && l.points > 0);
  const infrastructure: Dimension = {
    name: "INFRASTRUCTURE",
    state: !infraAnswered ? "unknown" : infraStrong ? "medium" : infraScored ? "low" : "safe",
    note: !infraAnswered
      ? "No infrastructure source answered."
      : infraStrong
        ? "Hosting or registration details include noteworthy signals."
        : infraScored
          ? "Hosted in a datacenter or CDN range, alongside other risk evidence."
          : "Hosting and registration details look ordinary.",
  };

  const malwareDimension: Dimension =
    targetType === "hash"
      ? {
          name: "MALWARE",
          state: malware?.families.length
            ? "critical"
            : providerStatus.some((p) => p.provider === "virustotal" && p.status === "completed")
              ? "safe"
              : "unknown",
          note: malware?.families.length
            ? `Attributed to ${malware.families.join(", ")}.`
            : providerStatus.some((p) => p.provider === "virustotal" && p.status === "completed")
              ? "No malware family attributed to this file."
              : "No malware source answered.",
        }
      : {
          name: "MALWARE",
          state: "not_applicable",
          note: "Only assessed for file hashes.",
        };

  return [threat, infrastructure, malwareDimension];
}
