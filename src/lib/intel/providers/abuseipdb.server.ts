import { fetchJson, nowIso } from "../http.server";
import type { Evidence, Severity } from "../types";
import type { Provider, ProviderContext, ProviderOutput } from "./provider.server";

interface AbuseResponse {
  data?: {
    abuseConfidenceScore?: number;
    totalReports?: number;
    numDistinctUsers?: number;
    lastReportedAt?: string | null;
    countryCode?: string | null;
    isp?: string | null;
    usageType?: string | null;
    domain?: string | null;
    isTor?: boolean;
  };
}

const HOSTING_USAGE = ["data center", "datacenter", "hosting", "content delivery network"];

export const abuseipdbProvider: Provider = {
  name: "abuseipdb",
  label: "AbuseIPDB",
  supports: (t) => t === "ip" || t === "domain" || t === "url",
  isConfigured: () => Boolean(process.env["ABUSEIPDB_API_KEY"]),
  async run(ctx: ProviderContext): Promise<ProviderOutput> {
    const key = process.env["ABUSEIPDB_API_KEY"];
    if (!key) throw new Error("ABUSEIPDB_API_KEY is not set");
    const ip = ctx.ip;
    if (!ip) return {};

    const response = await fetchJson<AbuseResponse>(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      { headers: { Key: key } },
    );

    const data = response.data ?? {};
    const confidence = data.abuseConfidenceScore ?? 0;
    const reports = data.totalReports ?? 0;
    const usageType = data.usageType ?? undefined;
    const observedAt = nowIso();
    const sourceUrl = `https://www.abuseipdb.com/check/${ip}`;

    const severity: Severity =
      confidence >= 75
        ? "critical"
        : confidence >= 40
          ? "high"
          : confidence >= 10
            ? "medium"
            : "info";

    const evidence: Evidence[] = [
      {
        provider: "AbuseIPDB",
        label:
          confidence > 0 || reports > 0
            ? `Abuse confidence ${confidence}% from ${reports} report${reports === 1 ? "" : "s"}`
            : "No abuse reports in the last 90 days — no malicious evidence found",
        detail: data.lastReportedAt
          ? `Last reported ${data.lastReportedAt.slice(0, 10)}${
              data.numDistinctUsers ? ` by ${data.numDistinctUsers} distinct reporters` : ""
            }`
          : undefined,
        severity,
        confidence,
        sourceUrl,
        observedAt,
      },
    ];

    if (usageType) {
      evidence.push({
        provider: "AbuseIPDB",
        label: `Usage type: ${usageType}`,
        detail: data.isp ? `ISP: ${data.isp}` : undefined,
        severity: "info",
        sourceUrl,
        observedAt,
      });
    }

    if (data.isTor) {
      evidence.push({
        provider: "AbuseIPDB",
        label: "Address is a known Tor exit node",
        severity: "medium",
        sourceUrl,
        observedAt,
      });
    }

    const hosting = usageType
      ? HOSTING_USAGE.some((needle) => usageType.toLowerCase().includes(needle))
      : undefined;

    return {
      evidence,
      infrastructure: {
        isp: data.isp ?? undefined,
        country: data.countryCode ?? undefined,
        usageType,
      },
      signals: {
        abuseipdb: { confidence, reports, usageType },
        infrastructure: { hostingProvider: hosting },
      },
    };
  },
};
