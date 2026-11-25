import { fetchJson, nowIso } from "../http.server";
import type { Evidence } from "../types";
import type { Provider, ProviderContext, ProviderOutput } from "./provider.server";

interface HunterDomainData {
  domain?: string;
  organization?: string | null;
  pattern?: string | null;
  disposable?: boolean;
  webmail?: boolean;
  accept_all?: boolean | null;
}

interface HunterDomainResponse {
  data?: HunterDomainData;
}

interface HunterCountData {
  total?: number;
  personal_emails?: number;
  generic_emails?: number;
}

interface HunterCountResponse {
  data?: HunterCountData;
}

export const hunterProvider: Provider = {
  name: "hunter",
  label: "Hunter.io",
  supports: (targetType) => targetType === "domain" || targetType === "url",
  isConfigured: () => Boolean(process.env["HUNTER_API_KEY"]),
  async run(ctx: ProviderContext): Promise<ProviderOutput> {
    const key = process.env["HUNTER_API_KEY"];
    if (!key) throw new Error("HUNTER_API_KEY is not set");
    if (!ctx.domain) return {};

    const headers = { "X-API-KEY": key };
    const domain = encodeURIComponent(ctx.domain);
    const [domainResult, countResult] = await Promise.allSettled([
      fetchJson<HunterDomainResponse>(
        `https://api.hunter.io/v2/domain-search?domain=${domain}&limit=1`,
        { headers },
      ),
      fetchJson<HunterCountResponse>(`https://api.hunter.io/v2/email-count?domain=${domain}`, {
        headers,
      }),
    ]);

    if (domainResult.status === "rejected" && countResult.status === "rejected") {
      throw domainResult.reason instanceof Error
        ? domainResult.reason
        : new Error("Hunter lookup failed");
    }

    // Hunter's individual email records are intentionally ignored. Only aggregate,
    // domain-level metadata enters the normalized investigation result.
    const domainData = domainResult.status === "fulfilled" ? domainResult.value.data : undefined;
    const countData = countResult.status === "fulfilled" ? countResult.value.data : undefined;
    const evidence: Evidence[] = [];
    const observedAt = nowIso();

    if (domainData?.organization) {
      evidence.push({
        provider: "Hunter.io",
        label: `Organization identified: ${domainData.organization}`,
        detail: "Domain-level organization attribution from Hunter.io.",
        severity: "info",
        sourceUrl: `https://hunter.io/search/${ctx.domain}`,
        observedAt,
      });
    }

    if (typeof countData?.total === "number") {
      evidence.push({
        provider: "Hunter.io",
        label: `${countData.total.toLocaleString()} public email record${countData.total === 1 ? "" : "s"} indexed`,
        detail:
          "Aggregate count only; SentinelGrid does not collect or display individual email addresses.",
        severity: "info",
        sourceUrl: `https://hunter.io/search/${ctx.domain}`,
        observedAt,
      });
    }

    if (evidence.length === 0) {
      evidence.push({
        provider: "Hunter.io",
        label: "No organization profile found",
        detail: "Hunter.io returned no domain-level organization or email footprint.",
        severity: "info",
        sourceUrl: `https://hunter.io/search/${ctx.domain}`,
        observedAt,
      });
    }

    return {
      evidence,
      domainProfile: {
        organization: domainData?.organization ?? undefined,
        emailPattern: domainData?.pattern ?? undefined,
        emailCount: countData?.total,
        personalEmailCount: countData?.personal_emails,
        genericEmailCount: countData?.generic_emails,
        acceptAll: domainData?.accept_all ?? undefined,
        disposable: domainData?.disposable,
        webmail: domainData?.webmail,
      },
    };
  },
};
