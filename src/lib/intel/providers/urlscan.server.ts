import { fetchJson, nowIso } from "../http.server";
import type { Evidence, Relationship } from "../types";
import type { Provider, ProviderContext, ProviderOutput } from "./provider.server";

interface UrlscanHit {
  task?: { url?: string; time?: string; visibility?: string };
  page?: { url?: string; domain?: string; ip?: string; server?: string; country?: string };
  verdicts?: { score?: number; malicious?: boolean };
  result?: string;
  screenshot?: string;
  _id?: string;
}

interface UrlscanSearchResponse {
  results?: UrlscanHit[];
  total?: number;
}

export const urlscanProvider: Provider = {
  name: "urlscan",
  label: "urlscan.io",
  supports: (t) => t === "url" || t === "domain",
  isConfigured: () => Boolean(process.env["URLSCAN_API_KEY"]),
  async run(ctx: ProviderContext): Promise<ProviderOutput> {
    const key = process.env["URLSCAN_API_KEY"];
    if (!key) throw new Error("URLSCAN_API_KEY is not set");
    const domain = ctx.domain;
    if (!domain) return {};

    const query = ctx.targetType === "url" ? `page.url:"${ctx.target}"` : `page.domain:"${domain}"`;
    const search = await fetchJson<UrlscanSearchResponse>(
      `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(query)}&size=10`,
      { headers: { "API-Key": key }, timeoutMs: 15000 },
    );

    const hits = search.results ?? [];
    const observedAt = nowIso();
    const evidence: Evidence[] = [];
    const relationships: Relationship[] = [];

    if (hits.length === 0) {
      return {
        evidence: [
          {
            provider: "urlscan.io",
            label: "No historical scans found",
            detail: "urlscan.io holds no prior scan for this target — no malicious evidence found.",
            severity: "info",
            sourceUrl: `https://urlscan.io/search/#${encodeURIComponent(query)}`,
            observedAt,
          },
        ],
      };
    }

    const malicious = hits.filter((h) => h.verdicts?.malicious === true);
    const latest = hits[0]!;

    evidence.push({
      provider: "urlscan.io",
      label: `${hits.length} historical scan${hits.length === 1 ? "" : "s"} on record`,
      detail: latest.task?.time
        ? `Most recent scan ${latest.task.time.slice(0, 10)}${
            latest.page?.server ? ` · server ${latest.page.server}` : ""
          }`
        : undefined,
      severity: "info",
      sourceUrl: latest.result,
      observedAt,
    });

    if (malicious.length > 0) {
      evidence.push({
        provider: "urlscan.io",
        label: `${malicious.length} scan${malicious.length === 1 ? "" : "s"} verdicted malicious`,
        detail: malicious
          .map((h) => h.page?.url)
          .filter(Boolean)
          .slice(0, 3)
          .join(", "),
        severity: "critical",
        sourceUrl: malicious[0]?.result,
        observedAt,
      });
    }

    const seenIps = new Set<string>();
    for (const hit of hits) {
      const ip = hit.page?.ip;
      if (ip && !seenIps.has(ip)) {
        seenIps.add(ip);
        relationships.push({
          fromValue: domain,
          fromType: "domain",
          toValue: ip,
          toType: "ip",
          kind: "hosted_on",
        });
      }
      const finalUrl = hit.page?.url;
      const requested = hit.task?.url;
      if (finalUrl && requested && finalUrl !== requested) {
        relationships.push({
          fromValue: requested,
          fromType: "url",
          toValue: finalUrl,
          toType: "url",
          kind: "redirects_to",
        });
      }
    }

    // Passive redirect data from the latest public scan (never fetched by us).
    let redirectChain: { source: string; hops: string[] } | undefined;
    const reqUrl = latest.task?.url;
    const finUrl = latest.page?.url;
    if (ctx.targetType === "url" && reqUrl && finUrl && reqUrl !== finUrl) {
      redirectChain = { source: "urlscan.io", hops: [reqUrl, finUrl] };
      evidence.push({
        provider: "urlscan.io",
        label: "Redirect recorded in latest scan",
        detail: `${reqUrl} → ${finUrl}`,
        severity: "info",
        sourceUrl: latest.result,
        observedAt,
      });
    } else if (ctx.targetType === "url") {
      evidence.push({
        provider: "urlscan.io",
        label: "No redirect data",
        detail: "The latest urlscan.io scan recorded no redirect.",
        severity: "info",
        sourceUrl: latest.result,
        observedAt,
      });
    }

    return {
      evidence,
      relationships,
      signals: {
        ...(redirectChain ? { heuristics: { redirectChain } } : {}),
        knownMalicious: malicious.length
          ? [
              {
                source: "urlscan.io",
                detail: `${malicious.length} scan(s) verdicted malicious`,
              },
            ]
          : undefined,
      },
    };
  },
};
