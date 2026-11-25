// abuse.ch URLhaus: live malware / phishing URL database (free Auth-Key).

import { fetchJson, nowIso } from "../http.server";
import type { Evidence } from "../types";
import type { Provider, ProviderContext, ProviderOutput } from "./provider.server";

interface UrlhausResp {
  query_status: string;
  threat?: string;
  url_status?: string;
  urls?: { url: string; url_status: string; threat: string; tags?: string[] | null }[];
  tags?: string[] | null;
  urlhaus_reference?: string;
}

async function query(kind: "url" | "host", value: string, key: string) {
  return fetchJson<UrlhausResp>(`https://urlhaus-api.abuse.ch/v1/${kind}/`, {
    method: "POST",
    headers: { "Auth-Key": key, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ [kind]: value }).toString(),
    timeoutMs: 8000,
  });
}

export const urlhausProvider: Provider = {
  name: "urlhaus",
  label: "abuse.ch URLhaus",
  supports: (t) => t === "url" || t === "domain" || t === "ip",
  isConfigured: () => Boolean(process.env["URLHAUS_AUTH_KEY"]),
  async run(ctx: ProviderContext): Promise<ProviderOutput> {
    const key = process.env["URLHAUS_AUTH_KEY"]!;
    const evidence: Evidence[] = [];
    const known: { source: string; detail: string }[] = [];

    if (ctx.targetType === "url") {
      const r = await query("url", ctx.target, key);
      if (r.query_status === "ok") {
        const detail = `${r.threat ?? "malware"} · status ${r.url_status ?? "unknown"}`;
        known.push({ source: "URLhaus (exact URL)", detail });
        evidence.push({
          provider: "URLhaus",
          label: "URL listed in URLhaus",
          detail,
          severity: "critical",
          sourceUrl: r.urlhaus_reference,
          observedAt: nowIso(),
        });
      }
    }
    const host = ctx.targetType === "ip" ? ctx.target : ctx.domain;
    if (host) {
      const r = await query("host", host, key);
      if (r.query_status === "ok" && r.urls?.length) {
        const online = r.urls.filter((u) => u.url_status === "online").length;
        const detail = `${r.urls.length} malicious URLs on host (${online} online) · ${[...new Set(r.urls.map((u) => u.threat))].join(", ")}`;
        known.push({ source: "URLhaus (host)", detail });
        evidence.push({
          provider: "URLhaus",
          label: `Host ${host} listed in URLhaus`,
          detail,
          severity: online > 0 ? "critical" : "high",
          sourceUrl: r.urlhaus_reference,
          observedAt: nowIso(),
        });
      }
    }
    if (evidence.length === 0) {
      evidence.push({
        provider: "URLhaus",
        label: "Not listed in URLhaus",
        severity: "info",
        observedAt: nowIso(),
      });
    }
    return { evidence, signals: known.length ? { knownMalicious: known } : {} };
  },
};
