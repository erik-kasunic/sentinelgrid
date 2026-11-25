// VirusTotal relationship pivots (passive): domains seen on the same IP and
// files that communicate with it. Shares the VirusTotal quota.

import { fetchJson, nowIso, ProviderHttpError } from "../http.server";
import type { Relationship } from "../types";
import type { Provider, ProviderContext, ProviderOutput } from "./provider.server";

const VT = "https://www.virustotal.com/api/v3";
const MAX_DOMAINS = 8;
const MAX_FILES = 5;

interface VtList<A> {
  data?: { id: string; attributes?: A }[];
}
interface Resolution {
  host_name?: string;
}
interface FileAttrs {
  last_analysis_stats?: { malicious?: number };
}

async function list<A>(url: string, key: string): Promise<VtList<A>> {
  try {
    return await fetchJson<VtList<A>>(url, { headers: { "x-apikey": key } });
  } catch (error) {
    // 403/404 = relationship unavailable on this key or no data.
    if (error instanceof ProviderHttpError && (error.status === 403 || error.status === 404))
      return {};
    throw error;
  }
}

export const vtRelationsProvider: Provider = {
  name: "vt_relations",
  label: "VirusTotal relations",
  budgetKey: "virustotal",
  cost: 2,
  supports: () => true,
  isConfigured: () => Boolean(process.env["VIRUSTOTAL_API_KEY"]),
  async run(ctx: ProviderContext): Promise<ProviderOutput> {
    const key = ctx.vtKey ?? process.env["VIRUSTOTAL_API_KEY"];
    if (!key) throw new Error("VIRUSTOTAL_API_KEY is not set");
    const rels: Relationship[] = [];

    if (ctx.targetType === "hash") {
      const h = encodeURIComponent(ctx.target);
      const [domains, ips] = await Promise.all([
        list<object>(`${VT}/files/${h}/contacted_domains?limit=${MAX_DOMAINS}`, key),
        list<object>(`${VT}/files/${h}/contacted_ips?limit=${MAX_DOMAINS}`, key),
      ]);
      for (const d of domains.data ?? []) {
        rels.push({
          fromValue: ctx.target,
          fromType: "hash",
          toValue: d.id,
          toType: "domain",
          kind: "associated_with",
        });
      }
      for (const ip of ips.data ?? []) {
        rels.push({
          fromValue: ctx.target,
          fromType: "hash",
          toValue: ip.id,
          toType: "ip",
          kind: "associated_with",
        });
      }
    } else if (ctx.ip) {
      const ip = ctx.ip;
      const [res, files] = await Promise.all([
        list<Resolution>(
          `${VT}/ip_addresses/${encodeURIComponent(ip)}/resolutions?limit=${MAX_DOMAINS + 2}`,
          key,
        ),
        list<FileAttrs>(
          `${VT}/ip_addresses/${encodeURIComponent(ip)}/communicating_files?limit=${MAX_FILES}`,
          key,
        ),
      ]);
      const own = ctx.domain?.toLowerCase();
      const hosts = new Set<string>();
      for (const r of res.data ?? []) {
        const h = r.attributes?.host_name?.toLowerCase();
        if (h && h !== own) hosts.add(h);
      }
      for (const h of [...hosts].slice(0, MAX_DOMAINS)) {
        rels.push({
          fromValue: ip,
          fromType: "ip",
          toValue: h,
          toType: "domain",
          kind: "hosted_on",
        });
      }
      for (const f of (files.data ?? []).slice(0, MAX_FILES)) {
        const malicious = f.attributes?.last_analysis_stats?.malicious ?? 0;
        rels.push({
          fromValue: ip,
          fromType: "ip",
          toValue: f.id,
          toType: "hash",
          kind: "associated_with",
          flagged: malicious > 0,
        });
      }
    }

    const cohosted = rels.filter((r) => r.toType === "domain").length;
    const hashes = rels.filter((r) => r.toType === "hash").length;
    return {
      relationships: rels,
      evidence: [
        {
          provider: "VirusTotal",
          label:
            rels.length === 0
              ? "No related domains, IPs or files recorded"
              : `Relations: ${cohosted} domain${cohosted === 1 ? "" : "s"}, ${hashes} file${hashes === 1 ? "" : "s"}`,
          detail: "Passive pivot from VirusTotal's resolution and file history.",
          severity: "info",
          observedAt: nowIso(),
        },
      ],
    };
  },
};
