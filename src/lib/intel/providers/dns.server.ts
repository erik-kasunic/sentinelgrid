import { fetchJson, nowIso } from "../http.server";
import type { Evidence, Relationship } from "../types";
import type { Provider, ProviderContext, ProviderOutput } from "./provider.server";

export interface DohAnswer {
  name: string;
  type: number;
  data: string;
}

interface DohResponse {
  Status: number;
  Answer?: DohAnswer[];
}

const RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"] as const;
type RecordType = (typeof RECORD_TYPES)[number];

// DNS wire type codes (RFC 1035 / RFC 3596).
const TYPE_CODE: Record<RecordType, number> = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28 };

/** Strip the root dot DNS returns on host names, so "a.com." and "a.com" are the same node. */
export const stripRootDot = (host: string) => host.replace(/\.$/, "");

/**
 * Keep only answers of the requested type. A resolver follows CNAMEs, so a query for A on an
 * alias also returns the CNAME record itself; without this filter the alias target would be
 * shown as an A/MX/NS/TXT record and treated as an IP.
 */
export function parseAnswers(type: RecordType, answers: DohAnswer[] | undefined): string[] {
  if (!answers) return [];
  return answers
    .filter((a) => a.type === TYPE_CODE[type])
    .map((a) => a.data.replace(/^"|"$/g, ""))
    .map((v) => (type === "TXT" ? v : stripRootDot(v)))
    .filter(Boolean);
}

async function resolve(name: string, type: RecordType): Promise<string[]> {
  const data = await fetchJson<DohResponse>(
    `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`,
    { timeoutMs: 6000 },
  );
  return parseAnswers(type, data.Answer);
}

export const dnsProvider: Provider = {
  name: "dns",
  label: "DNS",
  supports: (t) => t === "domain" || t === "url",
  isConfigured: () => true,
  async run(ctx: ProviderContext): Promise<ProviderOutput> {
    const domain = ctx.domain;
    if (!domain) return {};

    const settled = await Promise.allSettled(RECORD_TYPES.map((t) => resolve(domain, t)));
    const records: { type: string; value: string }[] = [];
    settled.forEach((outcome, index) => {
      if (outcome.status !== "fulfilled") return;
      const type = RECORD_TYPES[index]!;
      for (const value of outcome.value) records.push({ type, value });
    });

    if (settled.every((s) => s.status === "rejected")) {
      throw new Error("No DNS record type could be resolved");
    }

    const relationships: Relationship[] = [];
    const evidence: Evidence[] = [];
    const observedAt = nowIso();

    for (const record of records) {
      if (record.type === "A" || record.type === "AAAA") {
        relationships.push({
          fromValue: domain,
          fromType: "domain",
          toValue: record.value,
          toType: "ip",
          kind: "resolves_to",
        });
      }
      if (record.type === "CNAME" || record.type === "MX" || record.type === "NS") {
        const host = stripRootDot(record.value.replace(/^\d+\s+/, ""));
        if (host) {
          relationships.push({
            fromValue: domain,
            fromType: "domain",
            toValue: host,
            toType: "domain",
            kind: record.type === "CNAME" ? "related_to" : "associated_with",
          });
        }
      }
    }

    const addresses = records.filter((r) => r.type === "A" || r.type === "AAAA");
    if (addresses.length > 0) {
      evidence.push({
        provider: "DNS",
        label: `Resolves to ${addresses.length} address${addresses.length === 1 ? "" : "es"}`,
        detail: addresses.map((a) => a.value).join(", "),
        severity: "info",
        observedAt,
      });
    } else {
      evidence.push({
        provider: "DNS",
        label: "Domain does not currently resolve",
        detail: "No A or AAAA records were returned.",
        severity: "low",
        observedAt,
      });
    }

    if (ctx.targetType === "url") {
      relationships.push({
        fromValue: ctx.target,
        fromType: "url",
        toValue: domain,
        toType: "domain",
        kind: "hosted_on",
      });
    }

    return {
      evidence,
      relationships,
      infrastructure: { dnsRecords: records },
      signals: { infrastructure: { doesNotResolve: addresses.length === 0 } },
    };
  },
};
