import { fetchJson, nowIso } from "../http.server";
import type { Evidence } from "../types";
import type { Provider, ProviderContext, ProviderOutput } from "./provider.server";

interface RdapVcardEntry {
  roles?: string[];
  vcardArray?: unknown[];
}

interface RdapResponse {
  handle?: string;
  status?: string[];
  events?: { eventAction: string; eventDate: string }[];
  entities?: RdapVcardEntry[];
  nameservers?: { ldhName?: string }[];
}

const SUSPICIOUS_STATUS = ["clienthold", "serverhold", "pendingdelete", "redemptionperiod"];

function entityName(entity: RdapVcardEntry): string | undefined {
  const vcard = entity.vcardArray;
  if (!Array.isArray(vcard) || vcard.length < 2) return undefined;
  const fields = vcard[1];
  if (!Array.isArray(fields)) return undefined;
  for (const field of fields) {
    if (Array.isArray(field) && field[0] === "fn" && typeof field[3] === "string") {
      return field[3];
    }
  }
  return undefined;
}

function eventDate(data: RdapResponse, action: string): string | undefined {
  return data.events?.find((e) => e.eventAction === action)?.eventDate;
}

/** Public RDAP bootstraps, tried in order; either one redirects to the registry that owns the domain. */
const RDAP_ENDPOINTS = [
  "https://rdap-bootstrap.arin.net/bootstrap/domain/",
  "https://rdap.org/domain/",
];

async function lookup(domain: string): Promise<RdapResponse> {
  let lastError: unknown;
  for (const base of RDAP_ENDPOINTS) {
    try {
      return await fetchJson<RdapResponse>(`${base}${encodeURIComponent(domain)}`, {
        timeoutMs: 9000,
        headers: { "user-agent": "SentinelGrid/1.0 security-research" },
      });
    } catch (e) {
      lastError = e;
    }
  }
  throw lastError;
}

export const rdapProvider: Provider = {
  name: "rdap",
  label: "RDAP",
  supports: (t) => t === "domain" || t === "url",
  isConfigured: () => true,
  async run(ctx: ProviderContext): Promise<ProviderOutput> {
    const domain = ctx.domain;
    if (!domain) return {};

    const data = await lookup(domain);

    const registrar = data.entities
      ?.filter((e) => e.roles?.includes("registrar"))
      .map(entityName)
      .find(Boolean);

    const created = eventDate(data, "registration");
    const updated = eventDate(data, "last changed");
    const expires = eventDate(data, "expiration");
    const nameservers = (data.nameservers ?? [])
      .map((n) => n.ldhName?.toLowerCase())
      .filter((n): n is string => Boolean(n));
    const status = data.status ?? [];

    const evidence: Evidence[] = [];
    const observedAt = nowIso();
    let domainAgeDays: number | undefined;

    if (created) {
      const ageMs = Date.now() - new Date(created).getTime();
      if (Number.isFinite(ageMs)) {
        domainAgeDays = Math.max(0, Math.floor(ageMs / 86_400_000));
        const recent = domainAgeDays < 30;
        evidence.push({
          provider: "RDAP",
          label: recent
            ? `Domain registered ${domainAgeDays} day${domainAgeDays === 1 ? "" : "s"} ago`
            : `Domain registered ${created.slice(0, 10)}`,
          detail: recent
            ? "Newly registered domains are frequently used for short-lived malicious infrastructure."
            : registrar
              ? `Registrar: ${registrar}`
              : undefined,
          severity: recent ? "medium" : "info",
          observedAt,
        });
      }
    } else {
      evidence.push({
        provider: "RDAP",
        label: "No registration date published",
        detail: "The registry did not return a creation event for this domain.",
        severity: "info",
        observedAt,
      });
    }

    const flagged = status.filter((s) =>
      SUSPICIOUS_STATUS.includes(s.replace(/\s/g, "").toLowerCase()),
    );
    if (flagged.length > 0) {
      evidence.push({
        provider: "RDAP",
        label: `Registry status: ${flagged.join(", ")}`,
        detail: "The domain is held or pending deletion at the registry.",
        severity: "medium",
        observedAt,
      });
    }

    return {
      evidence,
      infrastructure: {
        registrar,
        createdDate: created,
        updatedDate: updated,
        expiresDate: expires,
        domainStatus: status,
        nameservers,
      },
      signals: {
        infrastructure: {
          domainAgeDays,
          suspiciousDomainStatus: flagged.length > 0 ? flagged : undefined,
        },
      },
    };
  },
};
