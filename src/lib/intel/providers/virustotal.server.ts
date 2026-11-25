import { fetchJson, nowIso, ProviderHttpError } from "../http.server";
import type { Evidence, Severity } from "../types";
import type { Provider, ProviderContext, ProviderOutput } from "./provider.server";

interface VtStats {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  timeout?: number;
}

interface VtAttributes {
  redirection_chain?: string[];
  last_final_url?: string;
  last_analysis_stats?: VtStats;
  last_analysis_date?: number;
  reputation?: number;
  popular_threat_classification?: {
    suggested_threat_label?: string;
    popular_threat_name?: { value: string }[];
  };
  type_description?: string;
  size?: number;
  first_submission_date?: number;
  tags?: string[];
  meaningful_name?: string;
  categories?: Record<string, string>;
}

interface VtResponse {
  data?: { attributes?: VtAttributes };
}

/** VirusTotal URL ids are unpadded base64url of the URL itself. */
function urlId(url: string): string {
  const bytes = new TextEncoder().encode(url);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function endpointFor(ctx: ProviderContext): string | null {
  switch (ctx.targetType) {
    case "ip":
      return `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ctx.target)}`;
    case "domain":
      return `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ctx.target)}`;
    case "url":
      return `https://www.virustotal.com/api/v3/urls/${urlId(ctx.target)}`;
    case "hash":
      return `https://www.virustotal.com/api/v3/files/${encodeURIComponent(ctx.target)}`;
    default:
      return null;
  }
}

/** Homepage of each categorisation vendor so a classification can be checked against the vendor's own documentation. */
const VENDOR_HOMEPAGES: Record<string, string> = {
  BitDefender: "https://www.bitdefender.com",
  Sophos: "https://www.sophos.com",
  Webroot: "https://www.webroot.com",
  Forcepoint: "https://www.forcepoint.com",
  Fortinet: "https://www.fortinet.com",
  ESET: "https://www.eset.com",
  Kaspersky: "https://www.kaspersky.com",
  "Google Safebrowsing": "https://safebrowsing.google.com",
  Google: "https://safebrowsing.google.com",
  Comodo: "https://www.comodo.com",
  CYREN: "https://www.cyren.com",
  "Dr.Web": "https://www.drweb.com",
  Emsisoft: "https://www.emsisoft.com",
  Avira: "https://www.avira.com",
  "Trend Micro": "https://www.trendmicro.com",
  McAfee: "https://www.mcafee.com",
  "F-Secure": "https://www.f-secure.com",
  "Palo Alto": "https://www.paloaltonetworks.com",
  "G-Data": "https://www.gdata.de",
  Prebytes: "https://www.prebytes.se",
  Scantitan: "https://www.scantitan.se",
  Trustwave: "https://www.trustwave.com",
  Zscaler: "https://www.zscaler.com",
  ZeroFox: "https://www.zerofox.com",
};

function vendorLinks(vendors: string[]) {
  const links = vendors
    .map((v) => ({ label: v, url: VENDOR_HOMEPAGES[v] }))
    .filter((l): l is { label: string; url: string } => Boolean(l.url));
  return links.length > 0 ? links : undefined;
}

function guiLink(ctx: ProviderContext): string {
  const base = "https://www.virustotal.com/gui";
  switch (ctx.targetType) {
    case "ip":
      return `${base}/ip-address/${ctx.target}`;
    case "domain":
      return `${base}/domain/${ctx.target}`;
    case "url":
      return `${base}/url/${urlId(ctx.target)}`;
    default:
      return `${base}/file/${ctx.target}`;
  }
}

export const virustotalProvider: Provider = {
  name: "virustotal",
  label: "VirusTotal",
  supports: () => true,
  isConfigured: () => Boolean(process.env["VIRUSTOTAL_API_KEY"]),
  async run(ctx: ProviderContext): Promise<ProviderOutput> {
    const key = ctx.vtKey ?? process.env["VIRUSTOTAL_API_KEY"];
    if (!key) throw new Error("VIRUSTOTAL_API_KEY is not set");
    const endpoint = endpointFor(ctx);
    if (!endpoint) return {};

    let response: VtResponse;
    try {
      response = await fetchJson<VtResponse>(endpoint, { headers: { "x-apikey": key } });
    } catch (error) {
      if (error instanceof ProviderHttpError && error.status === 404) {
        return {
          evidence: [
            {
              provider: "VirusTotal",
              label: "No record for this indicator",
              detail: "VirusTotal has never analysed it — no malicious evidence found.",
              severity: "info",
              sourceUrl: guiLink(ctx),
              observedAt: nowIso(),
            },
          ],
        };
      }
      throw error;
    }

    const attrs = response.data?.attributes ?? {};
    const stats = attrs.last_analysis_stats ?? {};
    const malicious = stats.malicious ?? 0;
    const suspicious = stats.suspicious ?? 0;
    const harmless = stats.harmless ?? 0;
    const undetected = stats.undetected ?? 0;
    const total = malicious + suspicious + harmless + undetected + (stats.timeout ?? 0);

    const observedAt = attrs.last_analysis_date
      ? new Date(attrs.last_analysis_date * 1000).toISOString()
      : nowIso();

    const severity: Severity =
      malicious >= 5 ? "critical" : malicious >= 1 ? "high" : suspicious >= 1 ? "medium" : "info";

    const evidence: Evidence[] = [
      {
        provider: "VirusTotal",
        label:
          total > 0
            ? `${malicious} of ${total} engines flag this as malicious`
            : "No engine verdicts available",
        detail:
          total > 0
            ? `Malicious ${malicious} · Suspicious ${suspicious} · Harmless ${harmless} · Undetected ${undetected}`
            : "VirusTotal returned no analysis statistics.",
        severity,
        sourceUrl: guiLink(ctx),
        observedAt,
      },
    ];

    if (malicious === 0 && suspicious === 0 && total > 0) {
      evidence.push({
        provider: "VirusTotal",
        label: "No malicious evidence found",
        detail: `All ${total} engines that returned a verdict consider this harmless or undetected.`,
        severity: "info",
        sourceUrl: guiLink(ctx),
        observedAt,
      });
    }

    const families = new Set<string>();
    const label = attrs.popular_threat_classification?.suggested_threat_label;
    if (label) families.add(label);
    for (const entry of attrs.popular_threat_classification?.popular_threat_name ?? []) {
      if (entry.value) families.add(entry.value);
    }

    if (families.size > 0) {
      evidence.push({
        provider: "VirusTotal",
        label: `Attributed malware family: ${[...families].join(", ")}`,
        severity: "critical",
        sourceUrl: guiLink(ctx),
        observedAt,
      });
    }

    if (typeof attrs.reputation === "number" && attrs.reputation < 0) {
      evidence.push({
        provider: "VirusTotal",
        label: `Community reputation ${attrs.reputation}`,
        detail: "VirusTotal community votes lean negative for this indicator.",
        severity: "low",
        sourceUrl: guiLink(ctx),
        observedAt,
      });
    }

    // Vendor web categories: anonymizers / open proxies are a policy risk, and
    // phishing / malware categories are treated as known-malicious evidence.
    const cats = Object.entries(attrs.categories ?? {});
    const proxyCats = cats.filter(([, c]) => /anonymi[sz]|proxy|vpn|p2p/i.test(c));
    const badCats = cats.filter(([, c]) =>
      /phish|malware|malicious|botnet|command and control|\bc2\b|spyware/i.test(c),
    );
    if (cats.length > 0) {
      evidence.push({
        provider: "VirusTotal",
        label: "Vendor web categories",
        detail: cats.map(([v, c]) => `${v}: ${c}`).join(" · "),
        severity: "info",
        sourceUrl: guiLink(ctx),
        observedAt,
        links: vendorLinks(cats.map(([v]) => v)),
      });
    }
    if (proxyCats.length > 0) {
      evidence.push({
        provider: "VirusTotal",
        label: "Open web proxy / anonymizer",
        detail: `Categorised as ${proxyCats.map(([v, c]) => `${c} (${v})`).join(", ")}. Used to bypass security filtering and monitoring; commonly blocked as a security violation.`,
        severity: "medium",
        sourceUrl: guiLink(ctx),
        observedAt,
        links: vendorLinks(proxyCats.map(([v]) => v)),
      });
    }
    if (badCats.length > 0) {
      evidence.push({
        provider: "VirusTotal",
        label: "Malicious web category",
        detail: badCats.map(([v, c]) => `${c} (${v})`).join(", "),
        severity: "high",
        sourceUrl: guiLink(ctx),
        observedAt,
        links: vendorLinks(badCats.map(([v]) => v)),
      });
    }

    // Passive redirect data: the chain VirusTotal recorded, never fetched by us.
    let redirectChain: { source: string; hops: string[] } | undefined;
    if (ctx.targetType === "url") {
      const hops = [...(attrs.redirection_chain ?? [])];
      if (attrs.last_final_url && hops[hops.length - 1] !== attrs.last_final_url)
        hops.push(attrs.last_final_url);
      if (hops.length >= 2) {
        redirectChain = { source: "VirusTotal", hops: hops.slice(0, 10) };
        evidence.push({
          provider: "VirusTotal",
          label: `Redirect chain recorded (${hops.length - 1} hop${hops.length === 2 ? "" : "s"})`,
          detail: hops.slice(0, 10).join(" → "),
          severity: "info",
          sourceUrl: guiLink(ctx),
          observedAt,
        });
      } else {
        evidence.push({
          provider: "VirusTotal",
          label: "No redirect data",
          detail: "VirusTotal recorded no redirect chain for this URL.",
          severity: "info",
          sourceUrl: guiLink(ctx),
          observedAt,
        });
      }
    }

    return {
      evidence,
      malware:
        ctx.targetType === "hash"
          ? {
              families: [...families],
              fileType: attrs.type_description,
              fileSize: attrs.size,
              tags: attrs.tags ?? [],
              firstSeen: attrs.first_submission_date
                ? new Date(attrs.first_submission_date * 1000).toISOString()
                : undefined,
            }
          : undefined,
      signals: {
        ...(redirectChain ? { heuristics: { redirectChain } } : {}),
        virustotal: {
          malicious,
          suspicious,
          harmless,
          undetected,
          total,
          reputation: attrs.reputation,
          malwareFamilies: [...families],
          proxyCategories: proxyCats.map(([v, c]) => `${c} (${v})`),
        },
        knownMalicious:
          families.size > 0 || badCats.length >= 2
            ? [
                ...(families.size > 0
                  ? [
                      {
                        source: "VirusTotal",
                        detail: `Named malware family: ${[...families].join(", ")}`,
                      },
                    ]
                  : []),
                ...(badCats.length >= 2
                  ? [
                      {
                        source: "VirusTotal",
                        detail: `Malicious web category: ${badCats.map(([, c]) => c).join(", ")}`,
                      },
                    ]
                  : []),
              ]
            : undefined,
      },
    };
  },
};
