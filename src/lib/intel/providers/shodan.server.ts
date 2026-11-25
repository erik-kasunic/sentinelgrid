// Shodan InternetDB: free, keyless, passive snapshot of open ports, CPEs and
// known CVEs for an IP from Shodan's own scans. We never contact the target.
import { ProviderHttpError, fetchJson, nowIso } from "../http.server";
import type { Evidence } from "../types";
import type { Provider, ProviderContext, ProviderOutput } from "./provider.server";

interface InternetDbResponse {
  ip?: string;
  ports?: number[];
  cpes?: string[];
  hostnames?: string[];
  tags?: string[];
  vulns?: string[];
}

export const shodanProvider: Provider = {
  name: "shodan",
  label: "Shodan InternetDB",
  supports: (t) => t === "ip" || t === "domain" || t === "url",
  isConfigured: () => true,
  async run(ctx: ProviderContext): Promise<ProviderOutput> {
    const ip = ctx.ip;
    if (!ip) return {};
    const sourceUrl = `https://www.shodan.io/host/${ip}`;
    const observedAt = nowIso();
    let data: InternetDbResponse;
    try {
      data = await fetchJson<InternetDbResponse>(
        `https://internetdb.shodan.io/${encodeURIComponent(ip)}`,
      );
    } catch (e) {
      if (e instanceof ProviderHttpError && e.status === 404) {
        return {
          evidence: [
            {
              provider: "Shodan",
              label: "No Shodan scan data for this IP — no exposed services recorded",
              severity: "info",
              sourceUrl,
              observedAt,
            },
          ],
        };
      }
      throw e;
    }
    const ports = (data.ports ?? []).slice().sort((a, b) => a - b);
    const vulns = data.vulns ?? [];
    const evidence: Evidence[] = [
      {
        provider: "Shodan",
        label: ports.length
          ? `${ports.length} open port${ports.length === 1 ? "" : "s"}: ${ports.slice(0, 20).join(", ")}`
          : "No open ports recorded",
        detail: data.cpes?.length ? `Services: ${data.cpes.slice(0, 8).join(", ")}` : undefined,
        severity: "info",
        sourceUrl,
        observedAt,
      },
    ];
    if (vulns.length) {
      evidence.push({
        provider: "Shodan",
        label: `${vulns.length} known vulnerabilit${vulns.length === 1 ? "y" : "ies"} on exposed services`,
        detail:
          vulns.slice(0, 12).join(", ") +
          (vulns.length > 12 ? ` (+${vulns.length - 12} more)` : ""),
        severity: vulns.length >= 5 ? "high" : "medium",
        sourceUrl,
        observedAt,
      });
    }
    if (data.tags?.length) {
      evidence.push({
        provider: "Shodan",
        label: `Tags: ${data.tags.join(", ")}`,
        severity: "info",
        sourceUrl,
        observedAt,
      });
    }
    return { evidence };
  },
};
