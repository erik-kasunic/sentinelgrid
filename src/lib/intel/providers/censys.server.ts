// Censys Platform API host lookup: services, software and labels from Censys's
// own scans. Passive — we never contact the target. CENSYS_API_SECRET holds a
// Platform personal access token (Search v2 was shut down 2026-09-30).
import { ProviderHttpError, fetchJson, nowIso } from "../http.server";
import type { Evidence } from "../types";
import type { Provider, ProviderContext, ProviderOutput } from "./provider.server";

interface CensysService {
  port?: number;
  protocol?: string;
  transport_protocol?: string;
  software?: { product?: string; version?: string }[];
  labels?: { value?: string }[];
  vulns?: { id?: string }[];
}
interface CensysResponse {
  result?: { resource?: { services?: CensysService[]; labels?: { value?: string }[] } };
}

export const censysProvider: Provider = {
  name: "censys",
  label: "Censys",
  supports: (t) => t === "ip" || t === "domain" || t === "url",
  isConfigured: () => Boolean(process.env["CENSYS_API_SECRET"]),
  async run(ctx: ProviderContext): Promise<ProviderOutput> {
    const token = process.env["CENSYS_API_SECRET"];
    if (!token) throw new Error("CENSYS_API_SECRET is not set");
    const ip = ctx.ip;
    if (!ip) return {};
    const sourceUrl = `https://platform.censys.io/hosts/${ip}`;
    const observedAt = nowIso();
    let data: CensysResponse;
    try {
      data = await fetchJson<CensysResponse>(
        `https://api.platform.censys.io/v3/global/asset/host/${encodeURIComponent(ip)}`,
        {
          headers: { Authorization: `Bearer ${token}` },
        },
      );
    } catch (e) {
      if (e instanceof ProviderHttpError && e.status === 404) {
        return {
          evidence: [
            {
              provider: "Censys",
              label: "Censys has no record of this host",
              severity: "info",
              sourceUrl,
              observedAt,
            },
          ],
        };
      }
      throw e;
    }
    const services = data.result?.resource?.services ?? [];
    const lines = services.slice(0, 15).map((s) => {
      const sw = s.software?.find((x) => x.product);
      return `${s.port ?? "?"}/${(s.transport_protocol ?? "tcp").toLowerCase()} ${s.protocol ?? "UNKNOWN"}${sw ? ` (${sw.product}${sw.version ? ` ${sw.version}` : ""})` : ""}`;
    });
    const evidence: Evidence[] = [
      {
        provider: "Censys",
        label: services.length
          ? `${services.length} exposed service${services.length === 1 ? "" : "s"}`
          : "No exposed services recorded",
        detail: lines.length ? lines.join("; ") : undefined,
        severity: "info",
        sourceUrl,
        observedAt: observedAt,
      },
    ];
    const labels = [
      ...(data.result?.resource?.labels ?? []),
      ...services.flatMap((s) => s.labels ?? []),
    ]
      .map((l) => l.value)
      .filter((v): v is string => Boolean(v));
    const vulns = [
      ...new Set(
        services
          .flatMap((s) => (s.vulns ?? []).map((v) => v.id))
          .filter((v): v is string => Boolean(v)),
      ),
    ];
    if (vulns.length) {
      evidence.push({
        provider: "Censys",
        label: `${vulns.length} known vulnerabilit${vulns.length === 1 ? "y" : "ies"} on exposed services`,
        detail: vulns.slice(0, 12).join(", "),
        severity: vulns.length >= 5 ? "high" : "medium",
        sourceUrl,
        observedAt,
      });
    }
    if (labels.length) {
      const risky = labels.some((l) => /c2|malware|open-proxy|botnet/i.test(l));
      evidence.push({
        provider: "Censys",
        label: `Labels: ${[...new Set(labels)].join(", ")}`,
        severity: risky ? "high" : "info",
        sourceUrl,
        observedAt,
      });
    }
    return { evidence };
  },
};
