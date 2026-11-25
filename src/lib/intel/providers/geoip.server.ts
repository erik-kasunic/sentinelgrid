import { fetchJson, nowIso } from "../http.server";
import type { Provider, ProviderContext, ProviderOutput } from "./provider.server";

interface IpWhoResponse {
  success: boolean;
  message?: string;
  ip?: string;
  country?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  connection?: { asn?: number; org?: string; isp?: string; domain?: string };
}

export const geoipProvider: Provider = {
  name: "geoip",
  label: "GeoIP / ASN",
  supports: (t) => t === "ip" || t === "domain" || t === "url",
  isConfigured: () => true,
  async run(ctx: ProviderContext): Promise<ProviderOutput> {
    const ip = ctx.ip;
    if (!ip) return {};

    const data = await fetchJson<IpWhoResponse>(`https://ipwho.is/${encodeURIComponent(ip)}`, {
      timeoutMs: 7000,
    });
    if (!data.success) throw new Error(data.message ?? "Lookup rejected by provider");

    const asn = data.connection?.asn ? `AS${data.connection.asn}` : undefined;
    const org = data.connection?.org;
    const isp = data.connection?.isp;

    return {
      evidence: [
        {
          provider: "GeoIP / ASN",
          label: [asn, isp ?? org].filter(Boolean).join(" · ") || "Network details retrieved",
          detail: [data.city, data.region, data.country].filter(Boolean).join(", ") || undefined,
          severity: "info",
          observedAt: nowIso(),
        },
      ],
      relationships: asn
        ? [{ fromValue: ip, fromType: "ip", toValue: asn, toType: "asn", kind: "belongs_to" }]
        : [],
      infrastructure: {
        asn,
        isp,
        organization: org,
        country: data.country,
        region: data.region,
        city: data.city,
        latitude: data.latitude,
        longitude: data.longitude,
      },
    };
  },
};
