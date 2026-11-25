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

interface Geo {
  asn?: string | undefined;
  isp?: string | undefined;
  org?: string | undefined;
  country?: string | undefined;
  region?: string | undefined;
  city?: string | undefined;
  latitude?: number | undefined;
  longitude?: number | undefined;
}

async function fromIpWho(ip: string): Promise<Geo> {
  const data = await fetchJson<IpWhoResponse>(`https://ipwho.is/${encodeURIComponent(ip)}`, {
    timeoutMs: 7000,
  });
  if (!data.success) throw new Error(data.message ?? "Lookup rejected by provider");
  return {
    asn: data.connection?.asn ? `AS${data.connection.asn}` : undefined,
    isp: data.connection?.isp,
    org: data.connection?.org,
    country: data.country,
    region: data.region,
    city: data.city,
    latitude: data.latitude,
    longitude: data.longitude,
  };
}

interface RipeGeo {
  data?: {
    located_resources?: {
      locations?: {
        country?: string;
        city?: string;
        latitude?: number;
        longitude?: number;
        covered_percentage?: number;
      }[];
    }[];
  };
}
interface RipeNetwork {
  data?: { asns?: string[] };
}
interface RipeAs {
  data?: { holder?: string };
}

const RIPE = "https://stat.ripe.net/data";

/**
 * Fallback: RIPEstat (GeoLite location plus routing data). Keyless and not limited per client
 * IP, so it still answers when ipwho.is rate-limits the shared Cloudflare egress addresses.
 */
export async function fromRipeStat(ip: string): Promise<Geo> {
  const q = `resource=${encodeURIComponent(ip)}&sourceapp=sentinelgrid`;
  const [geo, net] = await Promise.all([
    fetchJson<RipeGeo>(`${RIPE}/maxmind-geo-lite/data.json?${q}`, { timeoutMs: 7000 }),
    fetchJson<RipeNetwork>(`${RIPE}/network-info/data.json?${q}`, { timeoutMs: 7000 }).catch(
      () => ({}) as RipeNetwork,
    ),
  ]);
  const location = (geo.data?.located_resources ?? [])
    .flatMap((r) => r.locations ?? [])
    .sort((a, b) => (b.covered_percentage ?? 0) - (a.covered_percentage ?? 0))[0];
  const asnNumber = net.data?.asns?.[0];
  let holder: string | undefined;
  if (asnNumber) {
    const as = await fetchJson<RipeAs>(
      `${RIPE}/as-overview/data.json?resource=AS${asnNumber}&sourceapp=sentinelgrid`,
      { timeoutMs: 5000 },
    ).catch(() => ({}) as RipeAs);
    holder = as.data?.holder;
  }
  if (!location && !asnNumber) throw new Error("No location or network data returned");
  return {
    asn: asnNumber ? `AS${asnNumber}` : undefined,
    org: holder,
    country: location?.country || undefined,
    city: location?.city || undefined,
    latitude: location?.latitude,
    longitude: location?.longitude,
  };
}

export const geoipProvider: Provider = {
  name: "geoip",
  label: "GeoIP / ASN",
  supports: (t) => t === "ip" || t === "domain" || t === "url",
  isConfigured: () => true,
  async run(ctx: ProviderContext): Promise<ProviderOutput> {
    const ip = ctx.ip;
    if (!ip) return {};

    let data: Geo;
    try {
      data = await fromIpWho(ip);
    } catch {
      data = await fromRipeStat(ip);
    }
    const { asn, org, isp } = data;

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
