import { afterEach, describe, expect, it, vi } from "vitest";
import { geoipProvider } from "./geoip.server";
import type { ProviderContext } from "./provider.server";

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

afterEach(() => vi.unstubAllGlobals());

describe("geoipProvider", () => {
  it("falls back to RIPEstat when ipwho.is rate-limits", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.startsWith("https://ipwho.is/")) return json({}, 429);
        if (url.includes("/maxmind-geo-lite/"))
          return json({
            data: {
              located_resources: [
                {
                  locations: [
                    {
                      country: "US",
                      city: "",
                      latitude: 37.75,
                      longitude: -97.82,
                      covered_percentage: 100,
                    },
                  ],
                },
              ],
            },
          });
        if (url.includes("/network-info/")) return json({ data: { asns: ["15169"] } });
        if (url.includes("/as-overview/")) return json({ data: { holder: "GOOGLE - Google LLC" } });
        throw new Error(`unexpected ${url}`);
      }),
    );
    const out = await geoipProvider.run({ ip: "8.8.8.8" } as ProviderContext);
    expect(out.infrastructure).toMatchObject({
      asn: "AS15169",
      organization: "GOOGLE - Google LLC",
      country: "US",
      latitude: 37.75,
    });
  });

  it("fails when both sources fail", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => json({}, 503)),
    );
    await expect(geoipProvider.run({ ip: "8.8.8.8" } as ProviderContext)).rejects.toThrow();
  });
});
