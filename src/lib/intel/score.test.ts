import { describe, expect, it } from "vitest";
import { bandFor, buildDimensions, computeScore, mergeSignals } from "./score.server";
import type { ProviderSignals } from "./providers/provider.server";
import type { ProviderStatus } from "./types";

const done = (...providers: string[]): ProviderStatus[] =>
  providers.map((provider) => ({ provider, status: "completed" }));

const vt = (
  malicious: number,
  total = 70,
  extra: Partial<NonNullable<ProviderSignals["virustotal"]>> = {},
) => ({
  virustotal: {
    malicious,
    suspicious: 0,
    harmless: 0,
    undetected: total - malicious,
    total,
    ...extra,
  },
});

function score(
  signals: ProviderSignals[],
  status: ProviderStatus[],
  threat = ["virustotal", "abuseipdb"],
) {
  const merged = mergeSignals(signals);
  const s = computeScore(merged, status, threat);
  return { merged, s };
}

describe("bandFor", () => {
  it.each([
    [0, "safe"],
    [19, "safe"],
    [20, "low"],
    [40, "medium"],
    [60, "high"],
    [80, "critical"],
    [100, "critical"],
  ])("%i -> %s", (total, band) => {
    expect(bandFor(total)).toBe(band);
  });
});

describe("computeScore", () => {
  it("is deterministic", () => {
    const input = [vt(5), { abuseipdb: { confidence: 60, reports: 12 } }];
    const a = score(input, done("virustotal", "abuseipdb")).s;
    const b = score(input, done("virustotal", "abuseipdb")).s;
    expect(a).toEqual(b);
  });

  it("caps VirusTotal at 40", () => {
    const { s } = score([vt(30)], done("virustotal"));
    expect(s.lines.find((l) => l.category === "virustotal")?.points).toBe(40);
  });

  it("scales AbuseIPDB confidence to 25", () => {
    const { s } = score([{ abuseipdb: { confidence: 100, reports: 300 } }], done("abuseipdb"));
    expect(s.lines.find((l) => l.category === "abuseipdb")?.points).toBe(25);
  });

  it("never exceeds 100", () => {
    const { s } = score(
      [
        vt(50),
        { abuseipdb: { confidence: 100, reports: 900 } },
        { knownMalicious: [{ source: "URLhaus exact URL", detail: "status online" }] },
        { heuristics: { rawIpHost: true, nonStandardPort: 8080, dropperPath: "/bins/x86" } },
      ],
      done("virustotal", "abuseipdb"),
    );
    expect(s.total).toBe(100);
    expect(s.band).toBe("critical");
  });

  it("down-weights a few flags on a long-established domain", () => {
    const { s } = score(
      [vt(2), { infrastructure: { domainAgeDays: 10 * 365 } }],
      done("virustotal", "rdap", "dns"),
    );
    expect(s.lines.find((l) => l.category === "virustotal")?.points).toBe(8);
  });

  it("raises the score to CRITICAL when many engines agree", () => {
    const { s } = score([vt(20, 93)], done("virustotal"));
    expect(s.total).toBeGreaterThanOrEqual(80);
    expect(s.band).toBe("critical");
    expect(s.lines.reduce((sum, l) => sum + l.points, 0)).toBe(s.total);
  });

  it("does not apply the consensus floor to a handful of flags", () => {
    const { s } = score([vt(5, 93)], done("virustotal"));
    expect(s.total).toBeLessThan(80);
  });

  it("does not apply the consensus floor to down-weighted outliers", () => {
    const { s } = score(
      [vt(3, 93), { infrastructure: { domainAgeDays: 10 * 365 } }],
      done("virustotal", "rdap", "dns"),
    );
    expect(s.total).toBeLessThan(80);
  });

  it("marks the result insufficient when no reputation source answered", () => {
    const { s } = score([], [{ provider: "virustotal", status: "failed" }]);
    expect(s.basis).toBe("insufficient");
  });

  it("treats an old, resolving domain with no flags as evaluated and safe", () => {
    const { s } = score(
      [vt(0, 0), { infrastructure: { domainAgeDays: 4000 } }],
      done("dns", "rdap", "virustotal"),
    );
    expect(s.basis).toBe("evaluated");
    expect(s.band).toBe("safe");
  });

  it("gives no infrastructure points to a clean datacenter IP like 8.8.8.8", () => {
    const { s } = score(
      [
        vt(0),
        { abuseipdb: { confidence: 0, reports: 0 }, infrastructure: { hostingProvider: true } },
      ],
      done("virustotal", "abuseipdb"),
    );
    expect(s.lines.some((l) => l.category === "infrastructure")).toBe(false);
    expect(s.total).toBe(0);
  });

  it("adds hosting points when another source flags the IP", () => {
    const { s } = score(
      [
        vt(3),
        { abuseipdb: { confidence: 80, reports: 40 }, infrastructure: { hostingProvider: true } },
      ],
      done("virustotal", "abuseipdb"),
    );
    expect(s.lines.find((l) => l.category === "infrastructure")?.points).toBe(3);
  });
});

describe("buildDimensions", () => {
  it("does not show INFRASTRUCTURE as unknown when the score used infrastructure data", () => {
    const signals = [
      vt(3),
      { abuseipdb: { confidence: 80, reports: 40 }, infrastructure: { hostingProvider: true } },
    ];
    const status: ProviderStatus[] = [
      ...done("virustotal", "abuseipdb"),
      { provider: "geoip", status: "failed" },
    ];
    const { merged, s } = score(signals, status);
    const infra = buildDimensions(s, merged, "ip", status).find((d) => d.name === "INFRASTRUCTURE");
    expect(infra?.state).toBe("low");
  });

  it("shows INFRASTRUCTURE as unknown when no infrastructure source answered", () => {
    const status: ProviderStatus[] = [{ provider: "geoip", status: "failed" }];
    const { merged, s } = score([], status);
    const infra = buildDimensions(s, merged, "ip", status).find((d) => d.name === "INFRASTRUCTURE");
    expect(infra?.state).toBe("unknown");
  });

  it("flags a newly registered domain as medium", () => {
    const status = done("dns", "rdap");
    const { merged, s } = score([{ infrastructure: { domainAgeDays: 5 } }], status);
    const infra = buildDimensions(s, merged, "domain", status).find(
      (d) => d.name === "INFRASTRUCTURE",
    );
    expect(infra?.state).toBe("medium");
  });

  it("only assesses MALWARE for file hashes", () => {
    const status = done("virustotal");
    const { merged, s } = score([vt(0)], status);
    const malware = buildDimensions(s, merged, "domain", status).find((d) => d.name === "MALWARE");
    expect(malware?.state).toBe("not_applicable");
  });
});
