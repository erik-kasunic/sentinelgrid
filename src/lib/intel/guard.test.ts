import { afterEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
  selectResult: {
    data: [] as { created_at: string }[] | null,
    error: null as { message: string } | null,
  },
  insertResult: { error: null as { message: string } | null },
}));

vi.mock("@/integrations/supabase/client.server", () => ({
  supabaseAdmin: {
    from: () => ({
      select: () => ({
        eq: () => ({
          eq: () => ({
            gte: () => ({ order: () => ({ limit: async () => db.selectResult }) }),
          }),
        }),
      }),
      insert: async () => db.insertResult,
    }),
  },
}));

import { checkRateLimit, rateKey, verifyTurnstile } from "./guard.server";

afterEach(() => {
  db.selectResult = { data: [], error: null };
  db.insertResult = { error: null };
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("rateKey", () => {
  it("keeps IPv4 addresses as they are", () => {
    expect(rateKey("203.0.113.7")).toBe("203.0.113.7");
    expect(rateKey("unknown")).toBe("unknown");
  });

  it("maps every address in the same IPv6 /64 to one key", () => {
    const a = rateKey("2001:db8:1:2::1");
    const b = rateKey("2001:0db8:0001:0002:ffff:eeee:dddd:9999");
    expect(a).toBe("2001:db8:1:2::/64");
    expect(b).toBe(a);
  });

  it("keeps different /64 networks apart", () => {
    expect(rateKey("2001:db8:1:3::1")).not.toBe(rateKey("2001:db8:1:2::1"));
  });

  it("maps IPv4-mapped IPv6 back to the IPv4 address", () => {
    expect(rateKey("::ffff:203.0.113.7")).toBe("203.0.113.7");
  });

  it("returns malformed input unchanged instead of throwing", () => {
    expect(rateKey("1:2:3:4:5:6:7:8:9")).toBe("1:2:3:4:5:6:7:8:9");
    expect(rateKey("zzzz::1")).toBe("zzzz::1");
  });
});

describe("checkRateLimit", () => {
  it("rejects the request when the limit cannot be checked", async () => {
    db.selectResult = { data: null, error: { message: "db down" } };
    vi.spyOn(console, "error").mockImplementation(() => {});
    const result = await checkRateLimit("hash", "lookup");
    expect(result.ok).toBe(false);
  });

  it("rejects the request when the event cannot be recorded", async () => {
    db.insertResult = { error: { message: "write failed" } };
    vi.spyOn(console, "error").mockImplementation(() => {});
    const result = await checkRateLimit("hash", "lookup");
    expect(result.ok).toBe(false);
  });

  it("allows a request under the limit", async () => {
    expect((await checkRateLimit("hash", "lookup")).ok).toBe(true);
  });

  it("rejects once the hourly limit is reached", async () => {
    const recent = new Date(Date.now() - 60_000).toISOString();
    db.selectResult = {
      data: Array.from({ length: 10 }, () => ({ created_at: recent })),
      error: null,
    };
    const result = await checkRateLimit("hash", "lookup");
    expect(result.ok).toBe(false);
  });
});

describe("verifyTurnstile hostname", () => {
  const respond = (body: unknown) =>
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify(body))),
    );

  it("accepts a token solved on this site", async () => {
    vi.stubEnv("DEV", false);
    vi.stubEnv("TURNSTILE_SECRET_KEY", "test-secret");
    respond({ success: true, hostname: "sentinelgrid.erikkasunic.workers.dev" });
    expect(await verifyTurnstile("token", "203.0.113.7")).toBe(true);
  });

  it("rejects a token solved on another site", async () => {
    vi.stubEnv("DEV", false);
    vi.stubEnv("TURNSTILE_SECRET_KEY", "test-secret");
    vi.spyOn(console, "error").mockImplementation(() => {});
    respond({ success: true, hostname: "evil.example" });
    expect(await verifyTurnstile("token", "203.0.113.7")).toBe(false);
  });

  it("rejects a failed verification", async () => {
    vi.stubEnv("DEV", false);
    vi.stubEnv("TURNSTILE_SECRET_KEY", "test-secret");
    respond({ success: false });
    expect(await verifyTurnstile("token", "203.0.113.7")).toBe(false);
  });
});
