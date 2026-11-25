// Abuse guard backed by the database: hashed-IP rate limits, typed-TTL result
// cache, provider daily budgets and Turnstile verification. Server-only.
import type { TargetType } from "./types";

const HOUR_MS = 3_600_000;
export const LIMITS = { lookupPerHour: 10, refreshPerHour: 3 };
export const TTL_SECONDS: Record<TargetType, number> = {
  ip: 6 * 3600,
  domain: 12 * 3600,
  url: 3600,
  hash: 24 * 3600,
};
/** Known free quotas; providers are skipped at 80%. */
export const PROVIDER_BUDGET: Record<string, { perDay: number; perMinute?: number }> = {
  virustotal: { perDay: 500, perMinute: 4 },
  abuseipdb: { perDay: 1000 },
  censys: { perDay: 8 },
};
const BUDGET_THRESHOLD = 0.8;

async function admin() {
  const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
  return supabaseAdmin;
}

const isProduction = () => !import.meta.env.DEV;

export async function hashIp(ip: string): Promise<string> {
  let salt = process.env["RATE_LIMIT_SALT"];
  if (!salt) {
    if (isProduction()) throw new Error("RATE_LIMIT_SALT is not configured");
    console.warn("[sg-guard] RATE_LIMIT_SALT missing; using dev-only salt");
    salt = "sentinelgrid-dev-only-salt";
  }
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${salt}:${ip}`));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function checkRateLimit(
  ipHash: string,
  kind: "lookup" | "refresh",
): Promise<{ ok: true } | { ok: false; retryAfterSec: number }> {
  const db = await admin();
  const since = new Date(Date.now() - HOUR_MS).toISOString();
  const limit = kind === "refresh" ? LIMITS.refreshPerHour : LIMITS.lookupPerHour;
  const { data, error } = await db
    .from("rate_events")
    .select("created_at")
    .eq("ip_hash", ipHash)
    .eq("kind", kind)
    .gte("created_at", since)
    .order("created_at", { ascending: true })
    .limit(limit);
  if (error) {
    console.error("[sg-guard] rate check failed", error.message);
    return { ok: true };
  }
  if ((data?.length ?? 0) >= limit) {
    const oldest = new Date(data![0]!.created_at).getTime();
    return {
      ok: false,
      retryAfterSec: Math.max(1, Math.ceil((oldest + HOUR_MS - Date.now()) / 1000)),
    };
  }
  await db.from("rate_events").insert({ ip_hash: ipHash, kind });
  return { ok: true };
}

export async function getCached<T>(
  key: string,
): Promise<{ value: T; fetchedAt: string } | undefined> {
  const db = await admin();
  const { data } = await db
    .from("lookup_cache")
    .select("result, fetched_at, ttl_seconds")
    .eq("cache_key", key)
    .maybeSingle();
  if (!data) return undefined;
  if (Date.now() - new Date(data.fetched_at).getTime() > data.ttl_seconds * 1000) return undefined;
  return { value: data.result as T, fetchedAt: data.fetched_at };
}

export async function setCached(key: string, type: TargetType, value: unknown) {
  const db = await admin();
  const { error } = await db.from("lookup_cache").upsert({
    cache_key: key,
    result: JSON.parse(JSON.stringify(value)),
    fetched_at: new Date().toISOString(),
    ttl_seconds: TTL_SECONDS[type],
  });
  if (error) console.error("[sg-guard] cache write failed", error.message);
}

/** True when the provider may be called right now under its free quota. */
export async function providerHasBudget(
  provider: string,
): Promise<{ ok: boolean; reason?: string }> {
  const budget = PROVIDER_BUDGET[provider];
  if (!budget) return { ok: true };
  const db = await admin();
  const dayStart = new Date();
  dayStart.setUTCHours(0, 0, 0, 0);
  const { count: day } = await db
    .from("provider_usage")
    .select("id", { count: "exact", head: true })
    .eq("provider", provider)
    .gte("created_at", dayStart.toISOString());
  if ((day ?? 0) >= budget.perDay * BUDGET_THRESHOLD)
    return { ok: false, reason: "daily budget reached" };
  if (budget.perMinute) {
    const { count: min } = await db
      .from("provider_usage")
      .select("id", { count: "exact", head: true })
      .eq("provider", provider)
      .gte("created_at", new Date(Date.now() - 60_000).toISOString());
    if ((min ?? 0) >= budget.perMinute) return { ok: false, reason: "per-minute limit reached" };
  }
  return { ok: true };
}

export async function recordProviderUse(provider: string) {
  if (!PROVIDER_BUDGET[provider]) return;
  const db = await admin();
  await db.from("provider_usage").insert({ provider });
}

export async function verifyTurnstile(token: string | undefined, ip: string): Promise<boolean> {
  const secret = process.env["TURNSTILE_SECRET_KEY"];
  if (!secret) {
    if (isProduction()) {
      console.error("[sg-guard] TURNSTILE_SECRET_KEY missing; rejecting request (fail-closed)");
      return false;
    }
    return true;
  }
  if (!token) return false;
  try {
    const body = new FormData();
    body.append("secret", secret);
    body.append("response", token);
    if (ip !== "unknown") body.append("remoteip", ip);
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body,
      signal: AbortSignal.timeout(6000),
    });
    const json = (await res.json()) as { success?: boolean };
    return json.success === true;
  } catch {
    return false;
  }
}
