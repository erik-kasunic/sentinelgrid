import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { classify, classifyAs, validateClassified } from "./intel/classify";
import type { InvestigationResult, TargetType, Verdict } from "./intel/types";

const TARGET_TYPES = ["ip", "domain", "url", "hash"] as const;

const investigateInput = z.object({
  target: z.string().min(1).max(2048),
  type: z.enum(TARGET_TYPES).optional(),
  turnstileToken: z.string().max(4096).optional(),
  forceRefresh: z.boolean().optional(),
  /** Analyst's own VirusTotal key: used for this request only, never stored or logged. */
  vtKey: z
    .string()
    .regex(/^[a-f0-9]{64}$/i, "VirusTotal keys are 64 hex characters")
    .optional(),
});

function retryText(sec: number) {
  return sec >= 120 ? `${Math.ceil(sec / 60)} minuter` : `${sec} sekunder`;
}

export const investigateTarget = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) => investigateInput.parse(input))
  .handler(async ({ data }) => {
    const guard = await import("./intel/guard.server");
    const { getRequestHeader, setResponseStatus, setResponseHeader } =
      await import("@tanstack/react-start/server");
    const ip =
      getRequestHeader("cf-connecting-ip") ??
      getRequestHeader("x-forwarded-for")?.split(",")[0]?.trim() ??
      "unknown";

    if (!(await guard.verifyTurnstile(data.turnstileToken, ip))) {
      return {
        ok: false as const,
        error: "Bot-kontrollen misslyckades. Ladda om sidan och försök igen.",
        turnstileFailed: true,
      };
    }
    const ipHash = await guard.hashIp(guard.rateKey(ip));

    const limited = (sec: number) => {
      setResponseStatus(429);
      setResponseHeader("Retry-After", String(sec));
      console.log(`[sg-guard] rate_limited retry=${sec}s`);
      return {
        ok: false as const,
        error: `För många sökningar. Försök igen om ${retryText(sec)}.`,
        retryAfterSec: sec,
      };
    };

    let detected = data.type ? classifyAs(data.target, data.type) : classify(data.target);

    if (!detected.type && !data.type) {
      // Free text: let the LLM try to find an indicator (counts toward the limit).
      const rl0 = await guard.checkRateLimit(ipHash, "lookup");
      if (!rl0.ok) return limited(rl0.retryAfterSec);
      const { extractIndicatorWithLlm } = await import("./intel/llm-extract.server");
      const extracted = await extractIndicatorWithLlm(data.target);
      if (extracted) {
        console.log(`[sg-guard] llm_extracted type=${extracted.type}`);
        detected = extracted;
      }
    }

    const invalid = validateClassified(detected);
    if (invalid || !detected.type) {
      return {
        ok: false as const,
        error: invalid ?? "That input could not be classified as an IP, domain, URL or file hash.",
      };
    }

    type Result = Awaited<ReturnType<typeof import("./intel/pipeline.server").runInvestigation>>;
    const cacheKey = `${detected.type}:${detected.canonical.toLowerCase()}`;
    // Results fetched with a personal VT key are not shared through the cache.
    if (!data.forceRefresh && !data.vtKey) {
      const cached = await guard.getCached<Result>(cacheKey);
      if (cached) {
        console.log(`[sg-guard] cache_hit type=${detected.type}`);
        return {
          ok: true as const,
          result: { ...cached.value, id: crypto.randomUUID(), cachedAt: cached.fetchedAt },
        };
      }
    }

    if (data.forceRefresh) {
      const rr = await guard.checkRateLimit(ipHash, "refresh");
      if (!rr.ok) return limited(rr.retryAfterSec);
    }
    const rl = await guard.checkRateLimit(ipHash, "lookup");
    if (!rl.ok) return limited(rl.retryAfterSec);

    console.log(`[sg-guard] provider_run type=${detected.type}`);
    const { runInvestigation } = await import("./intel/pipeline.server");
    const result = await runInvestigation({
      target: detected.canonical,
      targetType: detected.type,
      vtKey: data.vtKey,
    });
    if (!data.vtKey) await guard.setCached(cacheKey, detected.type, result);
    return { ok: true as const, result };
  });

/** Loose validation of a client-returned result before persisting it. */
const resultSchema = z
  .object({
    target: z.string().min(1).max(2048),
    targetType: z.enum(TARGET_TYPES),
    verdict: z.string().max(32),
    verdictBasis: z.enum(["evaluated", "insufficient"]),
    riskScore: z.object({ total: z.number().min(0).max(100) }).passthrough(),
    iocs: z
      .array(
        z.object({ value: z.string().max(2048), type: z.enum(TARGET_TYPES), primary: z.boolean() }),
      )
      .max(200),
    evidence: z
      .array(
        z
          .object({
            provider: z.string().max(64),
            label: z.string().max(512),
            detail: z.string().max(2048).optional(),
            severity: z.string().max(16),
            confidence: z.number().optional(),
            sourceUrl: z.string().max(2048).optional(),
            observedAt: z.string().max(64).optional(),
          })
          .passthrough(),
      )
      .max(200),
    relationships: z
      .array(
        z.object({
          fromValue: z.string().max(2048),
          fromType: z.string().max(32),
          toValue: z.string().max(2048),
          toType: z.string().max(32),
          kind: z.string().max(32),
        }),
      )
      .max(400),
    providerStatus: z
      .array(
        z.object({
          provider: z.string().max(64),
          status: z.string().max(32),
          message: z.string().max(512).optional(),
          durationMs: z.number().optional(),
        }),
      )
      .max(50),
  })
  .passthrough();

const saveInput = z.object({
  title: z.string().min(1).max(200).optional(),
  folderId: z.string().uuid().nullable().optional(),
  result: resultSchema,
});

export const saveInvestigation = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) => saveInput.parse(input))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const result = data.result as unknown as InvestigationResult;

    // Simple per-user rate limit: 30 saved investigations per minute.
    const since = new Date(Date.now() - 60_000).toISOString();
    const { count } = await supabase
      .from("investigations")
      .select("id", { count: "exact", head: true })
      .eq("user_id", userId)
      .gte("created_at", since);
    if ((count ?? 0) >= 30) {
      return { ok: false as const, error: "Rate limit reached. Try again in a minute." };
    }

    const { data: inserted, error } = await supabase
      .from("investigations")
      .insert({
        user_id: userId,
        folder_id: data.folderId ?? null,
        title: data.title ?? `${result.targetType.toUpperCase()} · ${result.target}`,
        initial_target: result.target,
        target_type: result.targetType,
        threat_score: result.verdictBasis === "insufficient" ? null : result.riskScore.total,
        verdict: result.verdict,
        verdict_basis: result.verdictBasis,
        summary: result.ai?.summary ?? null,
        recommended_action: result.ai?.recommended_action ?? null,
        result: JSON.parse(JSON.stringify(result)) as import("@/integrations/supabase/types").Json,
      })
      .select("id")
      .single();

    if (error || !inserted) {
      console.error("save investigation failed", error);
      return { ok: false as const, error: "Could not save this investigation." };
    }

    const investigationId = inserted.id;

    const children: Promise<unknown>[] = [];
    if (result.iocs.length) {
      children.push(
        Promise.resolve(
          supabase.from("investigation_iocs").insert(
            result.iocs.map((ioc) => ({
              investigation_id: investigationId,
              user_id: userId,
              value: ioc.value,
              ioc_type: ioc.type,
              is_primary: ioc.primary,
            })),
          ),
        ),
      );
    }
    if (result.evidence.length) {
      children.push(
        Promise.resolve(
          supabase.from("evidence").insert(
            result.evidence.map((item) => ({
              investigation_id: investigationId,
              user_id: userId,
              provider: item.provider,
              label: item.label,
              detail: item.detail ?? null,
              severity: item.severity,
              confidence: item.confidence ?? null,
              source_url: item.sourceUrl ?? null,
              observed_at: item.observedAt ?? null,
            })),
          ),
        ),
      );
    }
    if (result.relationships.length) {
      children.push(
        Promise.resolve(
          supabase.from("relationships").insert(
            result.relationships.map((rel) => ({
              investigation_id: investigationId,
              user_id: userId,
              from_value: rel.fromValue,
              from_type: rel.fromType,
              to_value: rel.toValue,
              to_type: rel.toType,
              kind: rel.kind,
            })),
          ),
        ),
      );
    }
    if (result.providerStatus.length) {
      children.push(
        Promise.resolve(
          supabase.from("provider_results").insert(
            result.providerStatus.map((status) => ({
              investigation_id: investigationId,
              user_id: userId,
              provider: status.provider,
              status: status.status,
              message: status.message ?? null,
              duration_ms: status.durationMs ?? null,
            })),
          ),
        ),
      );
    }
    await Promise.allSettled(children);

    return { ok: true as const, id: investigationId };
  });

export const getInvestigation = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) => z.object({ id: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const { data: row, error } = await context.supabase
      .from("investigations")
      .select("id, title, created_at, result")
      .eq("id", data.id)
      .maybeSingle();

    if (error) {
      console.error("load investigation failed", error);
      return { ok: false as const, error: "Could not load this case." };
    }
    if (!row) return { ok: false as const, error: "Case not found." };

    const result = row.result as unknown as InvestigationResult;
    return {
      ok: true as const,
      result: { ...result, id: row.id, saved: true, title: row.title, createdAt: row.created_at },
    };
  });

const listInput = z.object({
  search: z.string().max(200).optional(),
  verdict: z.enum(["all", "safe", "low", "medium", "high", "critical", "unknown"]).optional(),
  limit: z.number().int().min(1).max(100).optional(),
  /** uuid = that folder, "none" = unfiled, omitted = all. */
  folderId: z.union([z.string().uuid(), z.literal("none")]).optional(),
});

export interface CaseSummary {
  id: string;
  title: string;
  initial_target: string;
  target_type: TargetType;
  threat_score: number | null;
  verdict: Verdict;
  verdict_basis: "evaluated" | "insufficient";
  summary: string | null;
  created_at: string;
  folder_id: string | null;
}

export const listInvestigations = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) => listInput.parse(input ?? {}))
  .handler(async ({ data, context }) => {
    let query = context.supabase
      .from("investigations")
      .select(
        "id, title, initial_target, target_type, threat_score, verdict, verdict_basis, summary, created_at, folder_id",
      )
      .order("created_at", { ascending: false })
      .limit(data.limit ?? 50);

    if (data.folderId === "none") query = query.is("folder_id", null);
    else if (data.folderId) query = query.eq("folder_id", data.folderId);

    if (data.verdict && data.verdict !== "all") query = query.eq("verdict", data.verdict);
    if (data.search) {
      const term = data.search.replace(/[%,()"\\]/g, "").trim();
      query = query.or(`initial_target.ilike.%${term}%,title.ilike.%${term}%`);
    }

    const { data: rows, error } = await query;
    if (error) {
      console.error("list investigations failed", error);
      return {
        ok: false as const,
        error: "Could not load your cases.",
        cases: [] as CaseSummary[],
      };
    }
    return { ok: true as const, cases: (rows ?? []) as unknown as CaseSummary[] };
  });

export const deleteInvestigation = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) => z.object({ id: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const { error } = await context.supabase.from("investigations").delete().eq("id", data.id);
    if (error) {
      console.error("delete investigation failed", error);
      return { ok: false as const, error: "Could not delete this case." };
    }
    return { ok: true as const };
  });

export const renameInvestigation = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({ id: z.string().uuid(), title: z.string().min(1).max(200) }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { error } = await context.supabase
      .from("investigations")
      .update({ title: data.title })
      .eq("id", data.id);
    if (error) {
      console.error("rename investigation failed", error);
      return { ok: false as const, error: "Could not rename this case." };
    }
    return { ok: true as const };
  });

export interface DashboardStats {
  investigations: number;
  highRisk: number;
  critical: number;
  unknown: number;
  iocs: number;
  distribution: { verdict: Verdict; count: number }[];
  typeCounts: { type: string; count: number }[];
  providerCounts: { provider: string; status: string; count: number }[];
  recent: CaseSummary[];
}

export const getDashboardStats = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase } = context;
    const [casesRes, iocRes, providerRes] = await Promise.all([
      supabase
        .from("investigations")
        .select(
          "id, title, initial_target, target_type, threat_score, verdict, verdict_basis, summary, created_at",
        )
        .order("created_at", { ascending: false })
        .limit(200),
      supabase.from("investigation_iocs").select("id", { count: "exact", head: true }),
      supabase.from("provider_results").select("provider, status").limit(2000),
    ]);

    const cases = (casesRes.data ?? []) as unknown as CaseSummary[];
    const verdicts: Verdict[] = ["safe", "low", "medium", "high", "critical", "unknown"];

    const providerCountMap = new Map<string, number>();
    for (const row of providerRes.data ?? []) {
      const key = `${row.provider}|${row.status}`;
      providerCountMap.set(key, (providerCountMap.get(key) ?? 0) + 1);
    }

    const typeMap = new Map<string, number>();
    for (const item of cases)
      typeMap.set(item.target_type, (typeMap.get(item.target_type) ?? 0) + 1);

    const stats: DashboardStats = {
      investigations: cases.length,
      highRisk: cases.filter((c) => c.verdict === "high").length,
      critical: cases.filter((c) => c.verdict === "critical").length,
      unknown: cases.filter((c) => c.verdict === "unknown").length,
      iocs: iocRes.count ?? 0,
      distribution: verdicts.map((verdict) => ({
        verdict,
        count: cases.filter((c) => c.verdict === verdict).length,
      })),
      typeCounts: [...typeMap.entries()].map(([type, count]) => ({ type, count })),
      providerCounts: [...providerCountMap.entries()].map(([key, count]) => {
        const [provider, status] = key.split("|");
        return { provider: provider ?? "", status: status ?? "", count };
      }),
      recent: cases.slice(0, 8),
    };

    return { ok: true as const, stats };
  });

export interface CaseFolder {
  id: string;
  name: string;
  count: number;
}

export const listFolders = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const [{ data: folders, error }, { data: rows }] = await Promise.all([
      context.supabase.from("case_folders").select("id, name").order("name"),
      context.supabase.from("investigations").select("folder_id"),
    ]);
    if (error) {
      console.error("list folders failed", error);
      return { ok: false as const, folders: [] as CaseFolder[], unfiled: 0, total: 0 };
    }
    const counts = new Map<string | null, number>();
    for (const r of rows ?? []) counts.set(r.folder_id, (counts.get(r.folder_id) ?? 0) + 1);
    return {
      ok: true as const,
      folders: (folders ?? []).map((f) => ({ ...f, count: counts.get(f.id) ?? 0 })),
      unfiled: counts.get(null) ?? 0,
      total: rows?.length ?? 0,
    };
  });

export const createFolder = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({ name: z.string().trim().min(1).max(80) }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { data: row, error } = await context.supabase
      .from("case_folders")
      .insert({ user_id: context.userId, name: data.name })
      .select("id, name")
      .single();
    if (error || !row) {
      return {
        ok: false as const,
        error:
          error?.code === "23505" ? "A folder with that name exists." : "Could not create folder.",
      };
    }
    return { ok: true as const, folder: row };
  });

export const deleteFolder = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) => z.object({ id: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    // Cases inside become unfiled (ON DELETE SET NULL), never deleted.
    const { error } = await context.supabase.from("case_folders").delete().eq("id", data.id);
    return error
      ? { ok: false as const, error: "Could not delete folder." }
      : { ok: true as const };
  });

export const moveInvestigation = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({ id: z.string().uuid(), folderId: z.string().uuid().nullable() }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { error } = await context.supabase
      .from("investigations")
      .update({ folder_id: data.folderId })
      .eq("id", data.id);
    return error
      ? { ok: false as const, error: "Could not move this case." }
      : { ok: true as const };
  });
