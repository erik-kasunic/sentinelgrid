// AI SOC analyst. Receives ONLY normalized evidence, never raw provider JSON,
// and never influences the numerical score.

import type { AiAssessment, InvestigationResult } from "./types";

const SYSTEM_PROMPT = `You are the SOC analyst assistant inside SentinelGrid, a threat investigation platform.

You receive a normalized evidence bundle produced by SentinelGrid's own deterministic engine.

Hard rules:
- Use ONLY the evidence provided. Never invent detections, reports, dates, malware names, geolocation or provider results.
- The numerical risk score is already calculated deterministically. Do not dispute, recalculate or restate a different number.
- Distinguish facts (what a source reported) from assumptions (what an analyst might infer).
- If a source was not configured or failed, treat that as missing information, not as a clean result.
- "No malicious evidence found" is not proof of safety; say so when the coverage is thin.
- Never claim an indicator is safe when the verdict basis is "insufficient".
- Be concise and operational, in the register of a senior SOC analyst.

Return STRICT JSON with exactly these keys:
{"summary","explanation","simple_explanation","recommended_action","confidence","uncertainties","next_steps"}
- summary: one or two sentences.
- explanation: 2-4 sentences of technical reasoning over the evidence.
- simple_explanation: the same conclusion for a non-technical reader, no jargon.
- recommended_action: one sentence naming the single most useful next action.
- confidence: integer 0-100 describing your confidence in the assessment given the evidence coverage.
- uncertainties: array of short strings.
- next_steps: array of 3-5 short imperative strings.`;

interface GatewayResponse {
  choices?: { message?: { content?: string } }[];
}

function evidenceBundle(result: InvestigationResult) {
  return {
    target: result.target,
    target_type: result.targetType,
    deterministic_score: {
      total: result.riskScore.total,
      band: result.riskScore.band,
      basis: result.riskScore.basis,
      note: result.riskScore.note,
      breakdown: result.riskScore.lines.map((l) => ({ label: l.label, points: l.points })),
    },
    dimensions: result.dimensions.map((d) => ({ name: d.name, state: d.state, note: d.note })),
    evidence: result.evidence.map((e) => ({
      provider: e.provider,
      finding: e.label,
      detail: e.detail,
      severity: e.severity,
      confidence: e.confidence,
      observed_at: e.observedAt,
    })),
    relationships: result.relationships.map((r) => `${r.fromValue} --${r.kind}--> ${r.toValue}`),
    infrastructure: result.infrastructure ?? null,
    domain_profile: result.domainProfile ?? null,
    malware: result.malware ?? null,
    provider_status: result.providerStatus.map((p) => ({
      provider: p.provider,
      status: p.status,
      message: p.message,
    })),
  };
}

function parseAssessment(raw: string): AiAssessment | null {
  const cleaned = raw
    .trim()
    .replace(/^```(?:json)?/i, "")
    .replace(/```$/, "")
    .trim();
  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");
  if (start === -1 || end === -1) return null;
  try {
    const parsed = JSON.parse(cleaned.slice(start, end + 1)) as Partial<AiAssessment>;
    if (!parsed.summary || !parsed.explanation) return null;
    return {
      summary: String(parsed.summary),
      explanation: String(parsed.explanation),
      simple_explanation: String(parsed.simple_explanation ?? parsed.summary),
      recommended_action: String(parsed.recommended_action ?? ""),
      confidence: Math.max(0, Math.min(100, Number(parsed.confidence ?? 0) || 0)),
      uncertainties: Array.isArray(parsed.uncertainties) ? parsed.uncertainties.map(String) : [],
      next_steps: Array.isArray(parsed.next_steps) ? parsed.next_steps.map(String) : [],
    };
  } catch {
    return null;
  }
}

export interface AiOutcome {
  assessment: AiAssessment | null;
  status: "completed" | "failed" | "not_configured";
  message?: string;
}

export async function runAiAnalysis(result: InvestigationResult): Promise<AiOutcome> {
  const groqKey = process.env["GROQ_API_KEY"];
  if (!groqKey)
    return { assessment: null, status: "not_configured", message: "AI analyst key absent" };
  return callModel(result, GROQ_URL, GROQ_MODEL, { Authorization: `Bearer ${groqKey}` });
}

const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";
const GROQ_MODEL = "openai/gpt-oss-120b";

async function callModel(
  result: InvestigationResult,
  url: string,
  model: string,
  authHeaders: Record<string, string>,
): Promise<AiOutcome> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 45_000);
  try {
    const response = await fetch(url, {
      method: "POST",
      signal: controller.signal,
      headers: { "content-type": "application/json", ...authHeaders },
      body: JSON.stringify({
        model,
        response_format: { type: "json_object" },
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          {
            role: "user",
            content: `Assess this SentinelGrid evidence bundle:\n\n${JSON.stringify(
              evidenceBundle(result),
              null,
              2,
            )}`,
          },
        ],
      }),
    });

    if (!response.ok) {
      const body = await response.text();
      console.error("AI gateway error", response.status, body.slice(0, 500));
      const message =
        response.status === 402
          ? "AI analysis is temporarily unavailable — the workspace is out of AI credits."
          : response.status === 429
            ? "AI analysis was rate limited. Try again shortly."
            : `AI analysis failed (status ${response.status}).`;
      return { assessment: null, status: "failed", message };
    }

    const payload = (await response.json()) as GatewayResponse;
    const content = payload.choices?.[0]?.message?.content ?? "";
    const assessment = parseAssessment(content);
    if (!assessment) {
      return {
        assessment: null,
        status: "failed",
        message: "AI returned an unreadable assessment.",
      };
    }
    return { assessment, status: "completed" };
  } catch (error) {
    console.error("AI analysis error", error);
    const aborted = error instanceof Error && error.name === "AbortError";
    return {
      assessment: null,
      status: "failed",
      message: aborted ? "AI analysis timed out." : "AI analysis could not be completed.",
    };
  } finally {
    clearTimeout(timer);
  }
}
