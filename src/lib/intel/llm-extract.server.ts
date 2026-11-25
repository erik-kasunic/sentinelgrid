// LLM fallback for free-text input: asks Groq to pull ONE indicator out of
// messy pasted text (defanged IOCs, emails, logs). Output is re-validated by
// the deterministic classifier — the LLM never decides the type on its own.
import { classify } from "./classify";

const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";
const GROQ_MODEL = "openai/gpt-oss-120b";

const PROMPT = `You extract exactly one security indicator from user-pasted text.
Valid indicators: IPv4/IPv6 address, domain name, full URL, or file hash (MD5/SHA1/SHA256).
Refang defanged values (hxxp -> http, [.] or (.) -> ., [:] -> :). Prefer a URL over its domain.
If several exist, pick the most suspicious one. Never invent a value not present in the text.
Reply with JSON only: {"indicator": "<value or empty string>"}`;

export async function extractIndicatorWithLlm(text: string) {
  const key = process.env["GROQ_API_KEY"];
  if (!key) return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12_000);
  try {
    const res = await fetch(GROQ_URL, {
      method: "POST",
      signal: controller.signal,
      headers: { "content-type": "application/json", Authorization: `Bearer ${key}` },
      body: JSON.stringify({
        model: GROQ_MODEL,
        response_format: { type: "json_object" },
        messages: [
          { role: "system", content: PROMPT },
          { role: "user", content: text.slice(0, 4000) },
        ],
      }),
    });
    if (!res.ok) {
      console.error("LLM extract failed", res.status, (await res.text()).slice(0, 300));
      return null;
    }
    const payload = (await res.json()) as { choices?: { message?: { content?: string } }[] };
    const raw = payload.choices?.[0]?.message?.content ?? "";
    const indicator = String((JSON.parse(raw) as { indicator?: unknown }).indicator ?? "").trim();
    if (!indicator) return null;
    // Guard against hallucination: value must appear in the input (after refanging).
    const refanged = text
      .replace(/hxxp/gi, "http")
      .replace(/\[\.\]|\(\.\)/g, ".")
      .replace(/\[:\]/g, ":");
    if (!refanged.toLowerCase().includes(indicator.toLowerCase())) return null;
    const detected = classify(indicator);
    return detected.type ? detected : null;
  } catch (error) {
    console.error("LLM extract error", error);
    return null;
  } finally {
    clearTimeout(timer);
  }
}
