// Deterministic lexical URL/domain heuristics. No network calls.

import { nowIso } from "../http.server";
import type { Evidence } from "../types";
import type { Provider, ProviderContext, ProviderOutput } from "./provider.server";

/** TLDs with persistently high abuse rates (Spamhaus / Interisle reports). */
export const RISKY_TLDS = new Set([
  "lat",
  "top",
  "xyz",
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "click",
  "buzz",
  "rest",
  "cfd",
  "sbs",
  "icu",
  "monster",
  "bond",
  "quest",
  "zip",
  "mov",
  "cyou",
  "live",
  "shop",
  "online",
  "site",
  "fun",
]);

export const heuristicsProvider: Provider = {
  name: "heuristics",
  label: "URL heuristics",
  supports: (t) => t === "url" || t === "domain",
  isConfigured: () => true,
  async run(ctx: ProviderContext): Promise<ProviderOutput> {
    const host = ctx.domain ?? "";
    const labels = host.split(".");
    const tld = labels[labels.length - 1] ?? "";
    const sld = labels[labels.length - 2] ?? "";
    const riskyTld = RISKY_TLDS.has(tld) ? tld : undefined;
    const shortRandomDomain =
      sld.length > 0 && sld.length <= 5 && /\d/.test(sld) && /[a-z]/.test(sld);

    let randomPath = false;
    let rawIpHost = false;
    let nonStandardPort: number | undefined;
    let dropperPath: string | undefined;
    if (ctx.targetType === "url") {
      const u = new URL(ctx.target);
      const path = u.pathname.replace(/^\/|\/$/g, "");
      randomPath = /^[A-Za-z0-9]{4,10}$/.test(path) && /[A-Z]/.test(path) && /[a-z]/.test(path);
      const hn = u.hostname.replace(/^\[|\]$/g, "");
      rawIpHost = /^\d{1,3}(\.\d{1,3}){3}$/.test(hn) || hn.includes(":");
      const port = u.port ? Number(u.port) : undefined;
      if (port && port > 1024 && ![8080, 8443, 8000, 8888].includes(port)) nonStandardPort = port;
      if (
        /^(i|sh|bin|x86|arm7?|mips|mpsl|bins?\.sh|[a-z0-9]{1,2}|.*\.(sh|exe|bin|elf|dll|ps1|apk|msi|scr))$/i.test(
          path,
        )
      ) {
        dropperPath = "/" + path;
      }
    }

    const evidence: Evidence[] = [];
    const add = (label: string, severity: Evidence["severity"] = "low") =>
      evidence.push({ provider: "URL heuristics", label, severity, observedAt: nowIso() });
    if (riskyTld) add(`High-abuse TLD .${riskyTld}`);
    if (shortRandomDomain) add(`Short random-looking domain label "${sld}"`);
    if (randomPath) add("Short random token path (typical of link shorteners / phishing kits)");
    if (rawIpHost) add("URL uses a raw IP address instead of a domain", "medium");
    if (nonStandardPort) add(`Non-standard high port :${nonStandardPort}`, "medium");
    if (dropperPath && rawIpHost)
      add(`Short payload/dropper-style path ${dropperPath} on raw IP`, "medium");

    return {
      evidence,
      signals: {
        heuristics: {
          riskyTld,
          shortRandomDomain,
          randomPath,
          rawIpHost,
          nonStandardPort,
          dropperPath,
        },
      },
    };
  },
};
