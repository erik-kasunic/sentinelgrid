// Input classification + canonicalisation. Client-safe: the terminal uses it for
// live "DETECTED:" feedback, and the server re-runs it before enrichment.

import type { HashKind, Ioc, TargetType } from "./types";

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6 = /^(([0-9a-f]{1,4}:){1,7}|:)((:[0-9a-f]{1,4}){1,7}|:)$/i;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const MD5 = /^[a-f0-9]{32}$/i;
const SHA1 = /^[a-f0-9]{40}$/i;
const SHA256 = /^[a-f0-9]{64}$/i;

export interface Classification {
  type: TargetType | null;
  /** Human label shown in the terminal, e.g. "IPv4" or "SHA256". */
  label: string;
  /** Canonical form used for lookups. */
  canonical: string;
  hashKind?: HashKind;
  reason?: string;
}

export function classify(raw: string): Classification {
  const input = raw.trim();
  if (!input) return { type: null, label: "", canonical: "" };

  if (IPV4.test(input)) return { type: "ip", label: "IPv4", canonical: input };
  if (IPV6.test(input)) return { type: "ip", label: "IPv6", canonical: input.toLowerCase() };

  if (MD5.test(input))
    return { type: "hash", label: "MD5", canonical: input.toLowerCase(), hashKind: "md5" };
  if (SHA1.test(input))
    return { type: "hash", label: "SHA1", canonical: input.toLowerCase(), hashKind: "sha1" };
  if (SHA256.test(input))
    return { type: "hash", label: "SHA256", canonical: input.toLowerCase(), hashKind: "sha256" };

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(input) || input.startsWith("//")) {
    const url = safeUrl(input);
    if (url) return { type: "url", label: "URL", canonical: url.toString() };
  }

  // A bare host with a path is a URL; a bare host alone is a domain.
  if (/^[^\s/]+\/\S*$/.test(input)) {
    const url = safeUrl(`http://${input}`);
    if (url && DOMAIN.test(url.hostname)) {
      return { type: "url", label: "URL", canonical: url.toString() };
    }
  }

  const host = input.replace(/\.$/, "");
  if (DOMAIN.test(host)) return { type: "domain", label: "DOMAIN", canonical: host.toLowerCase() };

  return {
    type: null,
    label: "UNRECOGNISED",
    canonical: input,
    reason: "Not a valid IP, domain, URL or MD5/SHA1/SHA256 hash.",
  };
}

/** Applies a user's manual type override, canonicalising for that type. */
export function classifyAs(raw: string, type: TargetType): Classification {
  const auto = classify(raw);
  if (auto.type === type) return auto;
  const input = raw.trim();
  switch (type) {
    case "ip":
      return { type: "ip", label: IPV6.test(input) ? "IPv6" : "IPv4", canonical: input };
    case "domain":
      return { type: "domain", label: "DOMAIN", canonical: hostOf(input) ?? input.toLowerCase() };
    case "url": {
      const url = safeUrl(/:\/\//.test(input) ? input : `http://${input}`);
      return { type: "url", label: "URL", canonical: url ? url.toString() : input };
    }
    case "hash":
      return {
        type: "hash",
        label: SHA256.test(input) ? "SHA256" : SHA1.test(input) ? "SHA1" : "MD5",
        canonical: input.toLowerCase(),
        hashKind: SHA256.test(input) ? "sha256" : SHA1.test(input) ? "sha1" : "md5",
      };
  }
}

export function safeUrl(value: string): URL | null {
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    return url;
  } catch {
    return null;
  }
}

export function hostOf(value: string): string | null {
  const url = safeUrl(/:\/\//.test(value) ? value : `http://${value}`);
  if (!url) return null;
  return url.hostname.toLowerCase();
}

export function isIpLiteral(value: string): boolean {
  return IPV4.test(value) || IPV6.test(value);
}

/**
 * Derives the indicator set from one target: a URL also yields its domain (and
 * its host IP when the URL points straight at one). Everything else yields
 * itself. MVP scope — no free-text IOC extraction.
 */
export function extractIocs(canonical: string, type: TargetType): Ioc[] {
  const iocs: Ioc[] = [{ value: canonical, type, primary: true }];
  if (type === "url") {
    const host = hostOf(canonical);
    if (host && !isIpLiteral(host)) iocs.push({ value: host, type: "domain", primary: false });
    if (host && isIpLiteral(host)) iocs.push({ value: host, type: "ip", primary: false });
  }
  return iocs;
}

export const HASH_KIND_LABEL: Record<HashKind, string> = {
  md5: "MD5",
  sha1: "SHA1",
  sha256: "SHA256",
};

/** Private, reserved, loopback and link-local ranges (v4 + v6). */
export function isPrivateIp(value: string): boolean {
  const ip = value.toLowerCase().replace(/^\[|\]$/g, "");
  if (IPV4.test(ip)) {
    const [a, b] = ip.split(".").map(Number) as [number, number];
    return (
      a === 10 ||
      a === 127 ||
      a === 0 ||
      a >= 224 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  if (ip.includes(":")) {
    return (
      ip === "::1" ||
      ip === "::" ||
      /^f[cd]/.test(ip) ||
      /^fe[89ab]/.test(ip) ||
      ip.startsWith("::ffff:")
    );
  }
  return false;
}

const INTERNAL_HOST = /(^localhost$|\.localhost$|\.local$|\.internal$|\.lan$|\.home\.arpa$)/i;

/** Strict per-type validation. Returns an error message or null when valid. */
export function validateClassified(c: Classification): string | null {
  if (!c.type) return c.reason ?? "Unrecognised input.";
  const v = c.canonical;
  switch (c.type) {
    case "ip":
      if (!(IPV4.test(v) || IPV6.test(v))) return "Not a valid IPv4 or IPv6 address.";
      if (isPrivateIp(v)) return "Private, reserved or loopback addresses cannot be investigated.";
      return null;
    case "domain":
      if (v.length > 253 || !DOMAIN.test(v)) return "Not a valid domain (max 253 characters).";
      if (INTERNAL_HOST.test(v)) return "Internal hostnames cannot be investigated.";
      return null;
    case "url": {
      if (v.length > 2048) return "URL is too long (max 2048 characters).";
      const url = safeUrl(v);
      if (!url) return "Only http(s) URLs can be investigated.";
      const host = url.hostname.replace(/^\[|\]$/g, "");
      if (isIpLiteral(host) ? isPrivateIp(host) : !DOMAIN.test(host) || INTERNAL_HOST.test(host))
        return "URLs pointing at private or internal hosts cannot be investigated.";
      return null;
    }
    case "hash":
      if (!(MD5.test(v) || SHA1.test(v) || SHA256.test(v)))
        return "Hashes must be exactly 32 (MD5), 40 (SHA1) or 64 (SHA256) hex characters.";
      return null;
  }
}
