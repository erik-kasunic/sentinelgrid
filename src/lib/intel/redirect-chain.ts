// Pure helpers for provider-reported redirect chains (no network).

const MULTI_PART_SUFFIXES = new Set([
  "co.uk",
  "org.uk",
  "ac.uk",
  "com.au",
  "net.au",
  "co.jp",
  "com.br",
  "co.nz",
  "co.za",
  "com.cn",
  "com.mx",
]);

export function hostOfUrl(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
}

/** Approximate registrable domain (eTLD+1) without a full public-suffix list. */
export function registrableDomain(host: string): string {
  const parts = host
    .toLowerCase()
    .replace(/^www\./, "")
    .split(".");
  if (parts.length <= 2) return parts.join(".");
  const lastTwo = parts.slice(-2).join(".");
  return MULTI_PART_SUFFIXES.has(lastTwo) ? parts.slice(-3).join(".") : lastTwo;
}

/** Final hop host when the chain leaves the starting registrable domain, else null. */
export function crossDomainDestination(hops: string[]): string | null {
  if (hops.length < 2) return null;
  const first = hostOfUrl(hops[0]!);
  const last = hostOfUrl(hops[hops.length - 1]!);
  if (!first || !last) return null;
  return registrableDomain(first) === registrableDomain(last) ? null : last;
}
