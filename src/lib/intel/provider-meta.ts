// Client-safe presentation metadata for the MVP intelligence sources.

import type { ProviderStatusKind } from "./types";

export interface ProviderMeta {
  id: string;
  name: string;
  kind: "reputation" | "infrastructure";
  keyed: boolean;
  description: string;
}

export const PROVIDER_META: ProviderMeta[] = [
  {
    id: "virustotal",
    name: "VirusTotal",
    kind: "reputation",
    keyed: true,
    description: "Multi-engine reputation for IPs, domains, URLs and file hashes.",
  },
  {
    id: "abuseipdb",
    name: "AbuseIPDB",
    kind: "reputation",
    keyed: true,
    description: "Community abuse reports and confidence score for IP addresses.",
  },
  {
    id: "urlscan",
    name: "urlscan.io",
    kind: "reputation",
    keyed: true,
    description: "Historical scans and verdicts for URLs and domains.",
  },
  {
    id: "urlhaus",
    name: "abuse.ch URLhaus",
    kind: "reputation",
    keyed: true,
    description: "Live database of active malware and phishing URLs.",
  },
  {
    id: "heuristics",
    name: "URL heuristics",
    kind: "infrastructure",
    keyed: false,
    description: "High-abuse TLDs, random domains and token paths.",
  },
  {
    id: "hunter",
    name: "Hunter.io",
    kind: "infrastructure",
    keyed: true,
    description: "Privacy-safe organization profile, email pattern and aggregate counts.",
  },
  {
    id: "dns",
    name: "DNS",
    kind: "infrastructure",
    keyed: false,
    description: "DNS-over-HTTPS resolution: A, AAAA, MX, NS, TXT, CNAME.",
  },
  {
    id: "rdap",
    name: "RDAP / WHOIS",
    kind: "infrastructure",
    keyed: false,
    description: "Registration dates, registrar and domain status.",
  },
  {
    id: "geoip",
    name: "GeoIP / ASN",
    kind: "infrastructure",
    keyed: false,
    description: "Network ownership, ASN and geolocation for IP addresses.",
  },
  {
    id: "shodan",
    name: "Shodan InternetDB",
    kind: "infrastructure",
    keyed: false,
    description: "Open ports, service fingerprints and known CVEs from Shodan scans.",
  },
  {
    id: "censys",
    name: "Censys",
    kind: "infrastructure",
    keyed: true,
    description: "Exposed services, software versions and host labels from Censys scans.",
  },
  {
    id: "vt_relations",
    name: "VirusTotal relations",
    kind: "infrastructure",
    keyed: true,
    description: "Other domains seen on the same IP and files that contact it.",
  },
];

const BY_ID = new Map(PROVIDER_META.map((p) => [p.id, p]));

export function providerName(id: string): string {
  return BY_ID.get(id)?.name ?? id;
}

export const PROVIDER_STATUS_LABEL: Record<ProviderStatusKind, string> = {
  completed: "COMPLETED",
  failed: "FAILED",
  not_configured: "NOT CONFIGURED",
  not_applicable: "NOT APPLICABLE",
  rate_limited: "QUOTA PAUSED",
};
