// Provider adapter contract. Adding a source later means one new file plus one
// line in registry.server.ts — no UI or scoring changes.

import type {
  Evidence,
  DomainProfileData,
  InfrastructureData,
  Ioc,
  MalwareData,
  Relationship,
  TargetType,
} from "../types";

export interface ProviderContext {
  target: string;
  targetType: TargetType;
  iocs: Ioc[];
  /** Host of a URL target, or the domain itself. Undefined for IP/hash targets. */
  domain?: string | undefined | undefined;
  /** IP being investigated, when the target is an IP. */
  ip?: string | undefined | undefined;
  /** Analyst-supplied VirusTotal key for this request only. Never stored or logged. */
  vtKey?: string | undefined;
}

export interface ProviderOutput {
  evidence?: Evidence[] | undefined;
  relationships?: Relationship[] | undefined;
  infrastructure?: Partial<InfrastructureData> | undefined;
  domainProfile?: Partial<DomainProfileData> | undefined;
  malware?: Partial<MalwareData> | undefined;
  /** Structured signals the deterministic scoring engine reads. */
  signals?: ProviderSignals | undefined;
}

export interface ProviderSignals {
  virustotal?: {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
    total: number;
    reputation?: number | undefined;
    malwareFamilies?: string[] | undefined;
    /** Vendor categories that mark an anonymizer / open proxy (policy risk). */
    proxyCategories?: string[] | undefined;
  };
  abuseipdb?: {
    confidence: number;
    reports: number;
    usageType?: string | undefined;
  };
  knownMalicious?: { source: string; detail: string }[] | undefined;
  heuristics?: {
    riskyTld?: string | undefined;
    shortRandomDomain?: boolean | undefined;
    randomPath?: boolean | undefined;
    rawIpHost?: boolean | undefined;
    nonStandardPort?: number | undefined;
    dropperPath?: string | undefined;
    /** Redirect chain reported by a provider (passive — never fetched by us). */
    redirectChain?: { source: string; hops: string[] } | undefined;
  };
  infrastructure?: {
    domainAgeDays?: number | undefined;
    suspiciousDomainStatus?: string[] | undefined;
    hostingProvider?: boolean | undefined;
    doesNotResolve?: boolean | undefined;
  };
}

export interface Provider {
  /** Stable machine name, e.g. "virustotal". */
  name: string;
  /** Display name shown in the provider checklist. */
  label: string;
  /** Quota bucket to charge (defaults to name). */
  budgetKey?: string;
  /** Upstream calls per run (defaults to 1). */
  cost?: number;
  supports(targetType: TargetType): boolean;
  /** False when the required key is absent -> reported as not_configured. */
  isConfigured(): boolean;
  run(ctx: ProviderContext): Promise<ProviderOutput>;
}
