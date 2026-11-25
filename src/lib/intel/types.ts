// Normalized internal intelligence types. UI components depend on these only —
// never on a provider's raw response shape.

export type TargetType = "ip" | "domain" | "url" | "hash";

export type HashKind = "md5" | "sha1" | "sha256";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type Verdict = "safe" | "low" | "medium" | "high" | "critical" | "unknown";

/** Why we arrived at the verdict: real evidence, or not enough of it. */
export type VerdictBasis = "evaluated" | "insufficient";

export type ProviderStatusKind =
  "completed" | "failed" | "not_configured" | "not_applicable" | "rate_limited";

export type RelationKind =
  | "resolves_to"
  | "hosted_on"
  | "redirects_to"
  | "associated_with"
  | "detected_by"
  | "related_to"
  | "belongs_to";

export interface Ioc {
  value: string;
  type: TargetType;
  primary: boolean;
}

export interface Evidence {
  provider: string;
  label: string;
  detail?: string | undefined;
  severity: Severity;
  /** 0-100 where the provider reports one. */
  confidence?: number | undefined;
  sourceUrl?: string | undefined;
  observedAt?: string | undefined;
  /** Additional links, e.g. each vendor's own site for cross-checking a classification. */
  links?: { label: string; url: string }[] | undefined;
}

export interface Relationship {
  fromValue: string;
  fromType: string;
  toValue: string;
  toType: string;
  kind: RelationKind;
  /** True when the source flagged the target node as malicious. */
  flagged?: boolean | undefined;
  /** Intelligence source that reported this link (set by the pipeline). */
  source?: string | undefined;
  /** When the source reported it (ISO). */
  observedAt?: string | undefined;
}

export interface ProviderStatus {
  provider: string;
  status: ProviderStatusKind;
  message?: string | undefined;
  durationMs?: number | undefined;
}

export type ScoreCategory =
  "virustotal" | "abuseipdb" | "known_malicious" | "infrastructure" | "heuristics" | "other";

export interface ScoreLine {
  category: ScoreCategory;
  label: string;
  points: number;
  max: number;
}

export interface RiskScore {
  total: number;
  max: 100;
  band: Verdict;
  basis: VerdictBasis;
  lines: ScoreLine[];
  /** Explains an insufficient basis, e.g. no threat provider answered. */
  note?: string | undefined;
}

export interface Dimension {
  name: string;
  state: Verdict | "not_applicable";
  note: string;
}

export interface InfrastructureData {
  asn?: string | undefined;
  isp?: string | undefined;
  organization?: string | undefined;
  country?: string | undefined;
  region?: string | undefined;
  city?: string | undefined;
  latitude?: number | undefined;
  longitude?: number | undefined;
  usageType?: string | undefined;
  registrar?: string | undefined;
  createdDate?: string | undefined;
  updatedDate?: string | undefined;
  expiresDate?: string | undefined;
  domainStatus?: string[] | undefined;
  nameservers?: string[] | undefined;
  dnsRecords?: { type: string; value: string }[] | undefined;
}

/** Privacy-minimized organization signals. Never contains individual email addresses. */
export interface DomainProfileData {
  organization?: string | undefined;
  emailPattern?: string | undefined;
  emailCount?: number | undefined;
  personalEmailCount?: number | undefined;
  genericEmailCount?: number | undefined;
  acceptAll?: boolean | undefined;
  disposable?: boolean | undefined;
  webmail?: boolean | undefined;
}

export interface MalwareData {
  families: string[];
  fileType?: string | undefined;
  fileSize?: number | undefined;
  tags: string[];
  firstSeen?: string | undefined;
}

export interface Recommendation {
  step: number;
  text: string;
  rationale?: string | undefined;
}

export interface AiAssessment {
  summary: string;
  explanation: string;
  simple_explanation: string;
  recommended_action: string;
  confidence: number;
  uncertainties: string[];
  next_steps: string[];
}

export interface InvestigationResult {
  id: string;
  target: string;
  targetType: TargetType;
  createdAt: string;
  iocs: Ioc[];
  riskScore: RiskScore;
  verdict: Verdict;
  verdictBasis: VerdictBasis;
  dimensions: Dimension[];
  evidence: Evidence[];
  relationships: Relationship[];
  infrastructure?: InfrastructureData | undefined;
  domainProfile?: DomainProfileData | undefined;
  malware?: MalwareData | undefined;
  recommendations: Recommendation[];
  providerStatus: ProviderStatus[];
  /** Providers skipped because the shared free quota is nearly spent. */
  degradedProviders?: string[] | undefined;
  /** Set when the result came from the shared cache. */
  cachedAt?: string | undefined;
  ai?: AiAssessment | null | undefined;
  aiStatus: ProviderStatus;
  saved?: boolean | undefined;
  /** Case id after a session-only result was saved. */
  savedCaseId?: string | undefined;
  title?: string | undefined;
}

export const VERDICT_LABEL: Record<Verdict, string> = {
  safe: "SAFE",
  low: "LOW",
  medium: "MEDIUM",
  high: "HIGH",
  critical: "CRITICAL",
  unknown: "UNKNOWN",
};

export const TARGET_TYPE_LABEL: Record<TargetType, string> = {
  ip: "IP ADDRESS",
  domain: "DOMAIN",
  url: "URL",
  hash: "FILE HASH",
};
