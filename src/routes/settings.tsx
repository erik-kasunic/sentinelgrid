import { createFileRoute } from "@tanstack/react-router";

import { AppShell } from "@/components/sg/app-shell";
import { Panel, TerminalLabel } from "@/components/sg/chrome";

export const Route = createFileRoute("/settings")({
  head: () => ({
    meta: [
      { title: "Settings — SentinelGrid" },
      { name: "description", content: "SentinelGrid intelligence sources and scoring model." },
      { property: "og:title", content: "Settings — SentinelGrid" },
      { property: "og:description", content: "Intelligence sources and scoring model overview." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: SettingsPage,
});

const SOURCES = [
  { name: "DNS records", key: false, note: "Resolves A, AAAA, MX, NS, TXT and CNAME records." },
  { name: "RDAP registration", key: false, note: "Domain age, registrar, status and nameservers." },
  { name: "GeoIP / ASN", key: false, note: "IP geolocation, ASN, ISP and organization." },
  {
    name: "VirusTotal",
    key: true,
    note: "Multi-engine reputation for IPs, domains, URLs and hashes.",
  },
  { name: "AbuseIPDB", key: true, note: "Community abuse reports and confidence score for IPs." },
  { name: "urlscan.io", key: true, note: "Historical scans and verdicts for URLs and domains." },
  {
    name: "Hunter.io",
    key: true,
    note: "Organization profile, email pattern and aggregate counts without exposing addresses.",
  },
];

function SettingsPage() {
  return (
    <AppShell>
      <TerminalLabel>Configuration</TerminalLabel>
      <h1 className="mt-3 mb-6 font-mono text-2xl text-foreground">Settings</h1>

      <div className="space-y-6">
        <Panel title="Intelligence sources">
          <ul className="space-y-3">
            {SOURCES.map((source) => (
              <li
                key={source.name}
                className="flex flex-wrap items-baseline justify-between gap-2 border-b border-border/50 pb-3 last:border-0 last:pb-0"
              >
                <div>
                  <span className="font-mono text-sm text-foreground">{source.name}</span>
                  <p className="mt-0.5 text-xs text-muted-foreground">{source.note}</p>
                </div>
                <span className="font-mono text-[0.625rem] tracking-[0.14em] text-muted-foreground uppercase">
                  {source.key ? "requires API key" : "no key required"}
                </span>
              </li>
            ))}
          </ul>
          <p className="mt-4 border-t border-border/60 pt-4 text-xs text-muted-foreground">
            Sources without a configured key report{" "}
            <span className="font-mono">not_configured</span> and never block an investigation. Keys
            are managed server-side by the deployment administrator and are never exposed to the
            browser.
          </p>
        </Panel>

        <Panel title="Scoring model">
          <ul className="space-y-1.5 font-mono text-xs text-muted-foreground">
            <li>VirusTotal reputation — up to 40 points</li>
            <li>AbuseIPDB confidence — up to 25 points</li>
            <li>Known malicious indicator — up to 20 points</li>
            <li>Infrastructure signals — up to 10 points</li>
            <li>Other evidence — up to 5 points</li>
          </ul>
          <p className="mt-4 text-xs text-muted-foreground">
            Scores are deterministic and fully explained in each investigation. The AI assessment
            can explain evidence but can never change the score. When no reputation source answers,
            the verdict is UNKNOWN — which is not the same as safe.
          </p>
        </Panel>
      </div>
    </AppShell>
  );
}
