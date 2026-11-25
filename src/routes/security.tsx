import { createFileRoute } from "@tanstack/react-router";

import { AppShell } from "@/components/sg/app-shell";
import { Panel, TerminalLabel } from "@/components/sg/chrome";

export const Route = createFileRoute("/security")({
  head: () => ({
    meta: [
      { title: "Security & abuse protection — SentinelGrid" },
      {
        name: "description",
        content: "How SentinelGrid protects quotas, keys and privacy: passive intelligence only.",
      },
      { property: "og:title", content: "Security & abuse protection — SentinelGrid" },
      {
        property: "og:description",
        content: "Passive intelligence only, rate limits, bot checks and key handling.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: SecurityPage,
});

const ITEMS = [
  [
    "Passive intelligence only",
    "SentinelGrid never contacts the targets you paste. Indicators are only sent as parameters to known intelligence providers. Redirect chains come from what VirusTotal and urlscan.io already recorded; if they have none you see “no redirect data”.",
  ],
  [
    "No internal targets",
    "Private, reserved, loopback and link-local addresses and internal hostnames are rejected.",
  ],
  [
    "Bot check + rate limits",
    "Every search passes a Cloudflare Turnstile check. Each visitor gets 10 lookups per hour and 3 forced refreshes per hour.",
  ],
  [
    "Shared cache",
    "Results are reused for a while (IP 6 h, domain 12 h, URL 1 h, hash 24 h) so repeated searches use no provider quota.",
  ],
  [
    "Quota circuit breaker",
    "When a provider reaches 80 % of its free daily quota it is paused and the report shows degraded mode.",
  ],
  [
    "Key handling",
    "Provider keys live only on the server. Your own VirusTotal key, if used, stays in this tab's memory and is never saved or logged.",
  ],
  [
    "Privacy",
    "Your IP is stored only as a salted hash for rate limiting. Saved cases are visible only to you.",
  ],
] as const;

function SecurityPage() {
  return (
    <AppShell>
      <div className="mx-auto max-w-3xl space-y-6">
        <div>
          <TerminalLabel>Security</TerminalLabel>
          <h1 className="mt-2 font-mono text-2xl text-foreground">Abuse protection & privacy</h1>
        </div>
        <Panel title="Protections">
          <ul className="space-y-4">
            {ITEMS.map(([t, d]) => (
              <li key={t}>
                <p className="font-mono text-sm text-foreground">{t}</p>
                <p className="mt-1 text-sm text-muted-foreground">{d}</p>
              </li>
            ))}
          </ul>
        </Panel>
      </div>
    </AppShell>
  );
}
