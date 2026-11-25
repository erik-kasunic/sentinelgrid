# SentinelGrid threat model

## Principle: passive intelligence only

The backend **never contacts user-supplied targets** (no fetch, crawl or connect to a pasted URL, domain or IP).
Indicators are only passed as parameters to known provider APIs (VirusTotal, AbuseIPDB, urlscan.io search,
URLhaus, RDAP, DNS-over-HTTPS, GeoIP, Hunter). Redirect chains come from what VirusTotal and urlscan.io already
recorded; when they have none, the report says "no redirect data" — there is no fallback fetch.

## Assets

- Provider API keys (server secrets only)
- Provider quotas (VirusTotal ~500/day, 4/min; AbuseIPDB ~1000/day; Hunter; Groq)
- Saved cases of signed-in analysts
- Visitor IP addresses

## Threat actors

Anonymous automated clients, quota-draining bots, attackers trying to use the app as a proxy, curious users probing internals.

## Abuse scenarios and mitigations

| Scenario                 | Mitigation                                                                                                                                                                                                                                                                             |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Quota drain              | Cloudflare Turnstile verified server-side before any lookup; 10 lookups/hour per IP, 3 force-refreshes/hour; shared cache (IP 6 h, domain 12 h, URL 1 h, hash 24 h); per-provider daily budget — at 80 % the provider is skipped ("degraded mode"); VirusTotal 4/min with one back-off |
| SSRF                     | No backend contact with targets; private, reserved, loopback and link-local IPs and internal hostnames are rejected at input                                                                                                                                                           |
| Recon proxy              | Same as SSRF — the app cannot be used to reach or scan hosts                                                                                                                                                                                                                           |
| Data leakage             | Per-user RLS on cases; cache, rate and usage tables have RLS with no client policies (server only); IPs stored only as salted SHA-256                                                                                                                                                  |
| Key exposure             | Keys read only in server modules; analyst's own VT key held in browser memory only, never stored or logged, never cached                                                                                                                                                               |
| Clickjacking / injection | CSP, frame-ancestors none, X-Content-Type-Options, Referrer-Policy                                                                                                                                                                                                                     |

## Residual risks

- Rotating IPs can still spend up to 10 lookups/hour each; Turnstile raises the cost.
- Approximate registrable-domain detection (no full public-suffix list).
- Provider data may be stale; scores are assessments, not truth.
