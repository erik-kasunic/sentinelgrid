# SentinelGrid

**A threat investigation platform for SOC analysts.** Paste an IP, domain, URL or file hash. SentinelGrid enriches it from multiple threat intelligence sources, correlates the findings and returns an explainable risk score with recommended next steps.

**Live:** https://sentinelgrid.erikkasunic.workers.dev

### Try it

Paste one of these into the live app. SentinelGrid never contacts the target, so investigating them is safe.

| Indicator                                                          | Type    | What it is                                                                                                                                                                            |
| ------------------------------------------------------------------ | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `8.8.8.8`                                                          | IP      | **Benign.** Google Public DNS. Expect SAFE.                                                                                                                                           |
| `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` | SHA-256 | **Malicious (test).** The [EICAR](https://www.eicar.org/download-anti-malware-testfile/) anti-malware test file, the industry standard sample that antivirus engines flag on purpose. |
| `http://malware.wicar.org/data/eicar.com`                          | URL     | **Malicious (test).** [WICAR](https://www.wicar.org/), a test site built to trigger web security tools. Expect HIGH.                                                                  |

> **Warning:** the URL is listed as malicious by security vendors. Investigate it in SentinelGrid only. Do not open it in a browser.

VirusTotal tells you what is known about an indicator. SentinelGrid turns scattered intelligence into an investigation: evidence, relationships, a verdict and what to do next.

## Features

- **Auto-detecting input**: IPs, domains, URLs and SHA-256/SHA-1/MD5 hashes. Messy free text is reduced to one indicator.
- **Parallel enrichment** from 10 intelligence sources plus local heuristics, with automatic pivoting (a domain resolves to its IP, so IP-only sources run too).
- **Deterministic risk score (0-100)** with a line-by-line breakdown. The same evidence always gives the same score.
- **Relationship graph** linking domains, IPs, ASNs and file hashes.
- **Geolocation map** and infrastructure details: ASN, WHOIS/RDAP, DNS, open ports.
- **AI analyst summary** that explains the evidence in plain language. It never changes the score.
- **Case management**: signed-in users get every investigation saved as a case, organized in folders.
- **PDF incident reports** for handing off findings.
- **Local-only tools**: file hashing and image EXIF/GPS extraction run in the browser. Files never leave the device.

## How an investigation works

```text
input -> classify -> normalize -> extract IOCs -> parallel enrichment -> correlate
      -> deterministic score -> evidence -> AI assessment -> recommendations
```

### Intelligence sources

| Category       | Sources                                                                                        |
| -------------- | ---------------------------------------------------------------------------------------------- |
| Reputation     | VirusTotal, AbuseIPDB, URLhaus, urlscan.io                                                     |
| Infrastructure | DNS over HTTPS, RDAP/WHOIS, GeoIP                                                              |
| Exposure       | Shodan InternetDB, Censys                                                                      |
| Organization   | Hunter.io (aggregate data only, no individual addresses)                                       |
| Heuristics     | High-abuse TLDs, random-looking domains, raw IP hosts, non-standard ports, dropper-style paths |

### Scoring

Each category contributes a capped number of points, so no single source can dominate:

| Signal                | Max points |
| --------------------- | ---------- |
| VirusTotal detections | 40         |
| AbuseIPDB reports     | 25         |
| Heuristics            | 25         |
| Known-malicious feeds | 20         |
| Infrastructure        | 10         |
| Other                 | 5          |

Verdicts: `safe` (0-19), `low` (20-39), `medium` (40-59), `high` (60-79), `critical` (80-100). Open ports are shown as evidence but never raise the score, since an open port is not proof of malicious intent.

`UNKNOWN` is a separate state, never merged with `safe`. It means there was not enough evidence to judge, for example when every provider failed or none covers that indicator type. Providers report `completed`, `not_configured` or `failed`, and a failed provider never blocks the investigation or adds to the score.

## Security by design

The platform is built to be safe to expose publicly. Full details in [THREAT_MODEL.md](THREAT_MODEL.md).

- **Passive intelligence only.** The backend never connects to a user-supplied target, so it cannot be abused as an SSRF or reconnaissance proxy.
- **Input validation.** Private, loopback, link-local and internal addresses are rejected.
- **Abuse protection.** Cloudflare Turnstile, per-IP rate limits (IPs stored only as salted SHA-256), a shared result cache and per-provider daily budgets.
- **Secrets stay on the server.** API keys are read only in server-side modules. An analyst's own VirusTotal key is held in browser memory and never stored.
- **Row Level Security** on every database table. Cache and rate-limit tables are server-only.
- **Security headers**: CSP, `frame-ancestors 'none'`, `X-Content-Type-Options`, `Referrer-Policy`.

## Tech stack

| Layer         | Technology                                                                         |
| ------------- | ---------------------------------------------------------------------------------- |
| Frontend      | React 19, TypeScript, TanStack Router/Start, Tailwind CSS, shadcn/ui               |
| Visualization | Recharts, D3 (geo), TopoJSON                                                       |
| Backend       | TanStack Start server functions on Cloudflare Workers, Supabase (PostgreSQL, Auth) |
| Data          | Drizzle ORM, SQL migrations                                                        |
| AI            | Groq (LLM) for summaries and free-text extraction                                  |
| Reports       | jsPDF                                                                              |

## Getting started

```bash
git clone https://github.com/erik-kasunic/sentinelgrid.git
cd sentinelgrid
npm install
# set the environment variables below, then:
npm run dev
```

Checks (the same ones CI runs on every push):

```bash
npm run lint
npm run typecheck
npm test        # scoring engine unit tests
npm run build
```

Server-side environment variables. Providers without a key are skipped and marked `not_configured`. DNS, RDAP, GeoIP and Shodan InternetDB need no key.

| Variable                                                                     | Used for                            |
| ---------------------------------------------------------------------------- | ----------------------------------- |
| `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_SERVICE_ROLE_KEY`      | Database and auth (server)          |
| `VITE_SUPABASE_URL`, `VITE_SUPABASE_PUBLISHABLE_KEY`                         | Database and auth (browser)         |
| `DATABASE_URL`                                                               | Running Drizzle migrations          |
| `VIRUSTOTAL_API_KEY`                                                         | File, URL, domain and IP reputation |
| `ABUSEIPDB_API_KEY`                                                          | IP abuse reports                    |
| `GROQ_API_KEY`                                                               | AI summary                          |
| `TURNSTILE_SECRET_KEY`, `RATE_LIMIT_SALT`                                    | Bot protection and rate limiting    |
| `URLSCAN_API_KEY`, `URLHAUS_AUTH_KEY`, `CENSYS_API_SECRET`, `HUNTER_API_KEY` | Optional enrichment                 |

## Project structure

```text
src/
  lib/intel/            investigation engine
    pipeline.server.ts  orchestrates an investigation
    score.server.ts     deterministic scoring
    correlate.server.ts relationships and recommendations
    guard.server.ts     rate limits, cache, budgets
    providers/          one module per intelligence source
  routes/               pages (investigate, cases, reports, metadata, settings)
  components/sg/        investigation UI panels
supabase/migrations/    database schema with RLS
docs/DESIGN.md          design decisions and reasoning
```

## Roadmap

- [ ] Sigma rule suggestions from investigation results
- [ ] MITRE ATT&CK mapping of findings
- [ ] Integration with my [Wazuh homelab](https://github.com/erik-kasunic) for alert enrichment

## Disclaimer

Built for education and defensive security. Scores are assessments based on third-party data, not proof. Always verify before acting.

## Author

**Erik Kasunić**, cybersecurity student at IT-Högskolan (ITHS). [GitHub profile](https://github.com/erik-kasunic)
