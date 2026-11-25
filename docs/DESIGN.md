# Design decisions

The main architecture choices in SentinelGrid and why they were made.

## Security and privacy

- **Passive intelligence only.** The backend never contacts a user-supplied target. Redirect chains come from VirusTotal and urlscan.io data and only score on hops that cross registrable domains. This rules out SSRF and stops the app from being used as a recon proxy.
- **Provider keys stay on the server.** Keys are only read inside `*.server.ts` modules, so they never end up in the browser bundle.
- **User-supplied VirusTotal keys are never stored.** An analyst's own key lives in browser memory only and bypasses the shared cache and budget.
- **Hunter results are reduced to domain-level signals.** Individual email records are discarded to limit personal data.
- **Image metadata is parsed in the browser.** EXIF/GPS extraction on `/metadata` uses exifr client-side, so photos never leave the device, the same as local file hashing.

## Abuse protection

- `investigateTarget` is guarded by `guard.server.ts`: Turnstile, rate limits on salted IP hashes, a cache with per-type TTLs and per-provider daily budgets. All of it lives in tables only the service role can read, so limits hold across instances.
- Providers that share an upstream API declare `budgetKey` and `cost`, so extra pivot calls such as `vt_relations` are charged to the same VirusTotal quota.

## Enrichment and scoring

- Domain and URL targets are resolved to their primary IP before enrichment, so IP-only sources (GeoIP, AbuseIPDB) also run.
- Port and service exposure (Shodan InternetDB, Censys) is shown as evidence but does not change the score. An open port is not proof of malicious activity.
- Free-text input that the classifier can't parse is sent to Groq to extract one indicator. The result must appear in the original input and pass the deterministic classifier, so the model output is never trusted on its own.
- The analyst summary uses Groq with a fallback model, for speed with a backup if the first model fails.

## Cases

- Results for signed-in users are saved once per result. The saved case id is written back into the session result, so a reload never creates a duplicate.

## UI

- Colors are semantic: near-black surfaces, green for actions and healthy status, yellow and red only for real severity. This keeps risk levels readable at a glance.
