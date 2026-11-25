import { heuristicsProvider } from "./heuristics.server";
import { urlhausProvider } from "./urlhaus.server";
import { abuseipdbProvider } from "./abuseipdb.server";
import { dnsProvider } from "./dns.server";
import { geoipProvider } from "./geoip.server";
import { hunterProvider } from "./hunter.server";
import { shodanProvider } from "./shodan.server";
import { censysProvider } from "./censys.server";
import type { Provider } from "./provider.server";
import { rdapProvider } from "./rdap.server";
import { urlscanProvider } from "./urlscan.server";
import { virustotalProvider } from "./virustotal.server";
import { vtRelationsProvider } from "./vt-relations.server";

/** Add a new intelligence source by appending it here. */
export const PROVIDERS: Provider[] = [
  virustotalProvider,
  abuseipdbProvider,
  urlscanProvider,
  urlhausProvider,
  heuristicsProvider,
  hunterProvider,
  dnsProvider,
  rdapProvider,
  geoipProvider,
  shodanProvider,
  censysProvider,
  vtRelationsProvider,
];

/** Providers capable of producing malicious-verdict evidence. */
export const THREAT_PROVIDERS = ["virustotal", "abuseipdb", "urlscan", "urlhaus"];
