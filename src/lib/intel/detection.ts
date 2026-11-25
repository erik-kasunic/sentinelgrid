import type { InvestigationResult, TargetType } from "./types";

export type SiemPlatform = "sentinel" | "splunk" | "elastic" | "crowdstrike" | "sigma" | "suricata";

export const SIEM_LABEL: Record<SiemPlatform, string> = {
  sentinel: "Microsoft Sentinel (KQL)",
  splunk: "Splunk (SPL)",
  elastic: "Elastic (KQL)",
  crowdstrike: "CrowdStrike Falcon (FQL)",
  sigma: "Sigma rule",
  suricata: "Suricata rules",
};

export interface IocSet {
  ips: string[];
  domains: string[];
  urls: string[];
  hashes: string[];
}

const PRIVATE = /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;

/** Collect IOCs found in the case. Only flagged related nodes are included besides the primary target. */
export function collectIocs(r: InvestigationResult, includeUnflagged = false): IocSet {
  const set: Record<TargetType, Set<string>> = {
    ip: new Set(),
    domain: new Set(),
    url: new Set(),
    hash: new Set(),
  };
  const add = (type: string, v: string) => {
    const t = type as TargetType;
    if (!set[t] || !v) return;
    if (t === "ip" && PRIVATE.test(v)) return;
    set[t].add(t === "hash" ? v.toLowerCase() : v);
  };
  for (const i of r.iocs) if (i.primary || includeUnflagged) add(i.type, i.value);
  add(r.targetType, r.target);
  for (const rel of r.relationships) {
    if (rel.flagged || includeUnflagged) add(rel.toType, rel.toValue);
  }
  return { ips: [...set.ip], domains: [...set.domain], urls: [...set.url], hashes: [...set.hash] };
}

const q = (s: string) => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
const list = (a: string[]) => a.map(q).join(", ");
const empty = (s: IocSet) =>
  !s.ips.length && !s.domains.length && !s.urls.length && !s.hashes.length;

function header(r: InvestigationResult, c = "//") {
  return `${c} SentinelGrid — case ${r.title ?? r.target}\n${c} Verdict ${r.verdict.toUpperCase()} · score ${r.riskScore.total}/100 · generated ${new Date().toISOString()}\n`;
}

export function buildQuery(p: SiemPlatform, r: InvestigationResult, s: IocSet): string {
  if (empty(s)) return "No indicators to hunt for in this case.";
  switch (p) {
    case "sentinel": {
      const parts: string[] = [];
      if (s.ips.length)
        parts.push(
          `let iocIps = dynamic([${list(s.ips)}]);\nunion isfuzzy=true\n  (CommonSecurityLog | where DestinationIP in (iocIps) or SourceIP in (iocIps)),\n  (DeviceNetworkEvents | where RemoteIP in (iocIps)),\n  (SigninLogs | where IPAddress in (iocIps))\n| project TimeGenerated, Type, Computer, DeviceName, SourceIP, DestinationIP, RemoteIP, IPAddress`,
        );
      if (s.domains.length)
        parts.push(
          `let iocDomains = dynamic([${list(s.domains)}]);\nunion isfuzzy=true\n  (DnsEvents | where Name has_any (iocDomains)),\n  (DeviceNetworkEvents | where RemoteUrl has_any (iocDomains))\n| project TimeGenerated, Type, Computer, DeviceName, Name, RemoteUrl`,
        );
      if (s.urls.length)
        parts.push(
          `let iocUrls = dynamic([${list(s.urls)}]);\nDeviceNetworkEvents\n| where RemoteUrl in~ (iocUrls)\n| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteUrl`,
        );
      if (s.hashes.length)
        parts.push(
          `let iocHashes = dynamic([${list(s.hashes)}]);\nDeviceFileEvents\n| where SHA256 in~ (iocHashes) or SHA1 in~ (iocHashes) or MD5 in~ (iocHashes)\n| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256`,
        );
      return header(r) + parts.join("\n\n");
    }
    case "splunk": {
      const parts: string[] = [];
      if (s.ips.length)
        parts.push(
          `index=* (${s.ips.map((i) => `src_ip=${q(i)} OR dest_ip=${q(i)}`).join(" OR ")})\n| stats count min(_time) as first max(_time) as last by src_ip, dest_ip, sourcetype`,
        );
      if (s.domains.length)
        parts.push(
          `index=* (${s.domains.map((d) => `query=*${d}* OR url=*${d}*`).join(" OR ")})\n| stats count by src_ip, query, url, sourcetype`,
        );
      if (s.urls.length)
        parts.push(
          `index=* (${s.urls.map((u) => `url=${q(u)}`).join(" OR ")})\n| stats count by src_ip, url, sourcetype`,
        );
      if (s.hashes.length)
        parts.push(
          `index=* (${s.hashes.map((h) => `file_hash=${q(h)} OR sha256=${q(h)} OR md5=${q(h)}`).join(" OR ")})\n| stats count by host, file_name, file_hash`,
        );
      return (
        `\`\`\` SentinelGrid case ${r.title ?? r.target} · verdict ${r.verdict} · ${r.riskScore.total}/100 \`\`\`\n` +
        parts.join("\n\n")
      );
    }
    case "elastic": {
      const parts: string[] = [];
      if (s.ips.length)
        parts.push(
          `source.ip : (${s.ips.join(" or ")}) or destination.ip : (${s.ips.join(" or ")})`,
        );
      if (s.domains.length)
        parts.push(
          `dns.question.name : (${s.domains.map(q).join(" or ")}) or url.domain : (${s.domains.map(q).join(" or ")})`,
        );
      if (s.urls.length) parts.push(`url.full : (${s.urls.map(q).join(" or ")})`);
      if (s.hashes.length)
        parts.push(
          `file.hash.sha256 : (${s.hashes.map(q).join(" or ")}) or file.hash.md5 : (${s.hashes.map(q).join(" or ")})`,
        );
      return parts.join("\nor\n");
    }
    case "crowdstrike": {
      const parts: string[] = [];
      if (s.ips.length)
        parts.push(
          `#event_simpleName=NetworkConnectIP4 RemoteAddressIP4=/^(${s.ips.map((i) => i.replace(/\./g, "\\.")).join("|")})$/`,
        );
      if (s.domains.length)
        parts.push(
          `#event_simpleName=DnsRequest DomainName=/(${s.domains.map((d) => d.replace(/\./g, "\\.")).join("|")})$/i`,
        );
      if (s.hashes.length)
        parts.push(`#event_simpleName=ProcessRollup2 SHA256HashData=/^(${s.hashes.join("|")})$/i`);
      return parts.length
        ? parts.join("\n\n")
        : "No Falcon-compatible indicators (URLs are covered via their domains).";
    }
    case "sigma": {
      const sel: string[] = [];
      if (s.ips.length)
        sel.push(
          `  selection_ip:\n    DestinationIp:\n${s.ips.map((i) => `      - '${i}'`).join("\n")}`,
        );
      if (s.domains.length)
        sel.push(
          `  selection_domain:\n    QueryName|endswith:\n${s.domains.map((d) => `      - '${d}'`).join("\n")}`,
        );
      if (s.hashes.length)
        sel.push(
          `  selection_hash:\n    Hashes|contains:\n${s.hashes.map((h) => `      - '${h}'`).join("\n")}`,
        );
      const names = sel.map((x) => x.trim().split(":")[0]);
      return `title: SentinelGrid IOC match — ${r.target}\nid: ${r.id}\nstatus: experimental\ndescription: Indicators from SentinelGrid case (verdict ${r.verdict}, score ${r.riskScore.total}/100)\nauthor: SentinelGrid\ndate: ${new Date().toISOString().slice(0, 10).replace(/-/g, "/")}\nlogsource:\n  category: network_connection\ndetection:\n${sel.join("\n")}\n  condition: 1 of ${names.length > 1 ? "selection_*" : names[0]}\nfalsepositives:\n  - Shared hosting / CDN infrastructure\nlevel: ${r.verdict === "critical" ? "critical" : r.verdict === "high" ? "high" : "medium"}`;
    }
    case "suricata": {
      let sid = 9100000;
      const rules: string[] = [];
      for (const ip of s.ips)
        rules.push(
          `alert ip $HOME_NET any -> ${ip} any (msg:"SentinelGrid IOC traffic to ${ip}"; classtype:trojan-activity; sid:${sid++}; rev:1;)`,
        );
      for (const d of s.domains) {
        rules.push(
          `alert dns $HOME_NET any -> any any (msg:"SentinelGrid IOC DNS lookup ${d}"; dns.query; dotprefix; content:".${d}"; nocase; endswith; sid:${sid++}; rev:1;)`,
        );
        rules.push(
          `alert tls $HOME_NET any -> any any (msg:"SentinelGrid IOC TLS SNI ${d}"; tls.sni; dotprefix; content:".${d}"; nocase; endswith; sid:${sid++}; rev:1;)`,
        );
      }
      return rules.length
        ? `# ${r.title ?? r.target}\n${rules.join("\n")}`
        : "No network indicators (hashes need an EDR rule instead).";
    }
  }
}
