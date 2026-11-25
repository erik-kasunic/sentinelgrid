import { EmptyState, Panel, TerminalLabel } from "./chrome";
import type { DomainProfileData, InfrastructureData, MalwareData } from "@/lib/intel/types";

function Row({ label, value }: { label: string; value?: string | number | undefined }) {
  if (value === undefined || value === "" || value === null) return null;
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-border/50 py-1.5 last:border-0">
      <span className="font-mono text-[0.625rem] tracking-[0.14em] text-muted-foreground uppercase">
        {label}
      </span>
      <span className="font-mono text-xs break-all text-foreground">{value}</span>
    </div>
  );
}

export function InfraPanel({
  infrastructure,
  domainProfile,
  malware,
}: {
  infrastructure?: InfrastructureData | undefined;
  domainProfile?: DomainProfileData | undefined;
  malware?: MalwareData | undefined;
}) {
  const infra = infrastructure ?? {};
  const location = [infra.city, infra.region, infra.country].filter(Boolean).join(", ");
  const hasInfra =
    Object.keys(infra).length > 0 && (infra.dnsRecords?.length || Object.keys(infra).length > 0);

  return (
    <Panel title="Infrastructure">
      {!hasInfra && !domainProfile && !malware ? (
        <EmptyState>No infrastructure data returned</EmptyState>
      ) : (
        <div className="space-y-5">
          <div>
            <Row label="ASN" value={infra.asn} />
            <Row label="ISP" value={infra.isp} />
            <Row label="Organization" value={infra.organization} />
            <Row label="Location" value={location} />
            <Row label="Usage type" value={infra.usageType} />
            <Row label="Registrar" value={infra.registrar} />
            <Row
              label="Registered"
              value={
                infra.createdDate ? new Date(infra.createdDate).toLocaleDateString() : undefined
              }
            />
            <Row
              label="Updated"
              value={
                infra.updatedDate ? new Date(infra.updatedDate).toLocaleDateString() : undefined
              }
            />
            <Row
              label="Expires"
              value={
                infra.expiresDate ? new Date(infra.expiresDate).toLocaleDateString() : undefined
              }
            />
            <Row label="Domain status" value={infra.domainStatus?.join(", ")} />
            <Row label="Nameservers" value={infra.nameservers?.join(", ")} />
          </div>

          {infra.dnsRecords && infra.dnsRecords.length > 0 && (
            <div className="space-y-2">
              <TerminalLabel>DNS records</TerminalLabel>
              <ul className="space-y-1">
                {infra.dnsRecords.map((record, index) => (
                  <li key={`${record.type}-${record.value}-${index}`} className="font-mono text-xs">
                    <span className="mr-2 inline-block w-12 text-primary-dim">{record.type}</span>
                    <span className="break-all text-muted-foreground">{record.value}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {domainProfile && (
            <div className="space-y-2">
              <TerminalLabel>Domain profile</TerminalLabel>
              <Row label="Organization" value={domainProfile.organization} />
              <Row label="Email pattern" value={domainProfile.emailPattern} />
              <Row label="Indexed emails" value={domainProfile.emailCount} />
              <Row
                label="Personal / generic"
                value={
                  domainProfile.personalEmailCount !== undefined ||
                  domainProfile.genericEmailCount !== undefined
                    ? `${domainProfile.personalEmailCount ?? 0} / ${domainProfile.genericEmailCount ?? 0}`
                    : undefined
                }
              />
              <Row
                label="Accept all"
                value={
                  domainProfile.acceptAll === undefined
                    ? undefined
                    : domainProfile.acceptAll
                      ? "Yes"
                      : "No"
                }
              />
              <Row
                label="Disposable domain"
                value={
                  domainProfile.disposable === undefined
                    ? undefined
                    : domainProfile.disposable
                      ? "Yes"
                      : "No"
                }
              />
              <Row
                label="Webmail domain"
                value={
                  domainProfile.webmail === undefined
                    ? undefined
                    : domainProfile.webmail
                      ? "Yes"
                      : "No"
                }
              />
            </div>
          )}

          {malware && (
            <div className="space-y-2">
              <TerminalLabel>File intelligence</TerminalLabel>
              <Row label="File type" value={malware.fileType} />
              <Row
                label="File size"
                value={malware.fileSize ? `${malware.fileSize.toLocaleString()} bytes` : undefined}
              />
              <Row
                label="First seen"
                value={malware.firstSeen ? new Date(malware.firstSeen).toLocaleString() : undefined}
              />
              <Row label="Families" value={malware.families.join(", ") || undefined} />
              <Row label="Tags" value={malware.tags.join(", ") || undefined} />
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}
