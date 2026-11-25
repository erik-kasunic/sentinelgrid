import { EmptyState, Panel } from "./chrome";
import type { Relationship } from "@/lib/intel/types";

const KIND_LABEL: Record<string, string> = {
  resolves_to: "resolves to",
  hosted_on: "also hosts",
  redirects_to: "redirects to",
  associated_with: "associated with",
  detected_by: "detected by",
  related_to: "related to",
  belongs_to: "belongs to",
};

const COLUMNS = ["Domain / URL", "IP", "ASN", "Same-server domains", "Hashes"] as const;
const MAX_ROWS = 10;
const INPUT = "Your input";
const UNATTRIBUTED = "Unattributed";

function columnOf(value: string, type: string, target: string, cohosted: Set<string>): number {
  if (type === "url") return 0;
  // Only domains a source saw on the same IP (or contacted by a file) belong in column 4;
  // nameservers and other DNS links stay next to the target domain.
  if (type === "domain") return value !== target && cohosted.has(value) ? 3 : 0;
  if (type === "ip") return 1;
  if (type === "asn") return 2;
  if (type === "hash") return 4;
  return 0;
}

/**
 * Layered pivot graph: domain -> IP -> ASN -> co-hosted domains -> hashes.
 * Deterministic layout so the same evidence always draws the same picture.
 */
export function GraphPanel({
  target,
  relationships,
}: {
  target: string;
  relationships: Relationship[];
}) {
  const types = new Map<string, string>();
  const flagged = new Set<string>();
  for (const rel of relationships) {
    if (!types.has(rel.fromValue)) types.set(rel.fromValue, rel.fromType);
    if (!types.has(rel.toValue)) types.set(rel.toValue, rel.toType);
    if (rel.flagged) flagged.add(rel.toValue);
  }

  // Provenance: a node is backed by the sources of the links that reported it.
  const inbound = new Map<string, Set<string>>();
  const outbound = new Map<string, Set<string>>();
  const add = (m: Map<string, Set<string>>, k: string, src: string | undefined) => {
    const set = m.get(k) ?? new Set<string>();
    for (const part of (src ?? UNATTRIBUTED).split(", ")) set.add(part);
    m.set(k, set);
  };
  for (const rel of relationships) {
    add(inbound, rel.toValue, rel.source);
    add(outbound, rel.fromValue, rel.source);
  }
  const sourcesOf = (value: string): string[] =>
    value === target
      ? [INPUT]
      : [...(inbound.get(value) ?? outbound.get(value) ?? new Set([UNATTRIBUTED]))];

  const cohosted = new Set(
    relationships
      .filter((r) => r.toType === "domain" && (r.kind === "hosted_on" || r.fromType === "hash"))
      .map((r) => r.toValue),
  );
  const targetIsHash = types.get(target) === "hash";
  const headers = COLUMNS.map((c, i) => (i === 3 && targetIsHash ? "Contacted domains" : c));
  const cols: string[][] = COLUMNS.map(() => []);
  for (const [value, type] of types) {
    const col = cols[columnOf(value, type, target, cohosted)]!;
    if (col.length < MAX_ROWS || value === target) col.push(value);
  }
  for (const col of cols)
    col.sort((a, b) => (a === target ? -1 : b === target ? 1 : a.localeCompare(b)));

  const width = 960;
  const colW = width / COLUMNS.length;
  const rowH = 46;
  const top = 48;
  const rows = Math.max(1, ...cols.map((c) => c.length));
  const height = top + rows * rowH + 16;

  const pos = new Map<string, { x: number; y: number }>();
  cols.forEach((col, ci) => {
    const offset = ((rows - col.length) * rowH) / 2;
    col.forEach((value, ri) =>
      pos.set(value, { x: colW * ci + colW / 2, y: top + offset + ri * rowH + rowH / 2 }),
    );
  });

  const truncate = (v: string) => (v.length > 20 ? `${v.slice(0, 9)}…${v.slice(-9)}` : v);

  return (
    <Panel
      title="Relationship graph"
      aside={
        <span className="font-mono text-[0.625rem] tracking-[0.14em] text-muted-foreground uppercase">
          domain ➔ ip ➔ asn ➔ same server ➔ hashes
        </span>
      }
    >
      {relationships.length === 0 ? (
        <EmptyState>No relationships observed</EmptyState>
      ) : (
        <div className="space-y-4">
          <div className="overflow-x-auto">
            <svg
              viewBox={`0 0 ${width} ${height}`}
              className="h-auto w-full min-w-[720px]"
              role="img"
              aria-label={`Relationship graph for ${target}`}
            >
              {headers.map((label, ci) => (
                <g key={label}>
                  <text
                    x={colW * ci + colW / 2}
                    y={18}
                    textAnchor="middle"
                    fontSize={10}
                    letterSpacing="0.12em"
                    fontFamily="var(--font-mono)"
                    fill="var(--muted-foreground)"
                  >
                    {label.toUpperCase()}
                  </text>
                  <line
                    x1={colW * ci + 16}
                    x2={colW * (ci + 1) - 16}
                    y1={28}
                    y2={28}
                    stroke="var(--border)"
                  />
                </g>
              ))}

              {relationships.map((rel, i) => {
                const a = pos.get(rel.fromValue);
                const b = pos.get(rel.toValue);
                if (!a || !b) return null;
                const mx = (a.x + b.x) / 2;
                const bad = rel.flagged;
                return (
                  <path
                    key={`${rel.fromValue}-${rel.toValue}-${i}`}
                    d={`M${a.x},${a.y} C${mx},${a.y} ${mx},${b.y} ${b.x},${b.y}`}
                    fill="none"
                    stroke={bad ? "var(--destructive)" : "var(--border-strong)"}
                    strokeOpacity={bad ? 0.8 : 0.9}
                    strokeWidth={bad ? 1.4 : 1}
                  >
                    <title>{`${rel.fromValue} ${KIND_LABEL[rel.kind] ?? rel.kind} ${rel.toValue}`}</title>
                  </path>
                );
              })}

              {[...pos.entries()].map(([value, p]) => {
                const isTarget = value === target;
                const bad = flagged.has(value);
                const color = bad ? "var(--destructive)" : "var(--primary)";
                return (
                  <g key={value}>
                    <title>{`${value}\nSource: ${sourcesOf(value).join(", ")}`}</title>
                    <rect
                      x={p.x - colW / 2 + 10}
                      y={p.y - 17}
                      width={colW - 20}
                      height={34}
                      rx={3}
                      fill={isTarget ? "var(--primary-dim)" : "var(--card)"}
                      fillOpacity={isTarget ? 0.35 : 1}
                      stroke={isTarget || bad ? color : "var(--border-strong)"}
                      strokeWidth={isTarget ? 1.4 : 1}
                    />
                    <text
                      x={p.x}
                      y={p.y - 1}
                      textAnchor="middle"
                      fontSize={10}
                      fontFamily="var(--font-mono)"
                      fill={
                        isTarget
                          ? "var(--primary)"
                          : bad
                            ? "var(--destructive)"
                            : "var(--foreground)"
                      }
                    >
                      {truncate(value)}
                    </text>
                    <text
                      x={p.x}
                      y={p.y + 11}
                      textAnchor="middle"
                      fontSize={8}
                      fontFamily="var(--font-mono)"
                      fill={
                        sourcesOf(value).includes(UNATTRIBUTED)
                          ? "var(--warning)"
                          : "var(--muted-foreground)"
                      }
                    >
                      {truncate(sourcesOf(value).join(" + "))}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          <div className="space-y-2">
            <p className="font-mono text-[0.625rem] tracking-[0.14em] text-muted-foreground uppercase">
              Node provenance
            </p>
            <ul className="max-h-56 space-y-1 overflow-y-auto">
              {[...pos.keys()].map((value) => {
                const srcs = sourcesOf(value);
                return (
                  <li
                    key={`prov-${value}`}
                    className="flex flex-wrap items-baseline gap-x-3 font-mono text-xs"
                  >
                    <span className="break-all text-foreground">{value}</span>
                    <span
                      className={srcs.includes(UNATTRIBUTED) ? "text-warning" : "text-primary-dim"}
                    >
                      ← {srcs.join(", ")}
                    </span>
                  </li>
                );
              })}
            </ul>
          </div>

          <ul className="max-h-56 space-y-1.5 overflow-y-auto">
            {relationships.map((rel, index) => (
              <li
                key={`row-${rel.fromValue}-${rel.toValue}-${index}`}
                className="font-mono text-xs"
              >
                <span className="break-all text-foreground">{rel.fromValue}</span>
                <span className="mx-2 text-primary-dim">
                  ──{KIND_LABEL[rel.kind] ?? rel.kind}──▶
                </span>
                <span
                  className={`break-all ${rel.flagged ? "text-destructive" : "text-muted-foreground"}`}
                >
                  {rel.toValue}
                  {rel.flagged ? " · flagged" : ""}
                </span>
                <span className="ml-2 text-muted-foreground">[{rel.source ?? UNATTRIBUTED}]</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Panel>
  );
}
