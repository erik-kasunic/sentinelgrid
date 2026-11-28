import { providerName, PROVIDER_STATUS_LABEL } from "./provider-meta";
import { collectIocs } from "./detection";
import { TARGET_TYPE_LABEL, VERDICT_LABEL, type InvestigationResult, type Verdict } from "./types";

const COLORS: Record<Verdict, [number, number, number]> = {
  safe: [22, 163, 74],
  low: [22, 163, 74],
  medium: [217, 119, 6],
  high: [220, 38, 38],
  critical: [185, 28, 28],
  unknown: [100, 116, 139],
};

// jsPDF core fonts are Latin-1 only; strip anything else so nothing renders as garbage.
const t = (s: unknown) =>
  String(s ?? "")
    .replace(/[—–]/g, "-")
    .replace(/[→]/g, "->")
    // Keep tab/newline/CR and Latin-1 only; jsPDF's built-in fonts cannot render anything else.
    // eslint-disable-next-line no-control-regex
    .replace(/[^\x09\x0A\x0D\x20-\xFF]/g, "");

/**
 * Draws the same world map as the web app (Natural Earth projection, world-atlas 110m) into a
 * jsPDF page box at (x, y), and returns the server position [px, py] relative to (x, y).
 */
async function drawWorldMap(
  doc: {
    setFillColor: (...c: number[]) => unknown;
    setDrawColor: (...c: number[]) => unknown;
    setLineWidth: (w: number) => unknown;
    lines: (
      l: number[][],
      x: number,
      y: number,
      s: number[],
      style: string | null,
      closed: boolean,
    ) => unknown;
  },
  x: number,
  y: number,
  w: number,
  h: number,
  lat: number,
  lon: number,
): Promise<[number, number]> {
  const [{ geoNaturalEarth1, geoPath, geoGraticule10 }, { feature }, world] = await Promise.all([
    import("d3-geo"),
    import("topojson-client"),
    import("world-atlas/countries-110m.json"),
  ]);
  const topo = world.default as unknown as Parameters<typeof feature>[0];
  const countryObject = (topo as { objects: Record<string, unknown> }).objects["countries"];
  const countries = countryObject
    ? (feature(topo, countryObject as never) as unknown as { features: unknown[] }).features
    : [];

  const proj = geoNaturalEarth1().fitExtent(
    [
      [0, 0],
      [w, h],
    ],
    { type: "Sphere" },
  );

  // Collect the projected outline as separate subpaths, so the antimeridian cuts from d3 are kept.
  type Sub = { pts: [number, number][]; closed: boolean };
  const collect = (features: unknown): Sub[] => {
    const subs: Sub[] = [];
    let cur: Sub | null = null;
    const ctx = {
      moveTo(px: number, py: number) {
        cur = { pts: [[px, py]], closed: false };
        subs.push(cur);
      },
      lineTo(px: number, py: number) {
        cur?.pts.push([px, py]);
      },
      closePath() {
        if (cur) cur.closed = true;
      },
    };
    const path = geoPath(proj, ctx as never);
    path(features as never);
    return subs;
  };

  const draw = (subs: Sub[], style: string | null, ox: number, oy: number) => {
    for (const s of subs) {
      if (s.pts.length < 2) continue;
      const deltas = s.pts.slice(1).map((p, i) => [p[0] - s.pts[i]![0], p[1] - s.pts[i]![1]]);
      doc.lines(deltas, ox + s.pts[0]![0], oy + s.pts[0]![1], [1, 1], style, s.closed);
    }
  };

  // Graticule first, then country borders on top.
  doc.setDrawColor(30, 41, 59);
  doc.setLineWidth(0.3);
  draw(collect(geoGraticule10()), "S", x, y);
  doc.setDrawColor(71, 85, 105);
  doc.setLineWidth(0.3);
  draw(collect({ type: "FeatureCollection", features: countries }), "S", x, y);

  const p = proj([lon, lat]);
  return p ? [p[0], p[1]] : [w / 2, h / 2];
}

/** Formal incident report built only from evidence stored in the case. Browser-only. */
export async function downloadPdfReport(r: InvestigationResult) {
  const { jsPDF } = await import("jspdf");
  const { default: autoTable } = await import("jspdf-autotable");
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const W = doc.internal.pageSize.getWidth();
  const M = 48;
  const color = COLORS[r.verdict];
  const insufficient = r.verdictBasis === "insufficient";
  let y = 0;

  const after = () =>
    (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 22;
  const heading = (s: string) => {
    if (y > 740) {
      doc.addPage();
      y = M;
    }
    doc
      .setFont("helvetica", "bold")
      .setFontSize(12)
      .setTextColor(15, 23, 42)
      .text(t(s).toUpperCase(), M, y);
    doc
      .setDrawColor(...color)
      .setLineWidth(1.5)
      .line(M, y + 5, M + 40, y + 5);
    y += 18;
  };
  const para = (s: string, size = 10) => {
    doc.setFont("helvetica", "normal").setFontSize(size).setTextColor(51, 65, 85);
    const lines = doc.splitTextToSize(t(s), W - 2 * M) as string[];
    for (const l of lines) {
      if (y > 790) {
        doc.addPage();
        y = M;
      }
      doc.text(l, M, y);
      y += size + 4;
    }
    y += 6;
  };
  const table = (head: string[], body: string[][]) => {
    if (!body.length) return para("None recorded.");
    autoTable(doc, {
      startY: y,
      head: [head],
      body: body.map((row) => row.map(t)),
      margin: { left: M, right: M },
      styles: { fontSize: 8.5, cellPadding: 4, overflow: "linebreak" },
      headStyles: { fillColor: [15, 23, 42], textColor: 255 },
      alternateRowStyles: { fillColor: [245, 247, 250] },
    });
    y = after();
  };

  // Cover band
  doc.setFillColor(8, 12, 24).rect(0, 0, W, 120, "F");
  doc
    .setTextColor(74, 222, 128)
    .setFont("courier", "bold")
    .setFontSize(10)
    .text("SENTINELGRID // INCIDENT REPORT", M, 36);
  doc.setTextColor(255).setFont("helvetica", "bold").setFontSize(18);
  doc.text(doc.splitTextToSize(t(r.title ?? r.target), W - 2 * M - 120) as string[], M, 64);
  doc.setFont("helvetica", "normal").setFontSize(9).setTextColor(180, 190, 205);
  doc.text(
    t(`Case ${r.id}  ·  Generated ${new Date().toISOString().replace("T", " ").slice(0, 16)} UTC`),
    M,
    104,
  );
  doc.setFillColor(...color).roundedRect(W - M - 110, 40, 110, 50, 4, 4, "F");
  doc
    .setTextColor(255)
    .setFont("helvetica", "bold")
    .setFontSize(14)
    .text(VERDICT_LABEL[r.verdict], W - M - 55, 62, { align: "center" });
  doc
    .setFontSize(10)
    .text(insufficient ? "not assessed" : `${r.riskScore.total}/100`, W - M - 55, 80, {
      align: "center",
    });
  y = 150;

  heading("Executive summary");
  para(
    r.ai?.simple_explanation ||
      r.ai?.summary ||
      `${TARGET_TYPE_LABEL[r.targetType]} ${r.target} was assessed as ${VERDICT_LABEL[r.verdict]}${insufficient ? " (insufficient evidence)" : ` with a deterministic risk score of ${r.riskScore.total}/100`}.`,
  );
  if (r.ai?.recommended_action) para(`Recommended action: ${r.ai.recommended_action}`);
  table(
    ["Field", "Value"],
    [
      ["Target", r.target],
      ["Type", TARGET_TYPE_LABEL[r.targetType]],
      ["Verdict", VERDICT_LABEL[r.verdict]],
      ["Risk score", insufficient ? "Not assessed" : `${r.riskScore.total}/100`],
      ["Investigated", new Date(r.createdAt).toISOString()],
      ...(r.infrastructure?.asn
        ? [["ASN / ISP", `${r.infrastructure.asn} ${r.infrastructure.isp ?? ""}`]]
        : []),
      ...(r.infrastructure?.country
        ? [
            [
              "Location",
              [r.infrastructure.city, r.infrastructure.country].filter(Boolean).join(", "),
            ],
          ]
        : []),
      ...(r.infrastructure?.registrar ? [["Registrar", r.infrastructure.registrar]] : []),
      ...(r.infrastructure?.createdDate ? [["Registered", r.infrastructure.createdDate]] : []),
    ],
  );

  const infra = r.infrastructure;
  if (infra && (infra.asn || infra.country || infra.registrar || infra.dnsRecords?.length)) {
    heading("Infrastructure and location");
    table(
      ["Field", "Value"],
      [
        ...(infra.asn ? [["ASN", infra.asn]] : []),
        ...(infra.isp ? [["ISP", infra.isp]] : []),
        ...(infra.organization ? [["Organization", infra.organization]] : []),
        ...(infra.usageType ? [["Usage type", infra.usageType]] : []),
        ...(infra.country
          ? [["Location", [infra.city, infra.region, infra.country].filter(Boolean).join(", ")]]
          : []),
        ...(infra.latitude !== undefined && infra.longitude !== undefined
          ? [["Coordinates", `${infra.latitude.toFixed(4)}, ${infra.longitude.toFixed(4)}`]]
          : []),
        ...(infra.registrar ? [["Registrar", infra.registrar]] : []),
        ...(infra.createdDate ? [["Registered", infra.createdDate]] : []),
        ...(infra.expiresDate ? [["Expires", infra.expiresDate]] : []),
        ...(infra.domainStatus?.length ? [["Domain status", infra.domainStatus.join(", ")]] : []),
        ...(infra.nameservers?.length ? [["Nameservers", infra.nameservers.join(", ")]] : []),
        ...(infra.dnsRecords ?? []).map((d) => [`DNS ${d.type}`, d.value]),
      ],
    );
    if (infra.latitude !== undefined && infra.longitude !== undefined) {
      const mapW = 300;
      const mapH = mapW / 2;
      if (y + mapH + 40 > 800) {
        doc.addPage();
        y = M;
      }
      doc.setFillColor(8, 12, 24).rect(M, y, mapW, mapH, "F");
      const [px, py] = await drawWorldMap(doc, M, y, mapW, mapH, infra.latitude, infra.longitude);
      doc.setFillColor(...color).circle(M + px, y + py, 5, "F");
      doc
        .setDrawColor(...color)
        .setLineWidth(1)
        .circle(M + px, y + py, 10, "S");
      doc
        .setFont("helvetica", "normal")
        .setFontSize(8)
        .setTextColor(148, 163, 184)
        .text(
          t(
            `Server location by IP geolocation (${infra.latitude.toFixed(2)}, ${infra.longitude.toFixed(2)}). Usually the provider's data center, not the exact building.`,
          ),
          M,
          y + mapH + 12,
        );
      y += mapH + 36;
    }
  }

  if (r.ai) {
    heading("Analyst assessment");
    if (r.ai.summary) para(r.ai.summary);
    if (r.ai.explanation) para(r.ai.explanation);
    if (r.ai.uncertainties.length) {
      para(`Uncertainties: ${r.ai.uncertainties.join(" | ")}`, 9);
    }
    para(
      `AI confidence ${Math.round(r.ai.confidence)}%. The AI explains the evidence; it never changes the score.`,
      8,
    );
  }

  heading("Score breakdown");
  table(
    ["Rule", "Points", "Max"],
    r.riskScore.lines.map((l) => [l.label, `+${l.points}`, String(l.max)]),
  );
  if (r.riskScore.note) para(`Note: ${r.riskScore.note}`, 9);

  heading("Evidence");
  table(
    ["Severity", "Source", "Finding", "Observed"],
    r.evidence.map((e) => [
      e.severity.toUpperCase(),
      providerName(e.provider),
      `${e.label}${e.detail ? ` - ${e.detail}` : ""}`,
      e.observedAt?.slice(0, 10) ?? "",
    ]),
  );

  if (r.recommendations.length) {
    heading("Recommended response");
    table(
      ["#", "Action"],
      r.recommendations.map((x) => [String(x.step), x.text]),
    );
  }

  heading("Intelligence sources");
  table(
    ["Source", "Status", "Detail"],
    r.providerStatus.map((p) => [
      providerName(p.provider),
      PROVIDER_STATUS_LABEL[p.status] ?? p.status,
      p.message ?? "",
    ]),
  );

  doc.addPage();
  y = M;
  heading("Appendix A - IOC list (defanged)");
  const s = collectIocs(r);
  const defang = (v: string) => v.replace(/\./g, "[.]").replace(/^http/i, "hxxp");
  table(
    ["Type", "Indicator"],
    [
      ...s.ips.map((v) => ["IP", defang(v)]),
      ...s.domains.map((v) => ["Domain", defang(v)]),
      ...s.urls.map((v) => ["URL", defang(v)]),
      ...s.hashes.map((v) => ["Hash", v]),
    ],
  );
  heading("Appendix B - Relationships");
  table(
    ["From", "Link", "To", "Source"],
    r.relationships
      .slice(0, 150)
      .map((x) => [
        x.fromValue,
        x.kind,
        `${x.toValue}${x.flagged ? " (flagged)" : ""}`,
        x.source ? providerName(x.source) : "",
      ]),
  );

  const pages = doc.getNumberOfPages();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    doc.setFont("helvetica", "normal").setFontSize(7.5).setTextColor(120);
    doc.text(
      "Passive intelligence only. Findings reflect third-party sources at investigation time. TLP:AMBER",
      M,
      820,
    );
    doc.text(`${i} / ${pages}`, W - M, 820, { align: "right" });
  }
  const safe = r.target.replace(/[^a-z0-9.-]+/gi, "_").slice(0, 60);
  doc.save(`SentinelGrid_${safe}_${r.createdAt.slice(0, 10)}.pdf`);
}
