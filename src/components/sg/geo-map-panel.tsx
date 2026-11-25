import { useEffect, useMemo, useRef, useState } from "react";
import { geoNaturalEarth1, geoPath, geoGraticule10, geoContains } from "d3-geo";
import { feature } from "topojson-client";
import type { Feature, FeatureCollection, Geometry } from "geojson";
import type { Topology } from "topojson-specification";
import world from "world-atlas/countries-110m.json";
import { Minus, Plus, LocateFixed } from "lucide-react";
import { EmptyState, Panel } from "./chrome";
import { Button } from "@/components/ui/button";
import type { InfrastructureData } from "@/lib/intel/types";

const W = 800;
const H = 420;
const MIN_Z = 1;
const MAX_Z = 12;
const clamp = (v: number, a: number, b: number) => Math.min(b, Math.max(a, v));

type Country = Feature<Geometry, { name?: string }>;

export function GeoMapPanel({
  infrastructure,
}: {
  infrastructure?: InfrastructureData | undefined;
}) {
  const lat = infrastructure?.latitude;
  const lon = infrastructure?.longitude;
  const hasPoint =
    typeof lat === "number" &&
    Number.isFinite(lat) &&
    lat >= -90 &&
    lat <= 90 &&
    typeof lon === "number" &&
    Number.isFinite(lon) &&
    lon >= -180 &&
    lon <= 180;

  const { countries, path, projection, graticule } = useMemo(() => {
    const topo = world as unknown as Topology;
    const countryObject = topo.objects["countries"];
    const fc = countryObject
      ? (feature(topo, countryObject) as unknown as FeatureCollection<Geometry, { name?: string }>)
      : { type: "FeatureCollection" as const, features: [] };
    const proj = geoNaturalEarth1().fitExtent(
      [
        [8, 8],
        [W - 8, H - 8],
      ],
      { type: "Sphere" },
    );
    const p = geoPath(proj);
    return {
      countries: fc.features as Country[],
      path: p,
      projection: proj,
      graticule: p(geoGraticule10()) ?? "",
    };
  }, []);

  const point = hasPoint ? projection([lon, lat]) : null;
  const hostCountry = useMemo(
    () => (hasPoint ? countries.find((c) => geoContains(c, [lon, lat])) : undefined),
    [countries, hasPoint, lat, lon],
  );

  const [view, setView] = useState({ z: 1, x: 0, y: 0 });
  const [hover, setHover] = useState<string | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const viewRef = useRef(view);
  viewRef.current = view;
  const drag = useRef<{ px: number; py: number; x: number; y: number } | null>(null);

  const toSvg = (clientX: number, clientY: number) => {
    const svg = svgRef.current;
    if (!svg) return null;
    const rect = svg.getBoundingClientRect();
    return {
      px: ((clientX - rect.left) / rect.width) * W,
      py: ((clientY - rect.top) / rect.height) * H,
    };
  };

  const zoomAt = (next: number, px: number, py: number) =>
    setView((v) => {
      const z = clamp(next, MIN_Z, MAX_Z);
      const k = z / v.z;
      return { z, x: px - (px - v.x) * k, y: py - (py - v.y) * k };
    });

  const focusPoint = () => {
    if (!point) return setView({ z: 1, x: 0, y: 0 });
    const z = 4;
    setView({ z, x: W / 2 - point[0] * z, y: H / 2 - point[1] * z });
  };

  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const dy = e.deltaY * (e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? 100 : 1);
      const position = toSvg(e.clientX, e.clientY);
      if (!position) return;
      const { px, py } = position;
      zoomAt(viewRef.current.z * Math.exp(-dy * 0.002), px, py);
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);

  const location = [infrastructure?.city, infrastructure?.region, infrastructure?.country]
    .filter(Boolean)
    .join(", ");
  const z = view.z;

  return (
    <Panel title="Server geolocation">
      {!hasPoint || !point ? (
        <EmptyState>No geolocation returned for this indicator</EmptyState>
      ) : (
        <div className="space-y-4">
          <div className="relative overflow-hidden border border-border bg-background">
            <svg
              ref={svgRef}
              viewBox={`0 0 ${W} ${H}`}
              className="h-auto w-full cursor-grab touch-none select-none active:cursor-grabbing"
              role="img"
              aria-label={`World map showing server location in ${location}`}
              onPointerDown={(e) => {
                (e.target as Element).setPointerCapture?.(e.pointerId);
                const position = toSvg(e.clientX, e.clientY);
                if (!position) return;
                const { px, py } = position;
                drag.current = { px, py, x: view.x, y: view.y };
              }}
              onPointerMove={(e) => {
                if (!drag.current) return;
                const position = toSvg(e.clientX, e.clientY);
                if (!position) return;
                const { px, py } = position;
                const d = drag.current;
                setView((v) => ({ ...v, x: d.x + px - d.px, y: d.y + py - d.py }));
              }}
              onPointerUp={() => (drag.current = null)}
              onPointerLeave={() => (drag.current = null)}
            >
              <g transform={`translate(${view.x},${view.y}) scale(${z})`}>
                <path
                  d={graticule}
                  fill="none"
                  stroke="var(--border)"
                  strokeWidth={0.4 / z}
                  opacity={0.6}
                />
                {countries.map((c, i) => {
                  const isHost = c === hostCountry;
                  const name = c.properties?.name ?? "";
                  return (
                    <path
                      key={i}
                      d={path(c) ?? ""}
                      fill={
                        isHost
                          ? "var(--accent)"
                          : hover === name
                            ? "var(--secondary)"
                            : "var(--muted)"
                      }
                      stroke={isHost ? "var(--primary)" : "var(--border)"}
                      strokeWidth={(isHost ? 0.9 : 0.4) / z}
                      onPointerEnter={() => setHover(name)}
                      onPointerLeave={() => setHover((h) => (h === name ? null : h))}
                    />
                  );
                })}
                <circle cx={point[0]} cy={point[1]} r={14 / z} fill="var(--primary)" opacity={0.15}>
                  <animate
                    attributeName="r"
                    values={`${6 / z};${22 / z};${6 / z}`}
                    dur="2.4s"
                    repeatCount="indefinite"
                  />
                  <animate
                    attributeName="opacity"
                    values="0.35;0;0.35"
                    dur="2.4s"
                    repeatCount="indefinite"
                  />
                </circle>
                <circle
                  cx={point[0]}
                  cy={point[1]}
                  r={4 / z}
                  fill="var(--primary)"
                  stroke="var(--background)"
                  strokeWidth={1.2 / z}
                />
                <line
                  x1={point[0]}
                  y1={0}
                  x2={point[0]}
                  y2={H}
                  stroke="var(--primary)"
                  strokeWidth={0.4 / z}
                  opacity={0.35}
                  strokeDasharray={`${3 / z} ${3 / z}`}
                />
                <line
                  x1={0}
                  y1={point[1]}
                  x2={W}
                  y2={point[1]}
                  stroke="var(--primary)"
                  strokeWidth={0.4 / z}
                  opacity={0.35}
                  strokeDasharray={`${3 / z} ${3 / z}`}
                />
              </g>
            </svg>

            <div className="pointer-events-none absolute top-2 left-2 font-mono text-[0.625rem] tracking-[0.14em] text-muted-foreground uppercase">
              {hover ?? "drag · scroll to zoom"}
            </div>
            <div className="absolute right-2 bottom-2 flex flex-col gap-1">
              {[
                { icon: Plus, label: "Zoom in", on: () => zoomAt(z * 1.5, W / 2, H / 2) },
                { icon: Minus, label: "Zoom out", on: () => zoomAt(z / 1.5, W / 2, H / 2) },
                { icon: LocateFixed, label: "Focus server", on: focusPoint },
              ].map(({ icon: Icon, label, on }) => (
                <Button
                  key={label}
                  type="button"
                  variant="outline"
                  size="icon"
                  aria-label={label}
                  title={label}
                  onClick={on}
                  className="h-8 w-8 rounded-none bg-card text-primary hover:border-primary"
                >
                  <Icon className="h-4 w-4" />
                </Button>
              ))}
            </div>
          </div>

          <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              ["Country", infrastructure?.country],
              ["City", infrastructure?.city ?? infrastructure?.region],
              ["Latitude", lat.toFixed(4)],
              ["Longitude", lon.toFixed(4)],
            ].map(([k, v]) => (
              <div key={k} className="border border-border/60 px-3 py-2">
                <dt className="font-mono text-[0.625rem] tracking-[0.14em] text-muted-foreground uppercase">
                  {k}
                </dt>
                <dd className="mt-1 font-mono text-xs break-all text-foreground">{v ?? "—"}</dd>
              </div>
            ))}
          </dl>
          {infrastructure?.asn && (
            <p className="font-mono text-xs text-muted-foreground">
              Hosted by{" "}
              <span className="text-primary">
                {infrastructure.isp ?? infrastructure.organization}
              </span>{" "}
              · {infrastructure.asn}
            </p>
          )}
        </div>
      )}
    </Panel>
  );
}
