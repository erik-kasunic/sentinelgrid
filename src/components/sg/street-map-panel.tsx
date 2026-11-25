import { useState } from "react";
import { ExternalLink } from "lucide-react";
import { Panel } from "./chrome";
import { Button } from "@/components/ui/button";
import type { InfrastructureData } from "@/lib/intel/types";

// Secondary, street-level view of the GeoIP coordinates. Keyless Google Maps embed,
// darkened with a CSS filter in map mode to match the SOC theme.
export function StreetMapPanel({
  infrastructure,
  note,
  title = "Street-level location",
}: {
  infrastructure?: InfrastructureData | undefined;
  note?: string;
  title?: string;
}) {
  const [satellite, setSatellite] = useState(false);
  const lat = infrastructure?.latitude;
  const lon = infrastructure?.longitude;
  if (
    typeof lat !== "number" ||
    typeof lon !== "number" ||
    !Number.isFinite(lat) ||
    !Number.isFinite(lon)
  )
    return null;

  const q = `${lat.toFixed(5)},${lon.toFixed(5)}`;
  const src = `https://maps.google.com/maps?q=${q}&z=13&t=${satellite ? "k" : "m"}&output=embed`;
  const location = [infrastructure?.city, infrastructure?.region, infrastructure?.country]
    .filter(Boolean)
    .join(", ");

  return (
    <Panel title={title}>
      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="font-mono text-xs text-muted-foreground">{location || q}</p>
          <div className="flex gap-2">
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="rounded-none font-mono text-xs"
              onClick={() => setSatellite((s) => !s)}
            >
              {satellite ? "Map view" : "Satellite view"}
            </Button>
            <Button asChild size="sm" variant="outline" className="rounded-none font-mono text-xs">
              <a
                href={`https://www.google.com/maps/search/?api=1&query=${q}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                <ExternalLink className="size-3.5" /> Open in Google Maps
              </a>
            </Button>
          </div>
        </div>
        <div className="overflow-hidden border border-border bg-background">
          <iframe
            key={src}
            title={`Google Maps pin for ${location || q}`}
            src={src}
            loading="lazy"
            referrerPolicy="no-referrer"
            className="h-80 w-full border-0"
            style={
              satellite
                ? undefined
                : { filter: "invert(90%) hue-rotate(180deg) contrast(1.1) brightness(0.85)" }
            }
          />
        </div>
        <p className="text-xs text-muted-foreground">
          {note ??
            "IP geolocation usually points to the provider's data center or network hub, not the exact server building."}
        </p>
      </div>
    </Panel>
  );
}
