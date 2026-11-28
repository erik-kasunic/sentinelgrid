import { useEffect, useRef, useState } from "react";
import { ImageUp } from "lucide-react";
import { toast } from "sonner";

import { Panel } from "./chrome";
import { takePendingImage } from "@/lib/pending-image";
import { cn } from "@/lib/utils";

type Meta = Record<string, unknown>;

const GROUPS: { title: string; keys: string[] }[] = [
  {
    title: "Capture",
    keys: [
      "DateTimeOriginal",
      "CreateDate",
      "ModifyDate",
      "OffsetTimeOriginal",
      "SubSecTimeOriginal",
      "GPSDateStamp",
      "GPSTimeStamp",
    ],
  },
  {
    title: "Device",
    keys: [
      "Make",
      "Model",
      "LensMake",
      "LensModel",
      "Software",
      "BodySerialNumber",
      "LensSerialNumber",
      "HostComputer",
      "CameraOwnerName",
    ],
  },
  {
    title: "Camera settings",
    keys: [
      "ExposureTime",
      "FNumber",
      "ISO",
      "FocalLength",
      "FocalLengthIn35mmFormat",
      "Flash",
      "WhiteBalance",
      "MeteringMode",
      "ExposureBiasValue",
      "BrightnessValue",
    ],
  },
  {
    title: "Location",
    keys: [
      "latitude",
      "longitude",
      "GPSAltitude",
      "GPSImgDirection",
      "GPSSpeed",
      "GPSHPositioningError",
    ],
  },
  {
    title: "Image",
    keys: [
      "ImageWidth",
      "ImageHeight",
      "ExifImageWidth",
      "ExifImageHeight",
      "Orientation",
      "ColorSpace",
      "ResolutionX",
      "ResolutionY",
    ],
  },
  {
    title: "Author & rights",
    keys: [
      "Artist",
      "Copyright",
      "OwnerName",
      "ImageDescription",
      "XPAuthor",
      "XPComment",
      "Creator",
      "Rights",
      "UserComment",
    ],
  },
];

function fmt(v: unknown): string {
  if (v instanceof Date) return v.toLocaleString();
  if (v instanceof Uint8Array) return `${v.length} bytes`;
  if (Array.isArray(v)) return v.map(fmt).join(", ");
  if (typeof v === "number") {
    if (Number.isInteger(v)) return String(v);
    return String(parseFloat(v.toFixed(v < 1 ? 6 : 4)));
  }
  if (v && typeof v === "object") return JSON.stringify(v);
  return String(v);
}

// Full local EXIF/GPS tool. The image is parsed in the browser (exifr) and never uploaded.
export function ImageMetadataTool() {
  const [file, setFile] = useState<{ name: string; size: number; type: string } | null>(null);
  const [meta, setMeta] = useState<Meta | null>(null);
  const [showAll, setShowAll] = useState(false);
  const [drag, setDrag] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  const handle = async (f: File) => {
    if (!f.type.startsWith("image/") && !/\.(heic|heif|dng|cr2|nef|arw|tiff?)$/i.test(f.name)) {
      toast.error("Choose an image file.");
      return;
    }
    try {
      const exifr = (await import("exifr")).default;
      // silentErrors exists at runtime but is missing from exifr's bundled type defs.
      const opts = {
        tiff: true,
        exif: true,
        gps: true,
        xmp: true,
        iptc: true,
        icc: false,
        mergeOutput: true,
        silentErrors: true,
      } as Record<string, unknown>;
      let data = (await exifr.parse(f, opts as Parameters<typeof exifr.parse>[1])) as
        Meta | undefined;
      if (!data || Object.keys(data).length === 0) {
        // Some cameras/phones store fields in unusual blocks — retry with every parser enabled.
        data = (await exifr.parse(f, { mergeOutput: true, silentErrors: true } as Parameters<
          typeof exifr.parse
        >[1])) as Meta | undefined;
      }
      setFile({ name: f.name, size: f.size, type: f.type || "unknown" });
      setMeta(data ?? {});
      if (!data || Object.keys(data).length === 0)
        toast.info("No metadata found — it may have been stripped.");
    } catch (e) {
      console.error(e);
      toast.error("Could not read metadata from this file.");
    }
  };

  useEffect(() => {
    const f = takePendingImage();
    if (f) void handle(f);
  }, []);

  const lat = typeof meta?.["latitude"] === "number" ? (meta["latitude"] as number) : undefined;
  const lon = typeof meta?.["longitude"] === "number" ? (meta["longitude"] as number) : undefined;
  const known = new Set(GROUPS.flatMap((g) => g.keys));

  return (
    <div className="space-y-6">
      <button
        type="button"
        onClick={() => input.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setDrag(true);
        }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDrag(false);
          const f = e.dataTransfer.files?.[0];
          if (f) void handle(f);
        }}
        className={cn(
          "glass-panel flex w-full flex-col items-center gap-3 border border-dashed p-10 transition-colors",
          drag ? "border-primary" : "border-primary/40 hover:border-primary",
        )}
      >
        <ImageUp className="size-8 text-primary" />
        <span className="font-mono text-sm text-foreground">Drop an image or click to choose</span>
        <span className="font-mono text-xs text-muted-foreground">
          JPEG, HEIC, PNG, TIFF, RAW — read locally, never uploaded
        </span>
      </button>
      <input
        ref={input}
        type="file"
        accept="image/*,.heic,.heif,.dng,.cr2,.nef,.arw"
        className="hidden"
        aria-label="Choose image"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) void handle(f);
          e.target.value = "";
        }}
      />

      {file && meta && (
        <>
          <Panel title="File">
            <p className="font-mono text-xs break-all text-foreground">
              {file.name} · {(file.size / 1024).toFixed(1)} KB · {file.type}
            </p>
            {Object.keys(meta).length === 0 ? (
              <p className="mt-2 text-xs text-muted-foreground">
                This image carries no readable metadata — the app or service it passed through most
                likely stripped it. Nothing is hidden here; the file simply contains no camera, time
                or location data.
              </p>
            ) : (
              lat === undefined && (
                <p className="mt-2 text-xs text-muted-foreground">
                  No GPS position in this image — all other metadata is shown below.
                </p>
              )
            )}
          </Panel>

          {Object.keys(meta).length > 0 && (
            <div className="grid gap-6 lg:grid-cols-2">
              {GROUPS.map((g) => {
                const rows = g.keys.filter(
                  (k) => meta[k] !== undefined && meta[k] !== null && meta[k] !== "",
                );
                if (!rows.length) return null;
                return (
                  <Panel key={g.title} title={g.title}>
                    <dl className="space-y-1.5">
                      {rows.map((k) => (
                        <div key={k} className="flex gap-3">
                          <dt className="w-40 shrink-0 font-mono text-[0.6875rem] tracking-[0.08em] text-muted-foreground uppercase">
                            {k}
                          </dt>
                          <dd className="min-w-0 font-mono text-xs break-all text-foreground">
                            {fmt(meta[k])}
                          </dd>
                        </div>
                      ))}
                    </dl>
                  </Panel>
                );
              })}
            </div>
          )}

          {Object.keys(meta).length > 0 && (
            <Panel title="All metadata">
              <button
                type="button"
                onClick={() => setShowAll((v) => !v)}
                className="font-mono text-[0.625rem] tracking-[0.14em] text-muted-foreground uppercase hover:text-foreground"
              >
                {showAll ? "hide" : "show"} all {Object.keys(meta).length} fields
              </button>
              {showAll && (
                <dl className="mt-3 space-y-1">
                  {Object.entries(meta).map(([k, v]) => (
                    <div key={k} className="flex gap-3">
                      <dt
                        className={cn(
                          "w-48 shrink-0 font-mono text-[0.6875rem]",
                          known.has(k) ? "text-primary" : "text-muted-foreground",
                        )}
                      >
                        {k}
                      </dt>
                      <dd className="min-w-0 font-mono text-xs break-all text-foreground">
                        {fmt(v)}
                      </dd>
                    </div>
                  ))}
                </dl>
              )}
            </Panel>
          )}
        </>
      )}
    </div>
  );
}
