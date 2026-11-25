import { createFileRoute } from "@tanstack/react-router";

import { AppShell } from "@/components/sg/app-shell";
import { TerminalLabel } from "@/components/sg/chrome";
import { ImageMetadataTool } from "@/components/sg/image-metadata-tool";

export const Route = createFileRoute("/metadata")({
  head: () => ({
    meta: [
      { title: "Image metadata (EXIF) — SentinelGrid" },
      {
        name: "description",
        content:
          "Read EXIF metadata from an image locally in your browser and see where it was taken on a map.",
      },
      { property: "og:title", content: "Image metadata (EXIF) — SentinelGrid" },
      {
        property: "og:description",
        content: "Local EXIF/GPS extraction with a map pin. The image never leaves your browser.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: MetadataPage,
});

function MetadataPage() {
  return (
    <AppShell>
      <div className="mx-auto max-w-5xl space-y-6">
        <div>
          <TerminalLabel>Image metadata</TerminalLabel>
          <h1 className="mt-2 font-mono text-2xl text-foreground">EXIF & location extraction</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            The image is read locally in your browser and is never uploaded.
          </p>
        </div>
        <ImageMetadataTool />
      </div>
    </AppShell>
  );
}
