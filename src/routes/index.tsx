import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { ImageUp, Radar } from "lucide-react";

import { AppShell } from "@/components/sg/app-shell";
import { TerminalLabel } from "@/components/sg/chrome";
import { ImageMetadataTool } from "@/components/sg/image-metadata-tool";
import { InvestigateForm } from "@/components/sg/investigate-form";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "SentinelGrid — SOC threat investigation platform" },
      {
        name: "description",
        content:
          "Investigate an IP, domain, URL or file hash: multi-source enrichment, correlation, explainable risk scoring — or analyze image metadata locally.",
      },
      { property: "og:title", content: "SentinelGrid — SOC threat investigation platform" },
      {
        property: "og:description",
        content:
          "Enrich, correlate and score a security indicator in one pass, or extract image EXIF/GPS locally.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Home,
});

const TABS = [
  { id: "target", label: "Target investigation", icon: Radar },
  { id: "image", label: "Image analysis", icon: ImageUp },
] as const;

type TabId = (typeof TABS)[number]["id"];

function Home() {
  const [tab, setTab] = useState<TabId>("target");

  return (
    <AppShell>
      <div
        className={cn(
          "mx-auto flex min-h-[calc(100dvh-7rem)] w-full flex-col justify-center pb-[18vh]",
          tab === "image" ? "max-w-5xl" : "max-w-3xl",
        )}
      >
        <TerminalLabel>New investigation</TerminalLabel>
        <h1 className="mt-3 mb-6 font-mono text-2xl text-foreground">Run an investigation</h1>

        <div className="mb-6 flex gap-2" role="tablist" aria-label="Investigation mode">
          {TABS.map((t) => {
            const Icon = t.icon;
            const active = tab === t.id;
            return (
              <button
                key={t.id}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => setTab(t.id)}
                className={cn(
                  "flex items-center gap-2 border px-4 py-2 font-mono text-xs uppercase transition-colors",
                  active
                    ? "border-primary text-primary"
                    : "border-border text-muted-foreground hover:text-foreground",
                )}
              >
                <Icon className="size-4" />
                {t.label}
              </button>
            );
          })}
        </div>

        {tab === "target" ? (
          <InvestigateForm autoFocus />
        ) : (
          <div className="space-y-6">
            <p className="text-sm text-muted-foreground">
              Upload an image to read its metadata, camera details and GPS position. The image is
              analyzed locally in your browser and is never uploaded.
            </p>
            <ImageMetadataTool />
          </div>
        )}
      </div>
    </AppShell>
  );
}
