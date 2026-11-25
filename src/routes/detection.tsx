import { createFileRoute } from "@tanstack/react-router";
import { CaseWorkbench } from "@/components/sg/case-workbench";

export const Route = createFileRoute("/detection")({
  ssr: false,
  head: () => ({
    meta: [
      { title: "SIEM & Detection — SentinelGrid" },
      {
        name: "description",
        content:
          "Generate Sentinel, Splunk, Elastic, Falcon, Sigma and Suricata detections from saved cases.",
      },
      { property: "og:title", content: "SIEM & Detection — SentinelGrid" },
      {
        property: "og:description",
        content: "Turn investigation IOCs into ready-to-run hunting queries and rules.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <CaseWorkbench mode="siem" />,
});
