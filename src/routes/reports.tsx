import { createFileRoute } from "@tanstack/react-router";
import { CaseWorkbench } from "@/components/sg/case-workbench";

export const Route = createFileRoute("/reports")({
  ssr: false,
  head: () => ({
    meta: [
      { title: "Incident reports — SentinelGrid" },
      {
        name: "description",
        content: "Export saved SentinelGrid cases as formal PDF incident reports.",
      },
      { property: "og:title", content: "Incident reports — SentinelGrid" },
      {
        property: "og:description",
        content: "Executive summary, evidence, sources and IOC appendix in one PDF.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <CaseWorkbench mode="report" />,
});
