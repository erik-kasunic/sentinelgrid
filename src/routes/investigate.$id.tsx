import { createFileRoute, Link, useParams } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useEffect, useState } from "react";

import { AppShell } from "@/components/sg/app-shell";
import { EmptyState } from "@/components/sg/chrome";
import { ResultView } from "@/components/sg/result-view";
import { useAuth } from "@/hooks/useAuth";
import { readLocalResult } from "@/lib/intel/result-store";
import type { InvestigationResult } from "@/lib/intel/types";
import { getInvestigation } from "@/lib/investigations.functions";

export const Route = createFileRoute("/investigate/$id")({
  ssr: false,
  head: () => ({
    meta: [
      { title: "Investigation result — SentinelGrid" },
      {
        name: "description",
        content:
          "Evidence, correlation, deterministic risk score and recommended actions for an investigated indicator.",
      },
      { property: "og:title", content: "Investigation result — SentinelGrid" },
      {
        property: "og:description",
        content: "Explainable risk scoring and SOC recommendations for a security indicator.",
      },
      { property: "og:type", content: "website" },
      { name: "robots", content: "noindex" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: ResultPage,
});

function ResultPage() {
  const { id } = useParams({ from: "/investigate/$id" });
  const { signedIn, loading: authLoading } = useAuth();
  const load = useServerFn(getInvestigation);
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "missing">("loading");

  useEffect(() => {
    const local = readLocalResult(id);
    if (local) {
      setResult(local);
      setState("ready");
      return;
    }
    if (authLoading) return;
    if (!signedIn) {
      setState("missing");
      return;
    }
    let active = true;
    void load({ data: { id } })
      .then((response) => {
        if (!active) return;
        if (response.ok) {
          setResult(response.result);
          setState("ready");
        } else {
          setState("missing");
        }
      })
      .catch(() => active && setState("missing"));
    return () => {
      active = false;
    };
  }, [id, signedIn, authLoading, load]);

  return (
    <AppShell>
      {state === "loading" ? (
        <EmptyState>loading investigation…</EmptyState>
      ) : state === "missing" || !result ? (
        <EmptyState>
          this investigation is not available in this session —{" "}
          <Link to="/" className="text-primary hover:underline">
            run a new one
          </Link>
        </EmptyState>
      ) : (
        <ResultView result={result} />
      )}
    </AppShell>
  );
}
