import { createFileRoute, Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useEffect, useState } from "react";

import { AppShell } from "@/components/sg/app-shell";
import { EmptyState, Panel, TerminalLabel, VerdictBadge } from "@/components/sg/chrome";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/hooks/useAuth";
import { listInvestigations, type CaseSummary } from "@/lib/investigations.functions";

export const Route = createFileRoute("/account")({
  ssr: false,
  head: () => ({
    meta: [
      { title: "Account overview — SentinelGrid" },
      { name: "description", content: "Your SentinelGrid account and saved investigations." },
      { property: "og:title", content: "Account overview — SentinelGrid" },
      {
        property: "og:description",
        content: "See your account and saved SOC investigations in one place.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
      { name: "robots", content: "noindex" },
    ],
  }),
  component: AccountPage,
});

function AccountPage() {
  const { signedIn, user, loading: authLoading } = useAuth();
  const list = useServerFn(listInvestigations);
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!signedIn) return;
    setLoading(true);
    void list({ data: { limit: 50 } })
      .then((r) =>
        setCases((r as { cases?: CaseSummary[] }).cases ?? (r as unknown as CaseSummary[])),
      )
      .finally(() => setLoading(false));
  }, [signedIn, list]);

  if (authLoading)
    return (
      <AppShell>
        <EmptyState>Loading account…</EmptyState>
      </AppShell>
    );
  if (!signedIn) {
    return (
      <AppShell>
        <Panel title="Account">
          <EmptyState>Sign in to see your account overview</EmptyState>
          <div className="mt-4 flex justify-center">
            <Button asChild>
              <Link to="/auth">Sign in</Link>
            </Button>
          </div>
        </Panel>
      </AppShell>
    );
  }

  const assessed = cases.filter((c) => c.verdict_basis === "evaluated").length;
  return (
    <AppShell>
      <div className="space-y-6">
        <div>
          <TerminalLabel>Account overview</TerminalLabel>
          <h1 className="mt-2 text-2xl font-semibold">{user?.email}</h1>
          <p className="mt-1 font-mono text-xs text-muted-foreground">
            Member since {user?.created_at ? new Date(user.created_at).toLocaleDateString() : "—"}
          </p>
        </div>
        <div className="grid gap-3 sm:grid-cols-3">
          <Stat label="Saved cases" value={cases.length} />
          <Stat label="Assessed" value={assessed} />
          <Stat label="Unknown" value={cases.length - assessed} />
        </div>
        <Panel
          title="Saved investigations"
          aside={
            <Link to="/investigations" className="font-mono text-xs text-primary underline">
              Manage folders →
            </Link>
          }
        >
          {loading ? (
            <EmptyState>Loading cases…</EmptyState>
          ) : cases.length === 0 ? (
            <EmptyState>No saved investigations yet</EmptyState>
          ) : (
            <ul className="divide-y divide-border">
              {cases.map((c) => (
                <li key={c.id}>
                  <Link
                    to="/investigate/$id"
                    params={{ id: c.id }}
                    className="flex items-center justify-between gap-3 py-3 hover:bg-primary/5"
                  >
                    <div className="min-w-0">
                      <div className="truncate font-mono text-sm">{c.initial_target}</div>
                      <div className="font-mono text-[11px] text-muted-foreground uppercase">
                        {c.target_type} · {new Date(c.created_at).toLocaleString()}
                      </div>
                    </div>
                    <VerdictBadge verdict={c.verdict} size="sm" />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </AppShell>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="border border-border bg-card/60 p-4">
      <div className="font-mono text-[11px] tracking-[0.16em] text-muted-foreground uppercase">
        {label}
      </div>
      <div className="mt-1 font-mono text-2xl text-primary">{value}</div>
    </div>
  );
}
