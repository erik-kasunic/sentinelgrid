import { createFileRoute, Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useEffect, useState } from "react";

import { AppShell } from "@/components/sg/app-shell";
import { EmptyState, Mono, Panel, TerminalLabel, VerdictBadge } from "@/components/sg/chrome";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/hooks/useAuth";
import { FolderPicker } from "@/components/sg/folder-picker";
import { Folder, FolderPlus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import {
  createFolder,
  deleteFolder,
  listFolders,
  listInvestigations,
  type CaseFolder,
  type CaseSummary,
} from "@/lib/investigations.functions";

export const Route = createFileRoute("/investigations")({
  ssr: false,
  head: () => ({
    meta: [
      { title: "Saved investigations — SentinelGrid" },
      {
        name: "description",
        content: "Your saved SentinelGrid cases with verdicts, targets and risk scores.",
      },
      { property: "og:title", content: "Saved investigations — SentinelGrid" },
      { property: "og:description", content: "Review and revisit your saved SOC investigations." },
      { property: "og:type", content: "website" },
      { name: "robots", content: "noindex" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: InvestigationsPage,
});

function InvestigationsPage() {
  const { signedIn, loading: authLoading } = useAuth();
  const list = useServerFn(listInvestigations);
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const folderList = useServerFn(listFolders);
  const create = useServerFn(createFolder);
  const remove = useServerFn(deleteFolder);
  const [folders, setFolders] = useState<CaseFolder[]>([]);
  const [counts, setCounts] = useState({ total: 0, unfiled: 0 });
  const [folder, setFolder] = useState<string | undefined>(undefined); // undefined=all, "none"=unfiled
  const [tick, setTick] = useState(0);
  const refresh = () => setTick((t) => t + 1);

  useEffect(() => {
    if (!signedIn) return;
    void folderList().then((r) => {
      setFolders(r.folders);
      setCounts({ total: r.total, unfiled: r.unfiled });
    });
  }, [signedIn, folderList, tick]);

  const onCreate = async () => {
    const name = window.prompt("Folder name (e.g. Incident #1042)")?.trim();
    if (!name) return;
    const res = await create({ data: { name } });
    if (!res.ok) return void toast.error(res.error);
    setFolder(res.folder.id);
    refresh();
  };

  const onDelete = async (f: CaseFolder) => {
    if (!window.confirm(`Delete folder "${f.name}"? Its ${f.count} case(s) move to Unfiled.`))
      return;
    const res = await remove({ data: { id: f.id } });
    if (!res.ok) return void toast.error(res.error);
    if (folder === f.id) setFolder(undefined);
    refresh();
  };

  useEffect(() => {
    if (authLoading || !signedIn) {
      setLoading(false);
      return;
    }
    let active = true;
    setLoading(true);
    void list({ data: { search: search || undefined, folderId: folder } })
      .then((response) => {
        if (!active) return;
        setCases(response.cases);
      })
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [signedIn, authLoading, search, list, folder, tick]);

  return (
    <AppShell>
      <TerminalLabel>Case library</TerminalLabel>
      <h1 className="mt-3 mb-6 font-mono text-2xl text-foreground">Saved investigations</h1>

      {!signedIn && !authLoading ? (
        <EmptyState>
          sign in to keep investigations —{" "}
          <Link to="/auth" className="text-primary hover:underline">
            sign in
          </Link>
        </EmptyState>
      ) : (
        <div className="grid gap-6 lg:grid-cols-[220px_1fr]">
          <aside className="space-y-1">
            <div className="mb-2 flex items-center justify-between">
              <TerminalLabel>Folders</TerminalLabel>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => void onCreate()}
                aria-label="New folder"
              >
                <FolderPlus className="size-4" />
              </Button>
            </div>
            {[
              { id: undefined, name: "All cases", count: counts.total },
              { id: "none", name: "Unfiled", count: counts.unfiled },
            ].map((f) => (
              <button
                key={f.name}
                onClick={() => setFolder(f.id)}
                className={`flex w-full items-center justify-between px-2 py-1.5 text-left font-mono text-xs ${folder === f.id ? "bg-primary/10 text-primary" : "text-muted-foreground hover:text-foreground"}`}
              >
                <span>{f.name}</span>
                <span>{f.count}</span>
              </button>
            ))}
            {folders.map((f) => (
              <div
                key={f.id}
                className={`group flex items-center ${folder === f.id ? "bg-primary/10" : ""}`}
              >
                <button
                  onClick={() => setFolder(f.id)}
                  className={`flex min-w-0 flex-1 items-center gap-2 px-2 py-1.5 text-left font-mono text-xs ${folder === f.id ? "text-primary" : "text-muted-foreground hover:text-foreground"}`}
                >
                  <Folder className="size-3.5 shrink-0" />
                  <span className="truncate">{f.name}</span>
                  <span className="ml-auto">{f.count}</span>
                </button>
                <button
                  onClick={() => void onDelete(f)}
                  aria-label={`Delete folder ${f.name}`}
                  className="px-1.5 text-muted-foreground opacity-0 group-hover:opacity-100 hover:text-destructive"
                >
                  <Trash2 className="size-3.5" />
                </button>
              </div>
            ))}
          </aside>
          <div className="min-w-0 space-y-4">
            <Input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search by target or title"
              className="max-w-sm font-mono text-sm"
            />

            {loading ? (
              <EmptyState>loading cases…</EmptyState>
            ) : cases.length === 0 ? (
              <EmptyState>no saved cases yet</EmptyState>
            ) : (
              <div className="space-y-3">
                {cases.map((item) => (
                  <Panel key={item.id}>
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0">
                        <Mono className="text-foreground">{item.initial_target}</Mono>
                        <p className="mt-1 font-mono text-[0.625rem] tracking-[0.14em] text-muted-foreground uppercase">
                          {item.target_type} ·{" "}
                          {item.threat_score === null ? "not assessed" : `${item.threat_score}/100`}{" "}
                          · {new Date(item.created_at).toLocaleString()}
                        </p>
                        {item.summary && (
                          <p className="mt-2 max-w-2xl text-xs text-muted-foreground">
                            {item.summary}
                          </p>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <FolderPicker caseId={item.id} value={item.folder_id} onMoved={refresh} />
                        <VerdictBadge verdict={item.verdict} />
                        <Button asChild size="sm" variant="outline" className="font-mono text-xs">
                          <Link to="/investigate/$id" params={{ id: item.id }}>
                            Open
                          </Link>
                        </Button>
                      </div>
                    </div>
                  </Panel>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </AppShell>
  );
}
