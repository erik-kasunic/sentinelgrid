import { useNavigate } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import { toast } from "sonner";

import { Turnstile } from "./turnstile";
import { Button } from "@/components/ui/button";
import { providerName } from "@/lib/intel/provider-meta";
import { storeLocalResult } from "@/lib/intel/result-store";
import type { InvestigationResult } from "@/lib/intel/types";
import { investigateTarget } from "@/lib/investigations.functions";

export function FreshnessBanner({ result }: { result: InvestigationResult }) {
  const [open, setOpen] = useState(false);
  const [token, setToken] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const run = useServerFn(investigateTarget);
  const navigate = useNavigate();

  const refresh = async () => {
    if (!token) return;
    setBusy(true);
    try {
      const res = await run({
        data: {
          target: result.target,
          type: result.targetType,
          turnstileToken: token,
          forceRefresh: true,
        },
      });
      if (!res.ok) {
        toast.error(res.error);
        return;
      }
      storeLocalResult(res.result);
      void navigate({ to: "/investigate/$id", params: { id: res.result.id } });
    } catch {
      toast.error("Uppdateringen misslyckades. Försök igen.");
    } finally {
      setBusy(false);
      setOpen(false);
    }
  };

  const mins = result.cachedAt
    ? Math.max(0, Math.round((Date.now() - new Date(result.cachedAt).getTime()) / 60000))
    : null;

  return (
    <div className="space-y-2">
      {result.degradedProviders?.length ? (
        <p className="border border-warning/50 bg-warning/10 px-4 py-2.5 font-mono text-xs text-warning">
          Degraded mode: using free sources only —{" "}
          {result.degradedProviders.map(providerName).join(", ")} paused to protect the shared daily
          quota.
        </p>
      ) : null}
      {mins !== null && (
        <div className="flex flex-wrap items-center gap-3 border border-border bg-card/50 px-4 py-2.5 font-mono text-xs text-muted-foreground">
          <span>
            Cached {mins < 1 ? "just now" : `${mins} min ago`} — no sources were contacted for this
            view.
          </span>
          {!open ? (
            <Button
              size="sm"
              variant="outline"
              className="ml-auto rounded-none font-mono text-xs"
              onClick={() => setOpen(true)}
            >
              Force refresh
            </Button>
          ) : (
            <div className="ml-auto flex w-full flex-wrap items-center gap-3 sm:w-auto">
              <div className="w-full sm:w-72">
                <Turnstile onToken={setToken} />
              </div>
              <Button
                size="sm"
                className="rounded-none font-mono text-xs"
                disabled={!token || busy}
                onClick={refresh}
              >
                {busy ? "Refreshing…" : "Confirm refresh"}
              </Button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
