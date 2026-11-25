import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/sg/app-shell";
import { TerminalLabel } from "@/components/sg/chrome";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { supabase } from "@/integrations/supabase/client";

export const Route = createFileRoute("/reset-password")({
  ssr: false,
  head: () => ({
    meta: [
      { title: "Reset password — SentinelGrid" },
      { name: "description", content: "Choose a new password for your SentinelGrid account." },
      { property: "og:title", content: "Reset password — SentinelGrid" },
      { property: "og:description", content: "Set a new SentinelGrid account password." },
      { property: "og:type", content: "website" },
      { name: "robots", content: "noindex" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: ResetPasswordPage,
});

function ResetPasswordPage() {
  const navigate = useNavigate();
  const [ready, setReady] = useState(false);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (window.location.hash.includes("type=recovery")) setReady(true);
    const { data } = supabase.auth.onAuthStateChange((event) => {
      if (event === "PASSWORD_RECOVERY") setReady(true);
    });
    return () => data.subscription.unsubscribe();
  }, []);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (busy) return;
    if (password !== confirm) {
      toast.error("Passwords do not match.");
      return;
    }
    if (new TextEncoder().encode(password).length > 72) {
      toast.error("Password is too long — use at most 72 characters.");
      return;
    }
    setBusy(true);
    const { error } = await supabase.auth.updateUser({ password });
    setBusy(false);
    if (error) {
      toast.error(error.message);
      return;
    }
    toast.success("Password updated.");
    void navigate({ to: "/investigations" });
  };

  return (
    <AppShell>
      <div className="mx-auto max-w-md">
        <TerminalLabel>Access control</TerminalLabel>
        <h1 className="mt-3 mb-6 font-mono text-2xl text-foreground">Set new password</h1>
        {!ready ? (
          <p className="border border-border bg-card/70 p-5 font-mono text-xs text-muted-foreground">
            Open this page from the reset link in your email. Links expire after a short time —
            request a new one from Sign in → Forgot password?
          </p>
        ) : (
          <form onSubmit={submit} className="space-y-4 border border-border bg-card/70 p-5">
            <Input
              type="password"
              required
              minLength={6}
              maxLength={72}
              placeholder="New password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="font-mono text-sm"
              autoComplete="new-password"
            />
            <Input
              type="password"
              required
              minLength={6}
              maxLength={72}
              placeholder="Repeat new password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className="font-mono text-sm"
              autoComplete="new-password"
            />
            <Button type="submit" disabled={busy} className="w-full font-mono text-xs">
              {busy ? "WORKING…" : "UPDATE PASSWORD"}
            </Button>
          </form>
        )}
      </div>
    </AppShell>
  );
}
