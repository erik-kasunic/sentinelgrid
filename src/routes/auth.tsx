import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/sg/app-shell";
import { TerminalLabel } from "@/components/sg/chrome";
import { Turnstile } from "@/components/sg/turnstile";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/hooks/useAuth";
import { supabase } from "@/integrations/supabase/client";

export const Route = createFileRoute("/auth")({
  ssr: false,
  head: () => ({
    meta: [
      { title: "Sign in — SentinelGrid" },
      { name: "description", content: "Sign in to SentinelGrid to save investigations and cases." },
      { property: "og:title", content: "Sign in — SentinelGrid" },
      { property: "og:description", content: "Access your SentinelGrid case library." },
      { property: "og:type", content: "website" },
      { name: "robots", content: "noindex" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: AuthPage,
});

function AuthPage() {
  const { signedIn, loading } = useAuth();
  const navigate = useNavigate();
  const [mode, setMode] = useState<"signin" | "signup" | "forgot">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  // Supabase Auth verifies this Turnstile token (Attack Protection > CAPTCHA). Tokens are
  // single-use, so the widget is reset after every attempt.
  const [captchaToken, setCaptchaToken] = useState<string | null>(null);
  const [captchaReset, setCaptchaReset] = useState(0);

  useEffect(() => {
    if (!loading && signedIn) void navigate({ to: "/investigations" });
  }, [loading, signedIn, navigate]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (busy) return;
    if (mode !== "forgot" && new TextEncoder().encode(password).length > 72) {
      toast.error("Password is too long — use at most 72 characters.");
      return;
    }
    if (!captchaToken) {
      toast.error("Wait for the bot check to finish.");
      return;
    }
    const captcha = captchaToken;
    setBusy(true);
    try {
      if (mode === "signin") {
        const { error } = await supabase.auth.signInWithPassword({
          email,
          password,
          options: { captchaToken: captcha },
        });
        if (error) {
          toast.error(
            error.message === "Invalid login credentials"
              ? "Wrong email or password. Use “Forgot password?” if you can't remember it."
              : error.message,
          );
          return;
        }
        toast.success("Signed in.");
      } else if (mode === "signup") {
        const { error } = await supabase.auth.signUp({
          email,
          password,
          options: { emailRedirectTo: window.location.origin, captchaToken: captcha },
        });
        if (error) {
          toast.error(error.message);
          return;
        }
        // Same message whether or not the address already exists, so nobody can probe which emails are registered.
        toast.success(
          "If this email can be registered, a confirmation link is on its way. Already have an account? Sign in or reset your password.",
        );
      } else {
        const { error } = await supabase.auth.resetPasswordForEmail(email, {
          redirectTo: `${window.location.origin}/reset-password`,
          captchaToken: captcha,
        });
        if (error) {
          toast.error(error.message);
          return;
        }
        toast.success("If an account exists for this email, a reset link has been sent.");
        setMode("signin");
      }
    } finally {
      setBusy(false);
      setCaptchaReset((n) => n + 1);
    }
  };

  const title =
    mode === "signin" ? "Sign in" : mode === "signup" ? "Create account" : "Reset password";
  const cta =
    mode === "signin" ? "SIGN IN" : mode === "signup" ? "CREATE ACCOUNT" : "SEND RESET LINK";

  return (
    <AppShell>
      <div className="mx-auto max-w-md">
        <TerminalLabel>Access control</TerminalLabel>
        <h1 className="mt-3 mb-6 font-mono text-2xl text-foreground">{title}</h1>

        <form onSubmit={submit} className="space-y-4 border border-border bg-card/70 p-5">
          <div className="space-y-1.5">
            <label
              htmlFor="email"
              className="font-mono text-[0.625rem] tracking-[0.14em] text-muted-foreground uppercase"
            >
              Email
            </label>
            <Input
              id="email"
              type="email"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              className="font-mono text-sm"
              autoComplete="email"
            />
          </div>
          {mode !== "forgot" && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label
                  htmlFor="password"
                  className="font-mono text-[0.625rem] tracking-[0.14em] text-muted-foreground uppercase"
                >
                  Password
                </label>
                {mode === "signin" && (
                  <button
                    type="button"
                    onClick={() => setMode("forgot")}
                    className="font-mono text-[0.625rem] text-muted-foreground hover:text-primary"
                  >
                    Forgot password?
                  </button>
                )}
              </div>
              <Input
                id="password"
                type="password"
                required
                minLength={6}
                maxLength={72}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className="font-mono text-sm"
                autoComplete={mode === "signin" ? "current-password" : "new-password"}
              />
              {mode === "signup" && (
                <p className="font-mono text-[0.625rem] text-muted-foreground">6–72 characters.</p>
              )}
            </div>
          )}
          <Turnstile onToken={setCaptchaToken} resetSignal={captchaReset} />
          <Button
            type="submit"
            disabled={busy || !captchaToken}
            className="w-full font-mono text-xs"
          >
            {busy ? "WORKING…" : cta}
          </Button>
          <button
            type="button"
            onClick={() => setMode(mode === "signin" ? "signup" : "signin")}
            className="w-full text-center font-mono text-xs text-muted-foreground hover:text-primary"
          >
            {mode === "signin" ? "Need an account? Sign up" : "Back to sign in"}
          </button>
        </form>
      </div>
    </AppShell>
  );
}
