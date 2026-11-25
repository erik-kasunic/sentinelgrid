import { Link, useNavigate } from "@tanstack/react-router";
import {
  Archive,
  FileText,
  ImageUp,
  LogOut,
  Menu,
  Radar,
  Settings,
  ShieldCheck,
  UserRound,
  X,
} from "lucide-react";
import { useState, type ReactNode } from "react";

import { StatusDot } from "./chrome";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/hooks/useAuth";
import { supabase } from "@/integrations/supabase/client";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/", label: "Investigate", icon: Radar },
  { to: "/metadata", label: "Image metadata", icon: ImageUp },
  { to: "/investigations", label: "Investigations", icon: Archive },
  { to: "/detection", label: "SIEM & Detection", icon: ShieldCheck },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/account", label: "Account", icon: UserRound },
  { to: "/settings", label: "Settings", icon: Settings },
] as const;

export function AppShell({ children }: { children: ReactNode }) {
  const { signedIn, user } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);

  const signOut = async () => {
    await supabase.auth.signOut();
    void navigate({ to: "/" });
  };

  return (
    <div className="relative min-h-screen bg-background md:flex">
      <div className="grid-field pointer-events-none fixed inset-0 opacity-60" aria-hidden />

      <aside className="relative z-30 hidden w-16 shrink-0 flex-col items-center border-r border-border/70 bg-background/90 py-5 backdrop-blur-xl md:flex">
        <Link
          to="/"
          className="glow-primary flex size-10 items-center justify-center border border-primary/50 bg-primary/10 font-mono text-base font-bold text-primary"
          aria-label="SentinelGrid home"
        >
          SG
        </Link>
        <nav className="mt-10 flex flex-col gap-3">
          {NAV.map((item) => {
            const Icon = item.icon;
            return (
              <Link
                key={item.to}
                to={item.to}
                activeOptions={{ exact: item.to === "/" }}
                className="group relative flex size-10 items-center justify-center border border-transparent text-muted-foreground transition-colors hover:border-border-strong hover:bg-secondary hover:text-foreground"
                activeProps={{ className: "border-border-strong bg-secondary text-foreground" }}
                aria-label={item.label}
                title={item.label}
              >
                <Icon className="size-5" />
              </Link>
            );
          })}
        </nav>
        <div className="mt-auto">
          <StatusDot />
        </div>
      </aside>

      <div className="relative z-10 flex min-h-screen min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 border-b border-border/70 bg-background/85 backdrop-blur-xl">
          <div className="flex h-16 items-center gap-4 px-4 sm:px-6">
            <div>
              <Link
                to="/"
                className="font-mono text-sm font-bold text-primary uppercase sm:text-base"
              >
                SentinelGrid <span className="text-primary/65">// OPS CORE</span>
              </Link>
              <p className="mt-0.5 font-sans text-[0.55rem] text-muted-foreground uppercase">
                Investigation terminal active
              </p>
            </div>

            <div className="ml-auto flex items-center gap-3">
              <span className="hidden items-center gap-2 font-mono text-[0.625rem] text-muted-foreground uppercase lg:flex">
                <StatusDot /> system nominal
              </span>
              {signedIn ? (
                <div className="flex items-center gap-2">
                  <span className="hidden max-w-[16ch] truncate font-mono text-xs text-muted-foreground sm:inline">
                    {user?.email}
                  </span>
                  <Button variant="ghost" size="sm" onClick={signOut} className="font-mono text-xs">
                    <LogOut className="size-3.5" />
                    <span className="sr-only sm:not-sr-only">Sign out</span>
                  </Button>
                </div>
              ) : (
                <Button asChild size="sm" variant="outline" className="font-mono text-xs">
                  <Link to="/auth">Sign in</Link>
                </Button>
              )}
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="md:hidden"
                onClick={() => setOpen((v) => !v)}
                aria-label="Toggle navigation"
              >
                {open ? <X className="size-5" /> : <Menu className="size-5" />}
              </Button>
            </div>
          </div>

          {open && (
            <nav className="border-t border-border bg-surface/95 md:hidden">
              {NAV.map((item) => (
                <Link
                  key={item.to}
                  to={item.to}
                  activeOptions={{ exact: item.to === "/" }}
                  onClick={() => setOpen(false)}
                  className="block border-b border-border/60 px-4 py-3 font-mono text-xs tracking-[0.14em] text-muted-foreground uppercase"
                  activeProps={{ className: "text-foreground" }}
                >
                  {item.label}
                </Link>
              ))}
            </nav>
          )}
        </header>

        <main className="w-full flex-1 px-4 py-5 sm:px-6 sm:py-6">{children}</main>

        <footer className="border-t border-border/70 py-3">
          <div
            className={cn(
              "flex flex-wrap items-center gap-x-6 gap-y-2 px-4 sm:px-8",
              "font-mono text-[0.625rem] tracking-[0.16em] text-muted-foreground uppercase",
            )}
          >
            <span className="flex items-center gap-2">
              <StatusDot /> threat engine: ready
            </span>
            <span className="flex items-center gap-2">
              <StatusDot /> correlation engine: active
            </span>
            <span>intelligence sources: 9</span>
            <span className="ml-auto">investigate · correlate · understand · act</span>
          </div>
          <p className="mt-2 px-4 text-[0.6875rem] text-muted-foreground sm:px-8">
            Privacy: indicators you search are sent only to the listed intelligence providers. We
            never contact the target itself. Your IP is stored only as a salted hash for rate
            limiting and results are cached up to 24 h.{" "}
            <Link to="/security" className="underline hover:text-foreground">
              Security & privacy
            </Link>
          </p>
        </footer>
      </div>
    </div>
  );
}
