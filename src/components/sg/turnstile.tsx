import { useEffect, useRef, useState } from "react";

export const TURNSTILE_SITE_KEY = "0x4AAAAAAFLKIOBWbulM5frI";

declare global {
  interface Window {
    turnstile?: {
      render: (el: HTMLElement, opts: Record<string, unknown>) => string;
      reset: (id?: string) => void;
      remove: (id: string) => void;
    };
  }
}

let scriptPromise: Promise<void> | null = null;
function loadScript() {
  if (window.turnstile) return Promise.resolve();
  scriptPromise ??= new Promise<void>((resolve, reject) => {
    const s = document.createElement("script");
    s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    s.async = true;
    s.onload = () => resolve();
    s.onerror = () => reject(new Error("turnstile load failed"));
    document.head.appendChild(s);
  });
  return scriptPromise;
}

/** Cloudflare Turnstile widget. Calls onToken with a fresh token (or null on expiry). */
export function Turnstile({
  onToken,
  resetSignal,
}: {
  onToken: (t: string | null) => void;
  resetSignal?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const idRef = useRef<string | null>(null);
  const cb = useRef(onToken);
  cb.current = onToken;
  const [verified, setVerified] = useState(false);

  useEffect(() => {
    let cancelled = false;
    loadScript()
      .then(() => {
        if (cancelled || !ref.current || !window.turnstile) return;
        idRef.current = window.turnstile.render(ref.current, {
          sitekey: TURNSTILE_SITE_KEY,
          theme: "dark",
          size: "flexible",
          // Only show the widget when Cloudflare actually needs the visitor to interact.
          appearance: "interaction-only",
          callback: (t: string) => {
            setVerified(true);
            cb.current(t);
          },
          "expired-callback": () => {
            setVerified(false);
            cb.current(null);
          },
          "error-callback": () => {
            setVerified(false);
            cb.current(null);
          },
        });
      })
      .catch(() => cb.current(null));
    return () => {
      cancelled = true;
      if (idRef.current && window.turnstile) window.turnstile.remove(idRef.current);
    };
  }, []);

  useEffect(() => {
    if (resetSignal && idRef.current && window.turnstile) {
      setVerified(false);
      cb.current(null);
      window.turnstile.reset(idRef.current);
    }
  }, [resetSignal]);

  // Kept mounted (so reset works) but collapsed once verified.
  return <div ref={ref} className={verified ? "hidden" : undefined} />;
}
