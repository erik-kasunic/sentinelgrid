import { useNavigate } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { Paperclip } from "lucide-react";
import { toast } from "sonner";

import { StatusDot, TerminalLabel } from "./chrome";
import { TypewriterLine } from "./typewriter-line";
import { Turnstile } from "./turnstile";
import { getVtKey, setVtKey, subscribeVtKey } from "@/lib/intel/vt-key-store";
import { Button } from "@/components/ui/button";
import { classify } from "@/lib/intel/classify";
import { markSessionSearch, storeLocalResult } from "@/lib/intel/result-store";
import { TARGET_TYPE_LABEL, type TargetType } from "@/lib/intel/types";
import { investigateTarget } from "@/lib/investigations.functions";
import { cn } from "@/lib/utils";
import { isImageFile, setPendingImage } from "@/lib/pending-image";
import { useAuth } from "@/hooks/useAuth";

const TYPES: (TargetType | "auto")[] = ["auto", "ip", "domain", "url", "hash"];

const STAGES = [
  "classifying input",
  "normalizing target",
  "extracting related IOCs",
  "querying intelligence sources",
  "correlating findings",
  "scoring evidence",
  "requesting AI assessment",
];

async function hashFileSha256(file: File): Promise<string> {
  const buffer = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export function InvestigateForm({ autoFocus = false }: { autoFocus?: boolean }) {
  const [value, setValue] = useState("");
  const [type, setType] = useState<TargetType | "auto">("auto");
  const [running, setRunning] = useState(false);
  const [stage, setStage] = useState(0);
  const [dragActive, setDragActive] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const dragDepth = useRef(0);
  const navigate = useNavigate();
  const run = useServerFn(investigateTarget);
  const [token, setToken] = useState<string | null>(null);
  const [resetSignal, setResetSignal] = useState(0);
  const vtKey = useSyncExternalStore(subscribeVtKey, getVtKey, () => null);
  const { signedIn, loading: authLoading } = useAuth();
  useEffect(() => {
    if (!authLoading && !signedIn && getVtKey()) setVtKey(null);
  }, [authLoading, signedIn]);
  const [keyOpen, setKeyOpen] = useState(false);
  const [keyDraft, setKeyDraft] = useState("");

  useEffect(() => {
    if (autoFocus) inputRef.current?.focus();
  }, [autoFocus]);

  useEffect(() => {
    if (!running) return;
    setStage(0);
    const timer = window.setInterval(() => {
      setStage((current) => Math.min(current + 1, STAGES.length - 1));
    }, 900);
    return () => window.clearInterval(timer);
  }, [running]);

  const detected = useMemo(() => (value.trim() ? classify(value.trim()) : null), [value]);

  const handleFile = async (file: File) => {
    if (isImageFile(file)) {
      setPendingImage(file);
      toast.info(`${file.name} → reading image metadata`);
      void navigate({ to: "/metadata" });
      return;
    }
    try {
      const hash = await hashFileSha256(file);
      setValue(hash);
      setType("hash");
      setFileName(file.name);
      toast.success(`${file.name} → SHA-256 ready for investigation`);
    } catch (error) {
      console.error(error);
      toast.error("The file could not be read. Please try again.");
    }
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    const target = value.trim();
    if (!target || running) return;
    if (!token) {
      toast.error("Vänta tills bot-kontrollen är klar.");
      return;
    }

    setRunning(true);
    try {
      const response = await run({
        data: {
          target,
          turnstileToken: token,
          ...(vtKey ? { vtKey } : {}),
          ...(type === "auto" ? {} : { type }),
        },
      });
      if (!response.ok) {
        toast.error(response.error);
        return;
      }
      storeLocalResult(response.result);
      markSessionSearch();
      void navigate({ to: "/investigate/$id", params: { id: response.result.id } });
    } catch (error) {
      console.error(error);
      toast.error("The investigation could not be completed. Please try again.");
    } finally {
      setRunning(false);
      setResetSignal((n) => n + 1); // tokens are single-use
    }
  };

  return (
    <div
      className={cn(
        "glass-panel relative overflow-hidden border p-5 transition-colors sm:p-6",
        dragActive ? "border-primary" : "border-primary/35 glow-primary",
      )}
      onDragEnter={(event) => {
        event.preventDefault();
        dragDepth.current += 1;
        setDragActive(true);
      }}
      onDragOver={(event) => event.preventDefault()}
      onDragLeave={(event) => {
        event.preventDefault();
        dragDepth.current = Math.max(0, dragDepth.current - 1);
        if (dragDepth.current === 0) setDragActive(false);
      }}
      onDrop={(event) => {
        event.preventDefault();
        dragDepth.current = 0;
        setDragActive(false);
        const file = event.dataTransfer?.files?.[0];
        if (file) void handleFile(file);
      }}
    >
      <span
        className="pointer-events-none absolute left-0 top-0 size-3 border-l border-t border-primary"
        aria-hidden
      />
      <span
        className="pointer-events-none absolute right-0 top-0 size-3 border-r border-t border-primary"
        aria-hidden
      />
      <span
        className="pointer-events-none absolute bottom-0 left-0 size-3 border-b border-l border-primary"
        aria-hidden
      />
      <span
        className="pointer-events-none absolute bottom-0 right-0 size-3 border-b border-r border-primary"
        aria-hidden
      />
      <input
        ref={fileInputRef}
        type="file"
        className="hidden"
        aria-label="Attach file to hash"
        onChange={(event) => {
          const file = event.target.files?.[0];
          if (file) void handleFile(file);
          event.target.value = "";
        }}
      />
      <form onSubmit={submit} className="space-y-5">
        <div className="flex items-center justify-between gap-4">
          <TerminalLabel>Investigation input</TerminalLabel>
          <span className="hidden items-center gap-2 font-mono text-[0.625rem] text-muted-foreground uppercase sm:flex">
            <StatusDot /> engine ready
          </span>
        </div>

        <TypewriterLine
          paused={running || value.trim().length > 0}
          onFill={(example) => {
            setValue(example);
            setFileName(null);
            setType("auto");
            inputRef.current?.focus();
          }}
          onPickFile={() => fileInputRef.current?.click()}
        />

        <div className="flex min-w-0 items-center gap-2 border border-primary/65 bg-background/90 px-3 py-4 shadow-[0_0_22px_-16px_var(--color-primary)] transition-all focus-within:border-primary focus-within:shadow-[0_0_28px_-12px_var(--color-primary)] sm:gap-3 sm:px-5 sm:py-5">
          <span className="shrink-0 font-mono text-xs font-semibold text-primary sm:text-sm">
            sg:~$
          </span>
          <input
            ref={inputRef}
            value={value}
            onChange={(event) => {
              setValue(event.target.value);
              setFileName(null);
            }}
            placeholder="IP, domain, URL, hash — or drop an image for EXIF / metadata"
            spellCheck={false}
            autoComplete="off"
            autoFocus={autoFocus}
            disabled={running}
            className="min-w-0 flex-1 bg-transparent font-mono text-base text-foreground outline-none placeholder:text-muted-foreground/60 sm:text-lg"
            aria-label="Investigation target"
          />
          {!value && !running && <span className="animate-blink font-mono text-primary">_</span>}
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            disabled={running}
            title="Attach a file — it is hashed locally (SHA-256) and investigated"
            aria-label="Attach file"
            className="shrink-0 border border-primary/40 p-1.5 text-primary/80 transition-colors hover:border-primary hover:text-primary disabled:opacity-50"
          >
            <Paperclip className="size-4" />
          </button>
        </div>

        {dragActive && (
          <p className="font-mono text-xs text-primary">
            drop an image for EXIF / GPS — or any file to hash (sha-256) → investigate
          </p>
        )}
        {fileName && !dragActive && (
          <p className="truncate font-mono text-xs text-primary">
            file: {fileName}{" "}
            <span className="text-muted-foreground">→ sha-256 loaded in field</span>
          </p>
        )}

        <div className="flex flex-wrap items-center gap-2">
          {TYPES.map((option) => (
            <button
              key={option}
              type="button"
              onClick={() => setType(option)}
              className={cn(
                "border px-2.5 py-1.5 font-mono text-[0.625rem] uppercase transition-colors",
                type === option
                  ? "border-primary text-primary"
                  : "border-border text-muted-foreground hover:text-foreground",
              )}
            >
              {option === "auto" ? "auto detect" : option}
            </button>
          ))}
          <div className="ml-auto flex flex-wrap items-center justify-end gap-3">
            {detected?.type && type === "auto" && (
              <span className="font-mono text-[0.625rem] tracking-[0.14em] text-primary uppercase">
                detected: {TARGET_TYPE_LABEL[detected.type]}
              </span>
            )}
            <Button
              type="submit"
              disabled={running || !value.trim() || !token}
              className="h-10 rounded-none px-5 font-mono text-xs shadow-[0_0_22px_-8px_var(--color-primary)]"
            >
              {running ? "INVESTIGATING…" : "RUN INVESTIGATION"}
            </Button>
          </div>
        </div>
        <Turnstile onToken={setToken} resetSignal={resetSignal} />

        {signedIn && (
          <div className="border-t border-border/60 pt-3">
            <button
              type="button"
              onClick={() => setKeyOpen((v) => !v)}
              className="font-mono text-[0.625rem] tracking-[0.14em] text-muted-foreground uppercase hover:text-foreground"
            >
              {vtKey ? "own virustotal key: active (memory only)" : "use your own virustotal key"}{" "}
              {keyOpen ? "−" : "+"}
            </button>
            {keyOpen && (
              <div className="mt-3 space-y-2">
                <div className="flex gap-2">
                  <input
                    type="password"
                    value={keyDraft}
                    onChange={(e) => setKeyDraft(e.target.value)}
                    placeholder="64-character VirusTotal API key"
                    autoComplete="off"
                    aria-label="Own VirusTotal API key"
                    className="min-w-0 flex-1 border border-border bg-background/90 px-3 py-2 font-mono text-xs outline-none focus:border-primary"
                  />
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="rounded-none font-mono text-xs"
                    onClick={() => {
                      if (!/^[a-f0-9]{64}$/i.test(keyDraft.trim())) {
                        toast.error("VirusTotal-nycklar är 64 hex-tecken.");
                        return;
                      }
                      setVtKey(keyDraft);
                      setKeyDraft("");
                      toast.success("Nyckeln används i den här fliken tills du laddar om.");
                    }}
                  >
                    Use
                  </Button>
                  {vtKey && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="rounded-none font-mono text-xs"
                      onClick={() => setVtKey(null)}
                    >
                      Clear
                    </Button>
                  )}
                </div>
                <p className="text-[0.6875rem] text-muted-foreground">
                  Kept only in this tab's memory, sent over HTTPS with each search, never saved or
                  logged. Searches with your key bypass the shared cache and quota.
                </p>
              </div>
            )}
          </div>
        )}
      </form>

      {running && (
        <ul className="mt-5 space-y-1.5 border-t border-border/60 pt-4">
          {STAGES.map((label, index) => (
            <li
              key={label}
              className={cn(
                "flex items-center gap-2 font-mono text-xs",
                index < stage
                  ? "text-primary-dim"
                  : index === stage
                    ? "text-primary"
                    : "text-muted-foreground/50",
              )}
            >
              {index === stage ? <StatusDot /> : <span className="w-1.5" />}
              {index < stage ? "[ok] " : index === stage ? "[..] " : "[  ] "}
              {label}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
