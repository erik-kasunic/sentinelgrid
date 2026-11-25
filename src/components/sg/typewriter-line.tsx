import { useEffect, useState } from "react";

type ExampleAction = { kind: "fill"; value: string } | { kind: "file" };

const LINES: { text: string; action?: ExampleAction; hint?: string }[] = [
  { text: "What are we investigating today?" },
  {
    text: "Paste an IP address → ports, abuse reports, geolocation",
    action: { kind: "fill", value: "8.8.8.8" },
    hint: "[ click → load ]",
  },
  {
    text: "Paste a domain → DNS, WHOIS age, reputation, related infrastructure",
    action: { kind: "fill", value: "example.com" },
    hint: "[ click → load ]",
  },
  {
    text: "Paste a URL → redirect chains, scans, malware checks",
    action: { kind: "fill", value: "http://example.com/secure-login" },
    hint: "[ click → load ]",
  },
  {
    text: "Paste a file hash → 70+ antivirus engines, contacted hosts",
    action: {
      kind: "fill",
      value: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    },
    hint: "[ click → load ]",
  },
  {
    text: "Drop any file → hashed locally (SHA-256), never uploaded",
    action: { kind: "file" },
    hint: "[ click → pick file ]",
  },
  {
    text: "Drop an image → EXIF, camera details, GPS pin on the map",
    action: { kind: "file" },
    hint: "[ click → pick image ]",
  },
];

const TYPE_MS = 38;
const DELETE_MS = 14;
const HOLD_MS = 2100;
const LOADED_MS = 3400;

// Typewriter prompt above the search input. Example lines are clickable:
// fill-lines load a safe example into the input, file-lines open the picker.
export function TypewriterLine({
  paused = false,
  onFill,
  onPickFile,
}: {
  paused?: boolean;
  onFill?: (value: string) => void;
  onPickFile?: () => void;
}) {
  const [text, setText] = useState("");
  const [line, setLine] = useState(0);
  const [phase, setPhase] = useState<"typing" | "holding" | "deleting">("typing");
  const [loaded, setLoaded] = useState<string | null>(null);

  useEffect(() => {
    if (loaded) {
      const timer = window.setTimeout(() => setLoaded(null), LOADED_MS);
      return () => window.clearTimeout(timer);
    }
    if (paused) return;

    const full = LINES[line]?.text ?? "";
    let timer: number;

    if (phase === "typing") {
      if (text.length < full.length) {
        timer = window.setTimeout(() => setText(full.slice(0, text.length + 1)), TYPE_MS);
      } else {
        timer = window.setTimeout(() => setPhase("holding"), 0);
      }
    } else if (phase === "holding") {
      timer = window.setTimeout(() => setPhase("deleting"), HOLD_MS);
    } else {
      if (text.length > 0) {
        timer = window.setTimeout(() => setText(full.slice(0, text.length - 1)), DELETE_MS);
      } else {
        timer = window.setTimeout(() => {
          setLine((l) => (l + 1) % LINES.length);
          setPhase("typing");
        }, 350);
      }
    }
    return () => window.clearTimeout(timer);
  }, [text, line, phase, paused, loaded]);

  if (paused) {
    return (
      <p className="min-h-5 font-mono text-xs text-primary/40 sm:text-sm" aria-hidden>
        <span>sg:~$ </span>
        {LINES[0]?.text}
        <span className="text-primary/30">▌</span>
      </p>
    );
  }

  if (loaded) {
    return (
      <p className="min-h-5 font-mono text-xs text-primary sm:text-sm" aria-live="polite">
        <span className="text-primary/60">sg:~$ </span>
        <span className="text-primary">&gt; {loaded}</span>
        <span className="ml-2 text-muted-foreground">
          {loaded.startsWith("picker")
            ? "choose a file — it never leaves this device"
            : "loaded into input — press run investigation"}
        </span>
        <span className="animate-blink text-primary">▌</span>
      </p>
    );
  }

  const current = LINES[line];

  if (!current?.action) {
    return (
      <p className="min-h-5 font-mono text-xs text-primary/90 sm:text-sm" aria-live="polite">
        <span className="text-primary/60">sg:~$ </span>
        {text}
        <span className="animate-blink text-primary">▌</span>
      </p>
    );
  }

  return (
    <p className="min-h-5 font-mono text-xs sm:text-sm" aria-live="polite">
      <button
        type="button"
        className="group max-w-full cursor-pointer truncate text-left align-baseline"
        title="Click to load this example"
        onClick={() => {
          const action = current.action!;
          if (action.kind === "fill") {
            onFill?.(action.value);
            setLoaded(action.value);
          } else {
            onPickFile?.();
            setLoaded("picker opened");
          }
          setText(current.text);
          setPhase("holding");
        }}
      >
        <span className="text-primary/60 group-hover:text-primary">sg:~$ </span>
        <span className="text-primary/90 underline decoration-primary/40 decoration-dotted underline-offset-4 transition-colors group-hover:text-primary">
          {text}
        </span>
        <span className="ml-2 text-[0.625rem] tracking-[0.14em] text-primary/50 uppercase opacity-0 transition-opacity duration-200 group-hover:opacity-100">
          {current.hint}
        </span>
        <span className="animate-blink text-primary">▌</span>
      </button>
    </p>
  );
}
