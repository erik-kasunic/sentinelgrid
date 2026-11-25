// Anonymous investigations are not persisted server-side. They live in this
// session-scoped store so the result page has a single rendering path.

import type { InvestigationResult } from "./types";

const PREFIX = "sentinelgrid:result:";

export function storeLocalResult(result: InvestigationResult): void {
  if (typeof window === "undefined") return;
  try {
    window.sessionStorage.setItem(PREFIX + result.id, JSON.stringify(result));
  } catch {
    // Storage full or unavailable — the result simply won't survive a reload.
  }
}

export function readLocalResult(id: string): InvestigationResult | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.sessionStorage.getItem(PREFIX + id);
    return raw ? (JSON.parse(raw) as InvestigationResult) : null;
  } catch {
    return null;
  }
}

export function clearLocalResult(id: string): void {
  if (typeof window === "undefined") return;
  try {
    window.sessionStorage.removeItem(PREFIX + id);
  } catch {
    /* ignore */
  }
}

// Progressive dashboard reveal: the landing page shows only the search box
// until the visitor has run their first investigation this session.
const SEARCHED_KEY = "sentinelgrid:searched";

export function markSessionSearch(): void {
  if (typeof window === "undefined") return;
  try {
    window.sessionStorage.setItem(SEARCHED_KEY, "1");
  } catch {
    /* ignore */
  }
}

export function hasSessionSearch(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.sessionStorage.getItem(SEARCHED_KEY) === "1";
  } catch {
    return false;
  }
}
