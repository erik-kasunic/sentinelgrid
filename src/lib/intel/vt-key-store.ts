// Analyst's own VirusTotal key: held in JS memory only (never localStorage,
// sessionStorage or cookies). Lost on reload by design.
let key: string | null = null;
const listeners = new Set<() => void>();

export function getVtKey() {
  return key;
}
export function setVtKey(value: string | null) {
  key = value && value.trim() ? value.trim() : null;
  listeners.forEach((l) => l());
}
export function subscribeVtKey(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
