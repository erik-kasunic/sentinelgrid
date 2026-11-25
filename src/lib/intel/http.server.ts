// Shared, timeout-bounded fetch for provider adapters. One slow or hanging
// source must never stall an investigation.

const DEFAULT_TIMEOUT_MS = 9000;

export class ProviderHttpError extends Error {
  status?: number | undefined;
  constructor(message: string, status?: number) {
    super(message);
    this.name = "ProviderHttpError";
    this.status = status;
  }
}

export async function fetchJson<T>(
  url: string,
  init: RequestInit & { timeoutMs?: number } = {},
): Promise<T> {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, ...rest } = init;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      ...rest,
      signal: controller.signal,
      headers: { accept: "application/json", ...(rest.headers ?? {}) },
    });
    if (!response.ok) {
      throw new ProviderHttpError(`HTTP ${response.status}`, response.status);
    }
    return (await response.json()) as T;
  } catch (error) {
    if (error instanceof ProviderHttpError) throw error;
    if (error instanceof Error && error.name === "AbortError") {
      throw new ProviderHttpError(`Request timed out after ${timeoutMs}ms`);
    }
    throw new ProviderHttpError(error instanceof Error ? error.message : "Request failed");
  } finally {
    clearTimeout(timer);
  }
}

export function nowIso(): string {
  return new Date().toISOString();
}
