import { createStart, createCsrfMiddleware, createMiddleware } from "@tanstack/react-start";

import { renderErrorPage } from "./lib/error-page";
import { attachSupabaseAuth } from "@/integrations/supabase/auth-attacher";

const errorMiddleware = createMiddleware().server(async ({ next }) => {
  try {
    return await next();
  } catch (error) {
    if (error != null && typeof error === "object" && "statusCode" in error) {
      throw error;
    }
    console.error(error);
    return new Response(renderErrorPage(), {
      status: 500,
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }
});

// Security headers on every response. CSP + frame-ancestors only in production
// builds: the editor preview runs the dev server inside an iframe.
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com data:",
  "img-src 'self' data: blob: https:",
  "connect-src 'self' https://*.supabase.co wss://*.supabase.co https://challenges.cloudflare.com",
  "frame-src https://challenges.cloudflare.com",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
].join("; ");

const securityHeadersMiddleware = createMiddleware().server(async ({ next }) => {
  const result = await next();
  const response = (result as { response?: Response }).response ?? (result as unknown as Response);
  if (response instanceof Response) {
    try {
      response.headers.set("X-Content-Type-Options", "nosniff");
      response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
      response.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
      if (!import.meta.env.DEV) {
        response.headers.set("Content-Security-Policy", CSP);
        response.headers.set("X-Frame-Options", "DENY");
      }
    } catch {
      // immutable headers (e.g. redirects) — skip
    }
  }
  return result;
});

// Start installs this automatically when src/start.ts is absent; defining the
// file opts out, so re-add it explicitly to keep server functions protected
// from cross-site requests.
const csrfMiddleware = createCsrfMiddleware({
  filter: (ctx) => ctx.handlerType === "serverFn",
});

// Refuse oversized request bodies before they are parsed. Every server function takes small
// JSON (the largest is a saved case, capped at 512 KB in the database).
const MAX_BODY_BYTES = 1_000_000;
const bodyLimitMiddleware = createMiddleware().server(async ({ next, request }) => {
  const declared = Number(request.headers.get("content-length") ?? 0);
  if (declared > MAX_BODY_BYTES) {
    return new Response("Payload too large", { status: 413 });
  }
  return next();
});

export const startInstance = createStart(() => ({
  functionMiddleware: [attachSupabaseAuth],
  requestMiddleware: [
    bodyLimitMiddleware,
    securityHeadersMiddleware,
    errorMiddleware,
    csrfMiddleware,
  ],
}));
