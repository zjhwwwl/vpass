import type { MiddlewareHandler } from 'hono';
import type { AppEnv } from '../env.js';

/** Blueprint section 9. Applied to every response, API and static assets alike. */
export const CSP = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "manifest-src 'self'",
  "worker-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "object-src 'none'",
  "require-trusted-types-for 'script'",
  // Only the app's own policy may exist; injected code cannot create a permissive `default` policy.
  'trusted-types vpass',
].join('; ');

export const SECURITY_HEADERS: Record<string, string> = {
  'Content-Security-Policy': CSP,
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
};

export function applySecurityHeaders(res: Response, path: string): Response {
  // Asset responses may be immutable; copy so headers are writable.
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) out.headers.set(k, v);
  const type = out.headers.get('content-type') ?? '';
  if (path.startsWith('/api/') || type.includes('text/html')) {
    out.headers.set('Cache-Control', 'no-store');
  } else if (path === '/sw.js' || path === '/manifest.webmanifest') {
    out.headers.set('Cache-Control', 'no-cache');
  } else if (path.startsWith('/assets/')) {
    out.headers.set('Cache-Control', 'public, max-age=31536000, immutable');
  }
  return out;
}

export const securityHeaders: MiddlewareHandler<AppEnv> = async (c, next) => {
  await next();
  c.res = applySecurityHeaders(c.res, c.req.path);
};
