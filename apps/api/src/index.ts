import { Hono } from 'hono';
import type { AppEnv, Env } from './env.js';
import { ApiError } from './lib/http.js';
import { applySecurityHeaders, securityHeaders } from './middleware/headers.js';
import { csrf } from './middleware/csrf.js';
import { clientIp } from './middleware/session.js';
import { auth } from './routes/auth.js';
import { vaults } from './routes/vaults.js';
import { users } from './routes/users.js';

// Middleware order (blueprint section 6): security headers → rate-limit context → Origin/CSRF → session → route permissions.
export const app = new Hono<AppEnv>().basePath('/api');
app.use('*', securityHeaders);
app.use('*', clientIp);
app.use('*', csrf);

app.route('/auth', auth);
app.route('/', vaults);
app.route('/', users);

app.notFound((c) => c.json({ error: 'not_found' }, 404));

app.onError((e, c) => {
  if (e instanceof ApiError) return c.json({ error: e.code, ...e.extra }, e.status);
  // Log only the route and error class; never bodies, keys or messages that could carry data.
  console.error(JSON.stringify({ path: c.req.path, status: 500, error: e.name }));
  return c.json({ error: 'internal' }, 500);
});

export default {
  async fetch(req, env, ctx): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname.startsWith('/api/') || url.pathname === '/api') {
      return app.fetch(req, env, ctx);
    }
    // Static frontend (Vite build). Only GET/HEAD.
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return applySecurityHeaders(new Response('method not allowed', { status: 405 }), url.pathname);
    }
    const res = await env.ASSETS.fetch(req);
    return applySecurityHeaders(res, url.pathname);
  },
} satisfies ExportedHandler<Env>;
