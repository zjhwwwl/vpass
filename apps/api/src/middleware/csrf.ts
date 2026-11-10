import type { MiddlewareHandler } from 'hono';
import { CSRF_HEADER, CSRF_VALUE } from '@vpass/shared';
import type { AppEnv } from '../env.js';
import { err } from '../lib/http.js';

const SAFE = new Set(['GET', 'HEAD', 'OPTIONS']);

/** Every state-changing request must carry X-Requested-With: vpass and a same-origin Origin. */
export const csrf: MiddlewareHandler<AppEnv> = async (c, next) => {
  if (!SAFE.has(c.req.method)) {
    const origin = c.req.header('Origin');
    const expected = new URL(c.req.url).origin;
    if (c.req.header(CSRF_HEADER) !== CSRF_VALUE || !origin || origin !== expected) {
      throw err(403, 'csrf');
    }
  }
  await next();
};
