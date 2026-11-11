import type { Context, MiddlewareHandler } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import type { AppEnv } from '../env.js';
import { randomToken, sha256Hex, ipHash } from '../lib/crypto.js';
import { err, now } from '../lib/http.js';

export const COOKIE = '__Host-session';
/** decisions D-14 */
export const SESSION_ABSOLUTE_MS = 30 * 24 * 3600 * 1000;
export const SESSION_IDLE_MS = 14 * 24 * 3600 * 1000;
const TOUCH_EVERY_MS = 5 * 60 * 1000;

export async function createSession(c: Context<AppEnv>, userId: string, deviceLabel: string | undefined): Promise<string> {
  const token = randomToken(32);
  const tokenHash = await sha256Hex(token);
  const t = now();
  await c.env.DB.prepare('INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at, device_label) VALUES (?,?,?,?,?,?)')
    .bind(tokenHash, userId, t, t, t + SESSION_ABSOLUTE_MS, deviceLabel ?? deviceFromUA(c.req.header('User-Agent')))
    .run();
  setCookie(c, COOKIE, token, { httpOnly: true, secure: true, sameSite: 'Strict', path: '/', maxAge: SESSION_ABSOLUTE_MS / 1000 });
  return tokenHash;
}

export function clearSessionCookie(c: Context<AppEnv>): void {
  deleteCookie(c, COOKIE, { path: '/', secure: true });
}

function deviceFromUA(ua: string | undefined): string | null {
  if (!ua) return null;
  const os = /Windows/.test(ua) ? 'Windows' : /iPhone|iPad/.test(ua) ? 'iOS' : /Android/.test(ua) ? 'Android' : /Mac OS X/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'Unknown';
  const br = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  return `${br} · ${os}`;
}

/** Sets c.var.ipHash for rate limiting and audit. */
export const clientIp: MiddlewareHandler<AppEnv> = async (c, next) => {
  const ip = c.req.header('CF-Connecting-IP') ?? 'local';
  c.set('ipHash', await ipHash(c.env.AUTH_PEPPER, ip));
  await next();
};

/** Resolve the session cookie. 401 when missing/expired. */
export const requireSession: MiddlewareHandler<AppEnv> = async (c, next) => {
  const token = getCookie(c, COOKIE);
  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) throw err(401, 'unauthorized');
  const tokenHash = await sha256Hex(token);
  const row = await c.env.DB.prepare(
    'SELECT s.user_id, s.last_seen_at, s.expires_at, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?',
  )
    .bind(tokenHash)
    .first<{ user_id: string; last_seen_at: number; expires_at: number; email: string }>();
  const t = now();
  if (!row || row.expires_at <= t || row.last_seen_at + SESSION_IDLE_MS <= t) {
    if (row) await c.env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(tokenHash).run();
    clearSessionCookie(c);
    throw err(401, 'unauthorized');
  }
  if (t - row.last_seen_at > TOUCH_EVERY_MS) {
    await c.env.DB.prepare('UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?').bind(t, tokenHash).run();
  }
  c.set('session', { tokenHash, userId: row.user_id, email: row.email });
  await next();
};

export function isAdmin(c: Context<AppEnv>, userId: string): boolean {
  return (c.env.ADMIN_USER_IDS ?? '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
    .includes(userId.toLowerCase());
}
