import type { Context } from 'hono';
import type { AppEnv } from '../env.js';
import { err, now } from '../lib/http.js';

export type AuditEvent =
  | 'login_ok'
  | 'login_fail'
  | 'register'
  | 'pw_change'
  | 'recover_ok'
  | 'recover_fail'
  | 'recovery_code_change'
  | 'totp_enable'
  | 'totp_disable'
  | 'session_revoke'
  | 'invite_create'
  | 'vault_create'
  | 'share'
  | 'rotate'
  | 'lookup';

export function auditStmt(c: Context<AppEnv>, userId: string | null, event: AuditEvent): D1PreparedStatement {
  return c.env.DB.prepare('INSERT INTO audit_log (user_id, event, ip_hash, created_at) VALUES (?,?,?,?)').bind(userId, event, c.var.ipHash ?? null, now());
}

export async function audit(c: Context<AppEnv>, userId: string | null, event: AuditEvent): Promise<void> {
  await auditStmt(c, userId, event).run();
}

// ---- rate limiting (decisions D-10, revised in D-23 after the P6 review)
//
// Failures are counted per IP hash and per *email key* (HMAC of the normalized email), never per user row, so an
// existing and a non-existent account behave identically (no enumeration). There is no hard account lock: a
// distributed attacker could otherwise keep a friend locked out forever. Instead:
//   - one IP: at most 10 failed login/recovery attempts per 15 minutes;
//   - one email (from all IPs together): at most 30 per 15 minutes;
// plus the Cloudflare WAF rule on /api/auth/*. Every refusal is the same `rate_limited`.

export const WINDOW_MS = 15 * 60 * 1000;
export const MAX_FAILURES_PER_IP = 10;
export const MAX_FAILURES_PER_EMAIL = 30;

const FAIL_EVENTS = "('login_fail','recover_fail')";

export async function enforceRateLimit(c: Context<AppEnv>, emailKey: string | null): Promise<void> {
  const since = now() - WINDOW_MS;
  const byIp = await c.env.DB.prepare(`SELECT COUNT(*) AS n FROM audit_log WHERE ip_hash = ? AND event IN ${FAIL_EVENTS} AND created_at > ?`)
    .bind(c.var.ipHash, since)
    .first<{ n: number }>();
  if ((byIp?.n ?? 0) >= MAX_FAILURES_PER_IP) throw err(429, 'rate_limited');
  if (emailKey) {
    const byEmail = await c.env.DB.prepare(`SELECT COUNT(*) AS n FROM audit_log WHERE user_id = ? AND event IN ${FAIL_EVENTS} AND created_at > ?`)
      .bind(emailKey, since)
      .first<{ n: number }>();
    if ((byEmail?.n ?? 0) >= MAX_FAILURES_PER_EMAIL) throw err(429, 'rate_limited');
  }
}

/** Record a failed attempt against the IP and the email key (the same for existing and unknown accounts). */
export async function recordFailure(c: Context<AppEnv>, emailKey: string | null, event: 'login_fail' | 'recover_fail'): Promise<void> {
  await auditStmt(c, emailKey, event).run();
}
