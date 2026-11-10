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
  | 'rotate';

export function auditStmt(c: Context<AppEnv>, userId: string | null, event: AuditEvent): D1PreparedStatement {
  return c.env.DB.prepare('INSERT INTO audit_log (user_id, event, ip_hash, created_at) VALUES (?,?,?,?)').bind(userId, event, c.var.ipHash ?? null, now());
}

export async function audit(c: Context<AppEnv>, userId: string | null, event: AuditEvent): Promise<void> {
  await auditStmt(c, userId, event).run();
}

// ---- rate limiting (decisions D-10)

export const WINDOW_MS = 15 * 60 * 1000;
export const MAX_FAILURES_PER_WINDOW = 10;
export const LOCK_AFTER_CONSECUTIVE = 10;
export const LOCK_MS = 15 * 60 * 1000;

const FAIL_EVENTS = "('login_fail','recover_fail')";

/** Throws 429 when this IP or this account had ≥10 failed login/recovery attempts in the last 15 minutes. */
export async function enforceRateLimit(c: Context<AppEnv>, userId: string | null): Promise<void> {
  const since = now() - WINDOW_MS;
  const byIp = await c.env.DB.prepare(`SELECT COUNT(*) AS n FROM audit_log WHERE ip_hash = ? AND event IN ${FAIL_EVENTS} AND created_at > ?`)
    .bind(c.var.ipHash, since)
    .first<{ n: number }>();
  if ((byIp?.n ?? 0) >= MAX_FAILURES_PER_WINDOW) throw err(429, 'rate_limited');
  if (userId) {
    const byUser = await c.env.DB.prepare(`SELECT COUNT(*) AS n FROM audit_log WHERE user_id = ? AND event IN ${FAIL_EVENTS} AND created_at > ?`)
      .bind(userId, since)
      .first<{ n: number }>();
    if ((byUser?.n ?? 0) >= MAX_FAILURES_PER_WINDOW) throw err(429, 'rate_limited');
  }
}

/** Record a failed attempt; lock the account after 10 consecutive failures. */
export async function recordFailure(c: Context<AppEnv>, userId: string | null, event: 'login_fail' | 'recover_fail'): Promise<void> {
  const stmts = [auditStmt(c, userId, event)];
  if (userId) {
    stmts.push(
      c.env.DB.prepare(
        'UPDATE users SET failed_logins = failed_logins + 1, locked_until = CASE WHEN failed_logins + 1 >= ? THEN ? ELSE locked_until END WHERE id = ?',
      ).bind(LOCK_AFTER_CONSECUTIVE, now() + LOCK_MS, userId),
    );
  }
  await c.env.DB.batch(stmts);
}
