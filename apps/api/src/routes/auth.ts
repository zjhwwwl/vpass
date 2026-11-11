import { Hono, type Context } from 'hono';
import {
  loginReq,
  passwordChangeReq,
  preloginReq,
  recoverReq,
  recoverStartReq,
  recoveryCodeReq,
  registerReq,
  totpDisableReq,
  totpEnableReq,
  type SessionInfo,
} from '@vpass/shared';
import { fromB64u, toBase32Rfc4648 } from '@vpass/crypto/encoding';
import { otpauthUri, verifyTotp } from '@vpass/crypto/totp';
import type { AppEnv } from '../env.js';
import { decryptTotpSecret, emailKey, encryptTotpSecret, fakeSalt, hmacB64, sha256Hex, timingSafeEqualB64 } from '../lib/crypto.js';
import { body, err, now } from '../lib/http.js';
import { audit, auditStmt, enforceRateLimit, recordFailure } from '../db/audit.js';
import { keyBundle, totpState, userByEmail, userById, type UserRow } from '../db/users.js';
import { clearSessionCookie, createSession, requireSession } from '../middleware/session.js';
import { DEFAULT_KDF_PARAMS_JSON } from '../lib/constants.js';

export const auth = new Hono<AppEnv>();

const authHmac = (c: Context<AppEnv>, authHash: string) => hmacB64(c.env.AUTH_PEPPER, 'auth', fromB64u(authHash));
const recoveryHmac = (c: Context<AppEnv>, recoveryAuth: string) => hmacB64(c.env.AUTH_PEPPER, 'recovery', fromB64u(recoveryAuth));

/** A dummy HMAC to compare against for unknown users, so timing doesn't reveal existence. */
const DUMMY_HMAC = 'A'.repeat(43);

async function verifyAuthHash(c: Context<AppEnv>, u: UserRow | null, authHash: string): Promise<boolean> {
  const got = await authHmac(c, authHash);
  return timingSafeEqualB64(got, u?.auth_hmac ?? DUMMY_HMAC) && u !== null;
}

// POST /api/auth/prelogin — unknown emails get a stable fake salt (D-06).
auth.post('/prelogin', async (c) => {
  const { email } = await body(c, preloginReq);
  const u = await userByEmail(c, email);
  if (u) return c.json({ kdfSalt: u.kdf_salt, kdfParams: JSON.parse(u.kdf_params) });
  return c.json({ kdfSalt: await fakeSalt(c.env.AUTH_PEPPER, email), kdfParams: JSON.parse(DEFAULT_KDF_PARAMS_JSON) });
});

// POST /api/auth/register — invite-only.
auth.post('/register', async (c) => {
  const r = await body(c, registerReq);
  await enforceRateLimit(c, null);
  const t = now();
  const codeHash = await sha256Hex(normalizeInvite(r.inviteCode));
  const invite = await c.env.DB.prepare('SELECT used_by, expires_at FROM invites WHERE code_hash = ?').bind(codeHash).first<{ used_by: string | null; expires_at: number }>();
  if (!invite || invite.used_by !== null || invite.expires_at <= t) {
    await recordFailure(c, null, 'login_fail');
    throw err(400, 'invalid_invite');
  }
  if (await userByEmail(c, r.email)) throw err(409, 'email_taken');
  const clash = await c.env.DB.prepare('SELECT (SELECT COUNT(*) FROM users WHERE id = ?) + (SELECT COUNT(*) FROM vaults WHERE id = ?) AS n')
    .bind(r.userId, r.personalVault.id)
    .first<{ n: number }>();
  if ((clash?.n ?? 0) > 0) throw err(409, 'conflict');

  const db = c.env.DB;
  try {
    // One transaction. The user row is only inserted while the invite is still unused; if it was consumed
    // concurrently, the vault insert violates its FK and the whole batch rolls back.
    await db.batch([
      db
        .prepare(
          `INSERT INTO users (id, email, kdf_salt, kdf_params, auth_hmac, wrapped_account_key, recovery_wrapped_key, recovery_auth_hmac, public_key, wrapped_private_key, created_at)
           SELECT ?,?,?,?,?,?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM invites WHERE code_hash = ? AND used_by IS NULL AND expires_at > ?)`,
        )
        .bind(
          r.userId,
          r.email,
          r.kdfSalt,
          JSON.stringify(r.kdfParams),
          await authHmac(c, r.authHash),
          r.wrappedAccountKey,
          r.recoveryWrappedKey,
          await recoveryHmac(c, r.recoveryAuth),
          r.publicKey,
          r.wrappedPrivateKey,
          t,
          codeHash,
          t,
        ),
      db.prepare('UPDATE invites SET used_by = ? WHERE code_hash = ? AND used_by IS NULL').bind(r.userId, codeHash),
      db.prepare("INSERT INTO vaults (id, owner_id, kind, name_enc, revision, created_at) VALUES (?, ?, 'personal', NULL, 0, ?)").bind(r.personalVault.id, r.userId, t),
      db.prepare("INSERT INTO vault_members (vault_id, user_id, sealed_vault_key, key_epoch, role) VALUES (?, ?, ?, 0, 'owner')").bind(r.personalVault.id, r.userId, r.personalVault.sealedVaultKey),
      auditStmt(c, r.userId, 'register'),
    ]);
  } catch {
    throw err(409, 'conflict');
  }
  await createSession(c, r.userId, r.deviceLabel);
  const u = (await userById(c, r.userId))!;
  return c.json(keyBundle(c, u), 201);
});

export function normalizeInvite(code: string): string {
  return code.trim().toUpperCase().replace(/[\s-]/g, '');
}

// POST /api/auth/login
auth.post('/login', async (c) => {
  const r = await body(c, loginReq);
  const ek = await emailKey(c.env.AUTH_PEPPER, r.email);
  await enforceRateLimit(c, ek);
  const u = await userByEmail(c, r.email);
  const t = now();
  const ok = await verifyAuthHash(c, u, r.authHash);
  if (!ok || !u) {
    await recordFailure(c, ek, 'login_fail');
    throw err(401, 'invalid_credentials');
  }
  const totp = totpState(u);
  if (totp?.enabled) {
    if (!r.totp) throw err(401, 'totp_required');
    const secret = await decryptTotpSecret(c.env.TOTP_ENC_KEY, u.id, totp);
    const counter = await verifyTotp(secret, r.totp, Math.floor(t / 1000));
    if (counter === null || counter <= totp.lastCounter) {
      await recordFailure(c, ek, 'login_fail');
      throw err(401, 'invalid_credentials');
    }
    // Compare-and-swap on the stored state, so two concurrent requests cannot both spend the same code.
    const swap = await c.env.DB.prepare('UPDATE users SET totp_secret_enc = ? WHERE id = ? AND totp_secret_enc = ?')
      .bind(JSON.stringify({ ...totp, lastCounter: counter }), u.id, u.totp_secret_enc)
      .run();
    if (swap.meta.changes !== 1) {
      await recordFailure(c, ek, 'login_fail');
      throw err(401, 'invalid_credentials');
    }
  }
  await c.env.DB.batch([
    c.env.DB.prepare('UPDATE users SET failed_logins = 0 WHERE id = ?').bind(u.id),
    auditStmt(c, u.id, 'login_ok'),
  ]);
  await createSession(c, u.id, r.deviceLabel);
  return c.json(keyBundle(c, u));
});

// POST /api/auth/recover/start — prove knowledge of the recovery code, receive the recovery-wrapped key (D-07).
auth.post('/recover/start', async (c) => {
  const r = await body(c, recoverStartReq);
  const u = await checkRecovery(c, r.email, r.recoveryAuth);
  return c.json({ userId: u.id, recoveryWrappedKey: u.recovery_wrapped_key, publicKey: u.public_key, wrappedPrivateKey: u.wrapped_private_key });
});

async function checkRecovery(c: Context<AppEnv>, email: string, recoveryAuth: string): Promise<UserRow> {
  const ek = await emailKey(c.env.AUTH_PEPPER, email);
  await enforceRateLimit(c, ek);
  const u = await userByEmail(c, email);
  const got = await recoveryHmac(c, recoveryAuth);
  if (!timingSafeEqualB64(got, u?.recovery_auth_hmac ?? DUMMY_HMAC) || !u) {
    await recordFailure(c, ek, 'recover_fail');
    throw err(401, 'invalid_credentials');
  }
  return u;
}

// POST /api/auth/recover — new password, new Secret Key, new recovery code; all sessions revoked.
auth.post('/recover', async (c) => {
  const r = await body(c, recoverReq);
  const u = await checkRecovery(c, r.email, r.recoveryAuth);
  const db = c.env.DB;
  await db.batch([
    db
      .prepare(
        'UPDATE users SET kdf_salt = ?, kdf_params = ?, auth_hmac = ?, wrapped_account_key = ?, recovery_wrapped_key = ?, recovery_auth_hmac = ?, failed_logins = 0 WHERE id = ?',
      )
      .bind(r.kdfSalt, JSON.stringify(r.kdfParams), await authHmac(c, r.authHash), r.wrappedAccountKey, r.newRecoveryWrappedKey, await recoveryHmac(c, r.newRecoveryAuth), u.id),
    db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(u.id),
    auditStmt(c, u.id, 'recover_ok'),
  ]);
  await createSession(c, u.id, r.deviceLabel);
  return c.json(keyBundle(c, (await userById(c, u.id))!));
});

// ---------------------------------------------------------------- session-protected below

auth.use('/logout', requireSession);
auth.use('/sessions', requireSession);
auth.use('/sessions/*', requireSession);
auth.use('/password', requireSession);
auth.use('/recovery-code', requireSession);
auth.use('/totp/*', requireSession);
auth.use('/me', requireSession);

auth.get('/me', async (c) => {
  const u = await userById(c, c.var.session.userId);
  if (!u) throw err(401, 'unauthorized');
  return c.json(keyBundle(c, u));
});

auth.post('/logout', async (c) => {
  await c.env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(c.var.session.tokenHash).run();
  clearSessionCookie(c);
  return c.json({ ok: true });
});

auth.get('/sessions', async (c) => {
  const { results } = await c.env.DB.prepare(
    'SELECT token_hash, created_at, last_seen_at, expires_at, device_label FROM sessions WHERE user_id = ? ORDER BY last_seen_at DESC',
  )
    .bind(c.var.session.userId)
    .all<{ token_hash: string; created_at: number; last_seen_at: number; expires_at: number; device_label: string | null }>();
  const out: SessionInfo[] = results.map((s) => ({
    id: s.token_hash,
    createdAt: s.created_at,
    lastSeenAt: s.last_seen_at,
    expiresAt: s.expires_at,
    deviceLabel: s.device_label,
    current: s.token_hash === c.var.session.tokenHash,
  }));
  return c.json({ sessions: out });
});

auth.delete('/sessions/:id', async (c) => {
  const id = c.req.param('id');
  const res = await c.env.DB.prepare('DELETE FROM sessions WHERE token_hash = ? AND user_id = ?').bind(id, c.var.session.userId).run();
  if (res.meta.changes === 0) throw err(404, 'not_found');
  await audit(c, c.var.session.userId, 'session_revoke');
  return c.json({ ok: true });
});

async function requireAuthHash(c: Context<AppEnv>, authHash: string): Promise<UserRow> {
  const ek = await emailKey(c.env.AUTH_PEPPER, c.var.session.email);
  await enforceRateLimit(c, ek);
  const u = await userById(c, c.var.session.userId);
  if (!u || !(await verifyAuthHash(c, u, authHash))) {
    await recordFailure(c, ek, 'login_fail');
    throw err(401, 'invalid_credentials');
  }
  return u;
}

// POST /api/auth/password — change password or rotate Secret Key; revokes all other sessions.
auth.post('/password', async (c) => {
  const r = await body(c, passwordChangeReq);
  const u = await requireAuthHash(c, r.oldAuthHash);
  const db = c.env.DB;
  await db.batch([
    db
      .prepare('UPDATE users SET kdf_salt = ?, kdf_params = ?, auth_hmac = ?, wrapped_account_key = ? WHERE id = ?')
      .bind(r.kdfSalt, JSON.stringify(r.kdfParams), await authHmac(c, r.authHash), r.wrappedAccountKey, u.id),
    db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?').bind(u.id, c.var.session.tokenHash),
    auditStmt(c, u.id, 'pw_change'),
  ]);
  return c.json(keyBundle(c, (await userById(c, u.id))!));
});

// POST /api/auth/recovery-code — replace the recovery wrapping (D-12).
auth.post('/recovery-code', async (c) => {
  const r = await body(c, recoveryCodeReq);
  const u = await requireAuthHash(c, r.authHash);
  await c.env.DB.batch([
    c.env.DB.prepare('UPDATE users SET recovery_wrapped_key = ?, recovery_auth_hmac = ? WHERE id = ?').bind(r.recoveryWrappedKey, await recoveryHmac(c, r.recoveryAuth), u.id),
    auditStmt(c, u.id, 'recovery_code_change'),
  ]);
  return c.json({ ok: true });
});

// ---- login TOTP (second factor for the account, not item TOTP)

auth.post('/totp/setup', async (c) => {
  const u = (await userById(c, c.var.session.userId))!;
  if (totpState(u)?.enabled) throw err(409, 'conflict');
  const secret = new Uint8Array(20);
  crypto.getRandomValues(secret);
  const enc = await encryptTotpSecret(c.env.TOTP_ENC_KEY, u.id, secret);
  await c.env.DB.prepare('UPDATE users SET totp_secret_enc = ? WHERE id = ?').bind(JSON.stringify({ enabled: false, lastCounter: 0, ...enc }), u.id).run();
  return c.json({ secret: toBase32Rfc4648(secret), uri: otpauthUri(secret, u.email) });
});

auth.post('/totp/enable', async (c) => {
  const r = await body(c, totpEnableReq);
  // Re-authenticate: a stolen session alone must not be able to bind an attacker-controlled second factor.
  const u = await requireAuthHash(c, r.authHash);
  const st = totpState(u);
  if (!st || st.enabled) throw err(409, 'conflict');
  const secret = await decryptTotpSecret(c.env.TOTP_ENC_KEY, u.id, st);
  const counter = await verifyTotp(secret, r.code, Math.floor(now() / 1000));
  if (counter === null) throw err(400, 'invalid_credentials');
  await c.env.DB.batch([
    c.env.DB.prepare('UPDATE users SET totp_secret_enc = ? WHERE id = ? AND totp_secret_enc = ?').bind(JSON.stringify({ ...st, enabled: true, lastCounter: counter }), u.id, u.totp_secret_enc),
    auditStmt(c, u.id, 'totp_enable'),
  ]);
  return c.json({ ok: true });
});

auth.post('/totp/disable', async (c) => {
  const r = await body(c, totpDisableReq);
  const u = await requireAuthHash(c, r.authHash);
  await c.env.DB.batch([c.env.DB.prepare('UPDATE users SET totp_secret_enc = NULL WHERE id = ?').bind(u.id), auditStmt(c, u.id, 'totp_disable')]);
  return c.json({ ok: true });
});

