import { Hono } from 'hono';
import { email as emailSchema } from '@vpass/shared';
import { HUMAN_INVITE_ALPHABET } from '../lib/constants.js';
import type { AppEnv } from '../env.js';
import { sha256Hex } from '../lib/crypto.js';
import { err, now } from '../lib/http.js';
import { audit } from '../db/audit.js';
import { isAdmin, requireSession } from '../middleware/session.js';
import { normalizeInvite } from './auth.js';

export const users = new Hono<AppEnv>();
users.use('/users/*', requireSession);
users.use('/invites', requireSession);

// GET /api/users/lookup?email= — the other person's userId and public key, for sharing.
users.get('/users/lookup', async (c) => {
  const parsed = emailSchema.safeParse(c.req.query('email') ?? '');
  if (!parsed.success) throw err(400, 'bad_request');
  const u = await c.env.DB.prepare('SELECT id, email, public_key FROM users WHERE email = ?').bind(parsed.data).first<{ id: string; email: string; public_key: string }>();
  if (!u) throw err(404, 'not_found');
  return c.json({ userId: u.id, email: u.email, publicKey: u.public_key });
});

export const INVITE_TTL_MS = 7 * 24 * 3600 * 1000;

export function generateInviteCode(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  // 32 divides 256, so `& 31` has no modulo bias.
  const chars = [...b].map((x) => HUMAN_INVITE_ALPHABET[x & 31]).join('');
  return `VPI-${chars.slice(0, 4)}-${chars.slice(4, 8)}-${chars.slice(8, 12)}-${chars.slice(12, 16)}`;
}

// POST /api/invites — admin only. The code is shown once; only its hash is stored.
users.post('/invites', async (c) => {
  if (!isAdmin(c, c.var.session.email)) throw err(403, 'forbidden');
  const code = generateInviteCode();
  const expiresAt = now() + INVITE_TTL_MS;
  await c.env.DB.prepare('INSERT INTO invites (code_hash, created_by, used_by, expires_at) VALUES (?, ?, NULL, ?)')
    .bind(await sha256Hex(normalizeInvite(code)), c.var.session.userId, expiresAt)
    .run();
  await audit(c, c.var.session.userId, 'invite_create');
  return c.json({ code, expiresAt }, 201);
});
