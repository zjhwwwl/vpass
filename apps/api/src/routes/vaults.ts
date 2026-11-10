import { Hono, type Context } from 'hono';
import {
  createVaultReq,
  deleteItemReq,
  putItemReq,
  putMemberReq,
  rotateReq,
  uuid,
  type ItemDto,
  type MemberDto,
  type Role,
  type VaultDto,
} from '@vpass/shared';
import type { AppEnv } from '../env.js';
import { body, err, now } from '../lib/http.js';
import { auditStmt } from '../db/audit.js';
import { requireSession } from '../middleware/session.js';

export const vaults = new Hono<AppEnv>();
vaults.use('/sync', requireSession);
vaults.use('/vaults', requireSession);
vaults.use('/vaults/*', requireSession);

interface Membership {
  role: Role;
  key_epoch: number;
  kind: 'personal' | 'shared';
  owner_id: string;
  revision: number;
}

const RANK: Record<Role, number> = { viewer: 0, editor: 1, owner: 2 };

/**
 * Route-level authorization: every :vid route goes through here. Non-members get 404 (no existence leak);
 * members without the required role get 403.
 */
async function requireMember(c: Context<AppEnv>, vid: string, min: Role): Promise<Membership> {
  if (!uuid.safeParse(vid).success) throw err(404, 'not_found');
  const m = await c.env.DB.prepare(
    'SELECT m.role, m.key_epoch, v.kind, v.owner_id, v.revision FROM vault_members m JOIN vaults v ON v.id = m.vault_id WHERE m.vault_id = ? AND m.user_id = ?',
  )
    .bind(vid, c.var.session.userId)
    .first<Membership>();
  if (!m) throw err(404, 'not_found');
  if (RANK[m.role] < RANK[min]) throw err(403, 'forbidden');
  return m;
}

interface ItemRow {
  id: string;
  vault_id: string;
  data: string;
  key_epoch: number;
  revision: number;
  deleted: number;
  updated_at: number;
}

export function itemDto(r: ItemRow): ItemDto {
  return { id: r.id, data: r.data, keyEpoch: r.key_epoch, revision: r.revision, deleted: r.deleted === 1, updatedAt: r.updated_at };
}

/** SQLite has no RAISE outside triggers; json('…') on invalid input aborts the batch, rolling back the transaction. */
const ABORT = "json('conflict')";

function isAbort(e: unknown): boolean {
  return e instanceof Error && /malformed JSON|JSON/i.test(e.message);
}

async function currentItem(c: Context<AppEnv>, iid: string): Promise<ItemRow | null> {
  return c.env.DB.prepare('SELECT * FROM items WHERE id = ?').bind(iid).first<ItemRow>();
}

// ---------------------------------------------------------------- sync

// GET /api/sync?since=<vid>.<rev>,<vid>.<rev>   (decisions D-08)
vaults.get('/sync', async (c) => {
  const since = new Map<string, number>();
  for (const part of (c.req.query('since') ?? '').split(',')) {
    const m = /^([0-9a-f-]{36})\.(\d{1,15})$/.exec(part);
    if (m) since.set(m[1]!, Number(m[2]));
  }
  const { results } = await c.env.DB.prepare(
    `SELECT v.id, v.kind, v.owner_id, v.name_enc, v.revision, m.key_epoch, m.role, m.sealed_vault_key
     FROM vault_members m JOIN vaults v ON v.id = m.vault_id WHERE m.user_id = ? ORDER BY v.created_at`,
  )
    .bind(c.var.session.userId)
    .all<{ id: string; kind: 'personal' | 'shared'; owner_id: string; name_enc: string | null; revision: number; key_epoch: number; role: Role; sealed_vault_key: string }>();
  const out: VaultDto[] = [];
  for (const v of results) {
    const s = since.get(v.id);
    const delta = s !== undefined && s <= v.revision;
    const items = delta
      ? await c.env.DB.prepare('SELECT * FROM items WHERE vault_id = ? AND revision > ? ORDER BY revision').bind(v.id, s).all<ItemRow>()
      : await c.env.DB.prepare('SELECT * FROM items WHERE vault_id = ? AND deleted = 0 ORDER BY revision').bind(v.id).all<ItemRow>();
    out.push({
      id: v.id,
      kind: v.kind,
      ownerId: v.owner_id,
      nameEnc: v.name_enc,
      revision: v.revision,
      keyEpoch: v.key_epoch,
      role: v.role,
      sealedVaultKey: v.sealed_vault_key,
      full: !delta,
      items: items.results.map(itemDto),
    });
  }
  return c.json({ vaults: out, serverTime: now() });
});

// ---------------------------------------------------------------- items

// PUT /api/vaults/:vid/items/:iid — create (expectedRevision=null) or update; 409 on revision mismatch.
vaults.put('/vaults/:vid/items/:iid', async (c) => {
  const vid = c.req.param('vid');
  const iid = c.req.param('iid');
  const m = await requireMember(c, vid, 'editor');
  if (!uuid.safeParse(iid).success) throw err(400, 'bad_request');
  const r = await body(c, putItemReq);
  if (r.keyEpoch !== m.key_epoch) throw err(409, 'conflict', { reason: 'key_epoch' });
  const existing = await currentItem(c, iid);
  if (existing && existing.vault_id !== vid) throw err(409, 'conflict');
  if ((r.expectedRevision === null && existing) || (r.expectedRevision !== null && existing?.revision !== r.expectedRevision)) {
    throw err(409, 'conflict', { current: existing ? itemDto(existing) : null });
  }
  const db = c.env.DB;
  const t = now();
  const upsert =
    r.expectedRevision === null
      ? db
          .prepare('INSERT INTO items (id, vault_id, data, key_epoch, revision, deleted, updated_at) VALUES (?, ?, ?, ?, (SELECT revision FROM vaults WHERE id = ?), 0, ?) ON CONFLICT(id) DO NOTHING')
          .bind(iid, vid, r.data, r.keyEpoch, vid, t)
      : db
          .prepare('UPDATE items SET data = ?, key_epoch = ?, revision = (SELECT revision FROM vaults WHERE id = ?), deleted = 0, updated_at = ? WHERE id = ? AND vault_id = ? AND revision = ?')
          .bind(r.data, r.keyEpoch, vid, t, iid, vid, r.expectedRevision);
  try {
    const res = await db.batch([
      db.prepare('UPDATE vaults SET revision = revision + 1 WHERE id = ?').bind(vid),
      upsert,
      // Guard: the write happened, and the caller is still an editor+ member at this key epoch.
      db
        .prepare(
          `SELECT CASE WHEN changes() = 1 AND (SELECT COUNT(*) FROM vault_members WHERE vault_id = ? AND user_id = ? AND key_epoch = ? AND role IN ('owner','editor')) = 1 THEN 1 ELSE ${ABORT} END AS ok`,
        )
        .bind(vid, c.var.session.userId, r.keyEpoch),
      db.prepare('SELECT revision FROM vaults WHERE id = ?').bind(vid),
    ]);
    const rev = (res[3]!.results[0] as { revision: number }).revision;
    return c.json({ revision: rev, vaultRevision: rev });
  } catch (e) {
    if (!isAbort(e)) throw e;
    const cur = await currentItem(c, iid);
    throw err(409, 'conflict', { current: cur ? itemDto(cur) : null });
  }
});

// DELETE /api/vaults/:vid/items/:iid — soft delete (D-17).
vaults.delete('/vaults/:vid/items/:iid', async (c) => {
  const vid = c.req.param('vid');
  const iid = c.req.param('iid');
  await requireMember(c, vid, 'editor');
  const r = await body(c, deleteItemReq);
  const db = c.env.DB;
  try {
    const res = await db.batch([
      db.prepare('UPDATE vaults SET revision = revision + 1 WHERE id = ?').bind(vid),
      db
        .prepare("UPDATE items SET deleted = 1, data = '', revision = (SELECT revision FROM vaults WHERE id = ?), updated_at = ? WHERE id = ? AND vault_id = ? AND revision = ? AND deleted = 0")
        .bind(vid, now(), iid, vid, r.expectedRevision),
      db
        .prepare(`SELECT CASE WHEN changes() = 1 AND (SELECT COUNT(*) FROM vault_members WHERE vault_id = ? AND user_id = ? AND role IN ('owner','editor')) = 1 THEN 1 ELSE ${ABORT} END`)
        .bind(vid, c.var.session.userId),
      db.prepare('SELECT revision FROM vaults WHERE id = ?').bind(vid),
    ]);
    const rev = (res[3]!.results[0] as { revision: number }).revision;
    return c.json({ revision: rev, vaultRevision: rev });
  } catch (e) {
    if (!isAbort(e)) throw e;
    const cur = await currentItem(c, iid);
    if (!cur || cur.vault_id !== vid) throw err(404, 'not_found');
    throw err(409, 'conflict', { current: itemDto(cur) });
  }
});

// ---------------------------------------------------------------- shared vaults

// POST /api/vaults — create a shared vault owned by the caller.
vaults.post('/vaults', async (c) => {
  const r = await body(c, createVaultReq);
  const db = c.env.DB;
  const uid = c.var.session.userId;
  try {
    await db.batch([
      db.prepare("INSERT INTO vaults (id, owner_id, kind, name_enc, revision, created_at) VALUES (?, ?, 'shared', ?, 0, ?)").bind(r.id, uid, r.nameEnc, now()),
      db.prepare("INSERT INTO vault_members (vault_id, user_id, sealed_vault_key, key_epoch, role) VALUES (?, ?, ?, 0, 'owner')").bind(r.id, uid, r.sealedVaultKey),
      auditStmt(c, uid, 'vault_create'),
    ]);
  } catch {
    throw err(409, 'conflict');
  }
  return c.json({ id: r.id }, 201);
});

// GET /api/vaults/:vid/members (D-09)
vaults.get('/vaults/:vid/members', async (c) => {
  const vid = c.req.param('vid');
  await requireMember(c, vid, 'viewer');
  const { results } = await c.env.DB.prepare(
    'SELECT m.user_id, u.email, u.public_key, m.role, m.key_epoch FROM vault_members m JOIN users u ON u.id = m.user_id WHERE m.vault_id = ? ORDER BY u.email',
  )
    .bind(vid)
    .all<{ user_id: string; email: string; public_key: string; role: Role; key_epoch: number }>();
  const members: MemberDto[] = results.map((r) => ({ userId: r.user_id, email: r.email, publicKey: r.public_key, role: r.role, keyEpoch: r.key_epoch }));
  return c.json({ members });
});

// PUT /api/vaults/:vid/members/:uid — owner adds a member or changes a role.
vaults.put('/vaults/:vid/members/:uid', async (c) => {
  const vid = c.req.param('vid');
  const target = c.req.param('uid');
  const m = await requireMember(c, vid, 'owner');
  if (m.kind !== 'shared') throw err(403, 'forbidden');
  if (!uuid.safeParse(target).success) throw err(400, 'bad_request');
  const r = await body(c, putMemberReq);
  if (target === c.var.session.userId || r.role === 'owner') throw err(403, 'forbidden');
  if (r.keyEpoch !== m.key_epoch) throw err(409, 'conflict', { reason: 'key_epoch' });
  const user = await c.env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(target).first();
  if (!user) throw err(404, 'not_found');
  await c.env.DB.batch([
    c.env.DB
      .prepare(
        'INSERT INTO vault_members (vault_id, user_id, sealed_vault_key, key_epoch, role) VALUES (?, ?, ?, ?, ?) ON CONFLICT(vault_id, user_id) DO UPDATE SET sealed_vault_key = excluded.sealed_vault_key, key_epoch = excluded.key_epoch, role = excluded.role',
      )
      .bind(vid, target, r.sealedVaultKey, r.keyEpoch, r.role),
    auditStmt(c, c.var.session.userId, 'share'),
  ]);
  return c.json({ ok: true });
});

// POST /api/vaults/:vid/rotate — new key epoch; all items re-encrypted; members not listed are removed. One D1 transaction.
vaults.post('/vaults/:vid/rotate', async (c) => {
  const vid = c.req.param('vid');
  const m = await requireMember(c, vid, 'owner');
  if (m.kind !== 'shared') throw err(403, 'forbidden');
  const r = await body(c, rotateReq);
  if (r.keyEpoch !== m.key_epoch + 1 || r.expectedVaultRevision !== m.revision) throw err(409, 'conflict');
  const uid = c.var.session.userId;
  const listed = new Set(r.members.map((x) => x.userId));
  if (listed.size !== r.members.length || !listed.has(uid)) throw err(400, 'bad_request');
  const db = c.env.DB;
  const current = await db.prepare('SELECT user_id FROM vault_members WHERE vault_id = ?').bind(vid).all<{ user_id: string }>();
  const currentIds = new Set(current.results.map((x) => x.user_id));
  for (const id of listed) if (!currentIds.has(id)) throw err(400, 'bad_request');
  const live = await db.prepare('SELECT id, revision FROM items WHERE vault_id = ? AND deleted = 0').bind(vid).all<{ id: string; revision: number }>();
  const itemIds = new Set(r.items.map((x) => x.id));
  if (itemIds.size !== r.items.length || itemIds.size !== live.results.length || live.results.some((x) => !itemIds.has(x.id))) {
    throw err(409, 'conflict');
  }
  const t = now();
  const removed = [...currentIds].filter((id) => !listed.has(id));
  const stmts: D1PreparedStatement[] = [
    db.prepare('UPDATE vaults SET revision = revision + 1, name_enc = ? WHERE id = ? AND revision = ?').bind(r.nameEnc, vid, r.expectedVaultRevision),
    db.prepare(`SELECT CASE WHEN changes() = 1 THEN 1 ELSE ${ABORT} END`),
    ...removed.map((id) => db.prepare('DELETE FROM vault_members WHERE vault_id = ? AND user_id = ?').bind(vid, id)),
    ...r.members.map((x) => db.prepare('UPDATE vault_members SET sealed_vault_key = ?, key_epoch = ? WHERE vault_id = ? AND user_id = ?').bind(x.sealedVaultKey, r.keyEpoch, vid, x.userId)),
    ...r.items.map((x) =>
      db
        .prepare('UPDATE items SET data = ?, key_epoch = ?, revision = (SELECT revision FROM vaults WHERE id = ?), updated_at = ? WHERE id = ? AND vault_id = ? AND revision = ? AND deleted = 0')
        .bind(x.data, r.keyEpoch, vid, t, x.id, vid, x.expectedRevision),
    ),
    // Every listed item must have been rewritten to the new epoch, or nothing commits.
    db.prepare(`SELECT CASE WHEN (SELECT COUNT(*) FROM items WHERE vault_id = ? AND deleted = 0 AND key_epoch != ?) = 0 THEN 1 ELSE ${ABORT} END`).bind(vid, r.keyEpoch),
    auditStmt(c, uid, 'rotate'),
  ];
  try {
    await db.batch(stmts);
  } catch (e) {
    if (!isAbort(e)) throw e;
    throw err(409, 'conflict');
  }
  return c.json({ ok: true, removed });
});
