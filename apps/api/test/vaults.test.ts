import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { client, fakeEnvelope, fakeSealed, json, registerUser, type TestUser } from './helpers.js';

interface SyncVault {
  id: string;
  kind: string;
  revision: number;
  keyEpoch: number;
  role: string;
  full: boolean;
  items: { id: string; revision: number; deleted: boolean; data: string; keyEpoch: number }[];
}
const sync = async (u: TestUser, since?: string) =>
  (await json<{ vaults: SyncVault[] }>(await u.client.req('GET', `/api/sync${since ? `?since=${since}` : ''}`))).vaults;

async function putItem(u: TestUser, vid: string, iid: string, expectedRevision: number | null, keyEpoch = 0) {
  return u.client.req('PUT', `/api/vaults/${vid}/items/${iid}`, { data: fakeEnvelope(), keyEpoch, expectedRevision });
}

async function sharedVault(owner: TestUser) {
  const id = crypto.randomUUID();
  const res = await owner.client.req('POST', '/api/vaults', { id, nameEnc: fakeEnvelope(), sealedVaultKey: fakeSealed() });
  expect(res.status).toBe(201);
  return id;
}

async function addMember(owner: TestUser, vid: string, m: TestUser, role: 'editor' | 'viewer', keyEpoch = 0) {
  return owner.client.req('PUT', `/api/vaults/${vid}/members/${m.userId}`, { sealedVaultKey: fakeSealed(), role, keyEpoch });
}

describe('items and sync', () => {
  it('create → update → delete with revisions, deltas and soft delete', async () => {
    const u = await registerUser();
    const vid = u.personalVaultId;
    const iid = crypto.randomUUID();
    const v0 = (await sync(u))[0]!;
    expect(v0).toMatchObject({ id: vid, kind: 'personal', role: 'owner', revision: 0, keyEpoch: 0, full: true, items: [] });

    const created = await json<{ revision: number }>(await putItem(u, vid, iid, null));
    expect(created.revision).toBe(1);
    const updated = await json<{ revision: number }>(await putItem(u, vid, iid, 1));
    expect(updated.revision).toBe(2);

    const delta = (await sync(u, `${vid}.1`))[0]!;
    expect(delta.full).toBe(false);
    expect(delta.items.map((i) => i.revision)).toEqual([2]);

    const del = await u.client.req('DELETE', `/api/vaults/${vid}/items/${iid}`, { expectedRevision: 2 });
    expect(del.status).toBe(200);
    const afterDel = (await sync(u, `${vid}.2`))[0]!;
    expect(afterDel.items).toEqual([expect.objectContaining({ id: iid, deleted: true, data: '' })]);
    expect((await sync(u))[0]!.items).toEqual([]);
    // a stale `since` (ahead of server) falls back to full
    expect((await sync(u, `${vid}.999`))[0]!.full).toBe(true);
  });

  it('409 on stale expectedRevision, duplicate create, and wrong key epoch; returns the current version', async () => {
    const u = await registerUser();
    const vid = u.personalVaultId;
    const iid = crypto.randomUUID();
    await putItem(u, vid, iid, null);
    const dup = await putItem(u, vid, iid, null);
    expect(dup.status).toBe(409);
    expect((await json(dup)).current).toMatchObject({ id: iid, revision: 1 });
    await putItem(u, vid, iid, 1);
    const stale = await putItem(u, vid, iid, 1);
    expect(stale.status).toBe(409);
    expect((await json(stale)).current).toMatchObject({ revision: 2 });
    expect((await putItem(u, vid, crypto.randomUUID(), null, 1)).status).toBe(409);
    expect((await u.client.req('DELETE', `/api/vaults/${vid}/items/${iid}`, { expectedRevision: 1 })).status).toBe(409);
    expect((await u.client.req('DELETE', `/api/vaults/${vid}/items/${crypto.randomUUID()}`, { expectedRevision: 1 })).status).toBe(404);
  });

  it('rejects malformed envelopes and oversize items', async () => {
    const u = await registerUser();
    const vid = u.personalVaultId;
    const bad = [
      { data: 'plaintext password', keyEpoch: 0, expectedRevision: null },
      { data: JSON.stringify({ v: 2, alg: 'xc20p', n: 'a', c: 'b'.repeat(50) }), keyEpoch: 0, expectedRevision: null },
      { data: fakeEnvelope(300 * 1024), keyEpoch: 0, expectedRevision: null },
    ];
    for (const b of bad) expect((await u.client.req('PUT', `/api/vaults/${vid}/items/${crypto.randomUUID()}`, b)).status).toBe(400);
    expect((await u.client.req('PUT', `/api/vaults/${vid}/items/not-a-uuid`, bad[0])).status).toBe(400);
  });

  it('an item id cannot be moved into another vault', async () => {
    const u = await registerUser();
    const iid = crypto.randomUUID();
    await putItem(u, u.personalVaultId, iid, null);
    const other = await sharedVault(u);
    expect((await putItem(u, other, iid, null)).status).toBe(409);
    expect((await putItem(u, other, iid, 1)).status).toBe(409);
  });
});

describe('authorization matrix', () => {
  it('unauthenticated → 401 on every protected route', async () => {
    const c = client();
    const vid = crypto.randomUUID();
    const iid = crypto.randomUUID();
    const routes: [string, string, unknown?][] = [
      ['GET', '/api/sync'],
      ['GET', '/api/auth/me'],
      ['GET', '/api/auth/sessions'],
      ['POST', '/api/auth/logout'],
      ['POST', '/api/auth/password', {}],
      ['POST', '/api/auth/totp/setup'],
      ['PUT', `/api/vaults/${vid}/items/${iid}`, {}],
      ['DELETE', `/api/vaults/${vid}/items/${iid}`, {}],
      ['POST', '/api/vaults', {}],
      ['GET', `/api/vaults/${vid}/members`],
      ['PUT', `/api/vaults/${vid}/members/${iid}`, {}],
      ['POST', `/api/vaults/${vid}/rotate`, {}],
      ['GET', '/api/users/lookup?email=a@example.com'],
      ['POST', '/api/invites'],
    ];
    for (const [m, p, b] of routes) expect((await c.req(m, p, b)).status, `${m} ${p}`).toBe(401);
  });

  it('A cannot touch B’s vault (404 for non-members); viewer cannot write (403); editor cannot manage members (403)', async () => {
    const a = await registerUser();
    const b = await registerUser();
    const viewer = await registerUser();
    const editor = await registerUser();
    const bVault = b.personalVaultId;
    const iid = crypto.randomUUID();
    await putItem(b, bVault, iid, null);

    // A vs B's personal vault
    expect((await putItem(a, bVault, crypto.randomUUID(), null)).status).toBe(404);
    expect((await putItem(a, bVault, iid, 1)).status).toBe(404);
    expect((await a.client.req('DELETE', `/api/vaults/${bVault}/items/${iid}`, { expectedRevision: 1 })).status).toBe(404);
    expect((await a.client.req('GET', `/api/vaults/${bVault}/members`)).status).toBe(404);
    expect((await addMember(a, bVault, a, 'editor')).status).toBe(404);
    expect((await a.client.req('POST', `/api/vaults/${bVault}/rotate`, {})).status).toBe(404);
    expect((await sync(a)).map((v) => v.id)).not.toContain(bVault);

    // Shared vault roles
    const sv = await sharedVault(b);
    expect((await addMember(b, sv, viewer, 'viewer')).status).toBe(200);
    expect((await addMember(b, sv, editor, 'editor')).status).toBe(200);
    expect((await sync(viewer)).find((v) => v.id === sv)).toMatchObject({ role: 'viewer', kind: 'shared' });

    expect((await putItem(viewer, sv, crypto.randomUUID(), null)).status).toBe(403);
    const sharedItem = crypto.randomUUID();
    expect((await putItem(editor, sv, sharedItem, null)).status).toBe(200);
    expect((await viewer.client.req('DELETE', `/api/vaults/${sv}/items/${sharedItem}`, { expectedRevision: 1 })).status).toBe(403);
    expect((await viewer.client.req('GET', `/api/vaults/${sv}/members`)).status).toBe(200);
    expect((await addMember(editor, sv, a, 'viewer')).status).toBe(403);
    expect((await addMember(viewer, sv, a, 'viewer')).status).toBe(403);
    expect((await editor.client.req('POST', `/api/vaults/${sv}/rotate`, {})).status).toBe(403);

    // Owner cannot make anyone owner, cannot demote self, cannot share a personal vault.
    expect((await b.client.req('PUT', `/api/vaults/${sv}/members/${a.userId}`, { sealedVaultKey: fakeSealed(), role: 'owner', keyEpoch: 0 })).status).toBe(403);
    expect((await addMember(b, sv, b, 'viewer')).status).toBe(403);
    expect((await addMember(b, bVault, a, 'viewer')).status).toBe(403);
    expect((await addMember(b, sv, a, 'viewer', 5)).status).toBe(409);
    expect((await b.client.req('PUT', `/api/vaults/${sv}/members/${crypto.randomUUID()}`, { sealedVaultKey: fakeSealed(), role: 'viewer', keyEpoch: 0 })).status).toBe(404);

    // Demote editor → viewer: writes now forbidden.
    expect((await addMember(b, sv, editor, 'viewer')).status).toBe(200);
    expect((await putItem(editor, sv, crypto.randomUUID(), null)).status).toBe(403);

    // Garbage vault ids are 404, not 500.
    expect((await a.client.req('GET', '/api/vaults/not-a-uuid/members')).status).toBe(404);
  });

  it('user lookup returns only public material', async () => {
    const a = await registerUser();
    const b = await registerUser();
    const res = await json(await a.client.req('GET', `/api/users/lookup?email=${encodeURIComponent(b.email)}`));
    expect(res).toEqual({ userId: b.userId, email: b.email, publicKey: b.publicKey });
    expect((await a.client.req('GET', '/api/users/lookup?email=nobody@example.com')).status).toBe(404);
    expect((await a.client.req('GET', '/api/users/lookup?email=bad')).status).toBe(400);
  });
});

describe('key rotation', () => {
  async function setup() {
    const owner = await registerUser();
    const keep = await registerUser();
    const gone = await registerUser();
    const sv = await sharedVault(owner);
    await addMember(owner, sv, keep, 'editor');
    await addMember(owner, sv, gone, 'viewer');
    const items = [crypto.randomUUID(), crypto.randomUUID()];
    for (const i of items) await putItem(owner, sv, i, null);
    const v = (await sync(owner)).find((x) => x.id === sv)!;
    return { owner, keep, gone, sv, v };
  }

  function rotation(v: SyncVault, members: string[], epoch = v.keyEpoch + 1) {
    return {
      keyEpoch: epoch,
      expectedVaultRevision: v.revision,
      nameEnc: fakeEnvelope(),
      members: members.map((userId) => ({ userId, sealedVaultKey: fakeSealed() })),
      items: v.items.map((i) => ({ id: i.id, data: fakeEnvelope(), expectedRevision: i.revision })),
    };
  }

  it('removes unlisted members, bumps epoch, re-encrypts every item atomically', async () => {
    const { owner, keep, gone, sv, v } = await setup();
    const res = await owner.client.req('POST', `/api/vaults/${sv}/rotate`, rotation(v, [owner.userId, keep.userId]));
    expect(res.status).toBe(200);
    expect((await json(res)).removed).toEqual([gone.userId]);
    expect((await sync(gone)).find((x) => x.id === sv)).toBeUndefined();
    expect((await gone.client.req('GET', `/api/vaults/${sv}/members`)).status).toBe(404);
    const after = (await sync(keep)).find((x) => x.id === sv)!;
    expect(after.keyEpoch).toBe(1);
    expect(after.items.every((i) => i.keyEpoch === 1)).toBe(true);
    // Writes with the old epoch are refused.
    expect((await putItem(keep, sv, crypto.randomUUID(), null, 0)).status).toBe(409);
    expect((await putItem(keep, sv, crypto.randomUUID(), null, 1)).status).toBe(200);
  });

  it('is all-or-nothing: a concurrent write, a missing item or a bad epoch changes nothing', async () => {
    const { owner, keep, gone, sv, v } = await setup();
    const snapshot = async () => ({
      members: (await env.DB.prepare('SELECT user_id, key_epoch, sealed_vault_key FROM vault_members WHERE vault_id = ? ORDER BY user_id').bind(sv).all()).results,
      items: (await env.DB.prepare('SELECT id, data, key_epoch, revision FROM items WHERE vault_id = ? ORDER BY id').bind(sv).all()).results,
    });

    // wrong epoch
    expect((await owner.client.req('POST', `/api/vaults/${sv}/rotate`, rotation(v, [owner.userId], 5))).status).toBe(409);
    // missing an item
    const missing = rotation(v, [owner.userId]);
    missing.items.pop();
    expect((await owner.client.req('POST', `/api/vaults/${sv}/rotate`, missing)).status).toBe(409);
    // owner not listed / unknown member listed
    expect((await owner.client.req('POST', `/api/vaults/${sv}/rotate`, rotation(v, [keep.userId]))).status).toBe(400);
    expect((await owner.client.req('POST', `/api/vaults/${sv}/rotate`, rotation(v, [owner.userId, crypto.randomUUID()]))).status).toBe(400);

    // concurrent write between fetch and rotate → vault revision moved → 409, nothing applied
    const before = await snapshot();
    await putItem(keep, sv, v.items[0]!.id, v.items[0]!.revision);
    const mid = await snapshot();
    expect(mid).not.toEqual(before);
    expect((await owner.client.req('POST', `/api/vaults/${sv}/rotate`, rotation(v, [owner.userId]))).status).toBe(409);
    expect(await snapshot()).toEqual(mid);
    expect((await sync(gone)).find((x) => x.id === sv)).toBeDefined();

    // In-batch guard: simulate a race the pre-checks can't see by making one item update miss.
    const v2 = (await sync(owner)).find((x) => x.id === sv)!;
    const racy = rotation(v2, [owner.userId]);
    racy.items[0]!.expectedRevision = 0; // pre-check only compares ids; the UPDATE ... AND revision = 0 matches nothing
    const pre = await snapshot();
    expect((await owner.client.req('POST', `/api/vaults/${sv}/rotate`, racy)).status).toBe(409);
    expect(await snapshot()).toEqual(pre);
  });
});
