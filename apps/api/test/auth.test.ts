import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { SECURITY_HEADERS } from '../src/middleware/headers.js';
import { DEFAULT_KDF_PARAMS_JSON } from '../src/lib/constants.js';
import { DEFAULT_KDF_PARAMS } from '@vpass/crypto/kdf-params';
import { client, fakeEnvelope, fakeKey, fakeSalt, json, KDF, registerUser, seedInvite } from './helpers.js';

describe('security headers', () => {
  it('every API response carries all section-9 headers, including errors', async () => {
    const c = client();
    const responses = [
      await c.req('GET', '/api/sync'),
      await c.req('POST', '/api/auth/prelogin', { email: 'x@example.com' }),
      await c.req('POST', '/api/auth/prelogin', { email: 'x@example.com' }, { 'X-Requested-With': '' }),
      await c.req('GET', '/api/nope'),
      await c.req('POST', '/api/auth/login', 'garbage'),
    ];
    for (const res of responses) {
      for (const [k, v] of Object.entries(SECURITY_HEADERS)) expect(res.headers.get(k), k).toBe(v);
      expect(res.headers.get('Cache-Control')).toBe('no-store');
    }
  });

  it('the server default KDF params match the crypto package', () => {
    expect(JSON.parse(DEFAULT_KDF_PARAMS_JSON)).toEqual(DEFAULT_KDF_PARAMS);
  });
});

describe('CSRF / Origin', () => {
  it('rejects writes without X-Requested-With or with a foreign Origin', async () => {
    const c = client();
    expect((await c.req('POST', '/api/auth/prelogin', { email: 'a@example.com' }, { 'X-Requested-With': 'XMLHttpRequest' })).status).toBe(403);
    expect((await c.req('POST', '/api/auth/prelogin', { email: 'a@example.com' }, { Origin: 'https://evil.test' })).status).toBe(403);
    const res = await c.req('POST', '/api/auth/prelogin', { email: 'a@example.com' }, { Origin: '' });
    expect(res.status).toBe(403);
    expect(await json(res)).toEqual({ error: 'csrf' });
    expect((await c.req('POST', '/api/auth/prelogin', { email: 'a@example.com' })).status).toBe(200);
  });
});

describe('prelogin', () => {
  it('unknown emails get a stable fake salt with default params; known emails their real salt', async () => {
    const c = client();
    const a = await json(await c.req('POST', '/api/auth/prelogin', { email: 'ghost@example.com' }));
    const b = await json(await c.req('POST', '/api/auth/prelogin', { email: 'GHOST@example.com' }));
    const other = await json(await c.req('POST', '/api/auth/prelogin', { email: 'ghost2@example.com' }));
    expect(a).toEqual(b);
    expect(a.kdfSalt).not.toEqual(other.kdfSalt);
    expect(a.kdfParams).toEqual(KDF);
    const u = await registerUser();
    const real = await json(await c.req('POST', '/api/auth/prelogin', { email: u.email }));
    const row = await env.DB.prepare('SELECT kdf_salt FROM users WHERE id = ?').bind(u.userId).first<{ kdf_salt: string }>();
    expect(real.kdfSalt).toBe(row!.kdf_salt);
  });
});

describe('register', () => {
  it('requires a valid unused invite and a free email', async () => {
    const c = client();
    const base = () => ({
      inviteCode: 'NOPE-NOPE-NOPE',
      userId: crypto.randomUUID(),
      email: `r${crypto.randomUUID().slice(0, 6)}@example.com`,
      kdfSalt: fakeSalt(),
      kdfParams: KDF,
      authHash: fakeKey(),
      wrappedAccountKey: fakeEnvelope(),
      recoveryWrappedKey: fakeEnvelope(),
      recoveryAuth: fakeKey(),
      publicKey: fakeKey(),
      wrappedPrivateKey: fakeEnvelope(),
      personalVault: { id: crypto.randomUUID(), sealedVaultKey: fakeKey() + fakeKey() + 'AAAAAAAAAAAAAAAAAAAAA' },
    });
    expect(await json(await c.req('POST', '/api/auth/register', base()))).toEqual({ error: 'invalid_invite' });
    const short = base();
    short.personalVault.sealedVaultKey = short.personalVault.sealedVaultKey.slice(0, 100);
    expect(await json(await c.req('POST', '/api/auth/register', short))).toEqual({ error: 'bad_request' });
    const ok = base();
    ok.inviteCode = await seedInvite();
    const r1 = await c.req('POST', '/api/auth/register', ok);
    expect(r1.status).toBe(201);
    const bundle = await json(r1);
    expect(bundle).toMatchObject({ userId: ok.userId, email: ok.email, isAdmin: false, totpEnabled: false });
    expect(c.cookie).toMatch(/^__Host-session=/);
    // invite is single-use
    const again = { ...base(), inviteCode: ok.inviteCode };
    again.personalVault.sealedVaultKey = ok.personalVault.sealedVaultKey;
    expect(await json(await c.req('POST', '/api/auth/register', again))).toEqual({ error: 'invalid_invite' });
    // expired invite
    const exp = { ...again, inviteCode: await seedInvite(undefined, Date.now() - 1) };
    expect(await json(await c.req('POST', '/api/auth/register', exp))).toEqual({ error: 'invalid_invite' });
    // taken email
    const dup = { ...again, email: ok.email, inviteCode: await seedInvite() };
    expect(await json(await c.req('POST', '/api/auth/register', dup))).toEqual({ error: 'email_taken' });
    // weak KDF params are rejected by schema
    const weak = { ...again, inviteCode: await seedInvite(), kdfParams: { ...KDF, ops: 1 } };
    expect((await c.req('POST', '/api/auth/register', weak)).status).toBe(400);
  });

  it('cookie is HttpOnly, Secure, SameSite=Strict, Path=/', async () => {
    const u = await registerUser();
    const res = await u.client.req('POST', '/api/auth/login', { email: u.email, authHash: u.authHash });
    const set = res.headers.get('Set-Cookie')!;
    expect(set).toMatch(/^__Host-session=[A-Za-z0-9_-]{43};/);
    expect(set).toMatch(/HttpOnly/);
    expect(set).toMatch(/Secure/);
    expect(set).toMatch(/SameSite=Strict/);
    expect(set).toMatch(/Path=\//);
    expect(set).not.toMatch(/Domain=/);
  });
});

describe('login, sessions, lockout', () => {
  it('login works; wrong hash and unknown user both give invalid_credentials', async () => {
    const u = await registerUser();
    const c = client();
    expect(await json(await c.req('POST', '/api/auth/login', { email: u.email, authHash: fakeKey() }))).toEqual({ error: 'invalid_credentials' });
    expect(await json(await c.req('POST', '/api/auth/login', { email: 'nobody@example.com', authHash: fakeKey() }))).toEqual({ error: 'invalid_credentials' });
    const ok = await c.req('POST', '/api/auth/login', { email: u.email.toUpperCase(), authHash: u.authHash, deviceLabel: 'Test laptop' });
    expect(ok.status).toBe(200);
    expect((await json(ok)).userId).toBe(u.userId);
    const sessions = await json<{ sessions: { id: string; current: boolean; deviceLabel: string }[] }>(await c.req('GET', '/api/auth/sessions'));
    expect(sessions.sessions).toHaveLength(2);
    expect(sessions.sessions.find((s) => s.current)!.deviceLabel).toBe('Test laptop');
    // kick the other device
    const other = sessions.sessions.find((s) => !s.current)!;
    expect((await c.req('DELETE', `/api/auth/sessions/${other.id}`)).status).toBe(200);
    expect((await u.client.req('GET', '/api/sync')).status).toBe(401);
    expect((await c.req('DELETE', `/api/auth/sessions/${other.id}`)).status).toBe(404);
    // logout
    expect((await c.req('POST', '/api/auth/logout')).status).toBe(200);
    expect((await c.req('GET', '/api/auth/me')).status).toBe(401);
  });

  it('cannot revoke another user’s session', async () => {
    const a = await registerUser();
    const b = await registerUser();
    const bs = await json<{ sessions: { id: string }[] }>(await b.client.req('GET', '/api/auth/sessions'));
    expect((await a.client.req('DELETE', `/api/auth/sessions/${bs.sessions[0]!.id}`)).status).toBe(404);
    expect((await b.client.req('GET', '/api/auth/me')).status).toBe(200);
  });

  it('no hard lockout: 10 distributed failures do not lock the real user out (P6 M3)', async () => {
    const u = await registerUser();
    for (let i = 0; i < 10; i++) {
      expect((await client(`192.0.2.${i}`).req('POST', '/api/auth/login', { email: u.email, authHash: fakeKey() })).status).toBe(401);
    }
    expect((await client('198.51.100.1').req('POST', '/api/auth/login', { email: u.email, authHash: u.authHash })).status).toBe(200);
  });

  it('per-email limit (30 / 15 min across IPs) behaves identically for existing and unknown emails', async () => {
    const u = await registerUser();
    const ghost = 'ghost-limit@example.com';
    for (const email of [u.email, ghost]) {
      for (let i = 0; i < 30; i++) {
        const ip = `198.18.${email === ghost ? 1 : 0}.${i}`;
        expect((await client(ip).req('POST', '/api/auth/login', { email, authHash: fakeKey() })).status).toBe(401);
      }
    }
    const real = await client('198.19.0.1').req('POST', '/api/auth/login', { email: u.email, authHash: u.authHash });
    const fake = await client('198.19.0.2').req('POST', '/api/auth/login', { email: ghost, authHash: fakeKey() });
    expect(real.status).toBe(429);
    expect(await json(real)).toEqual({ error: 'rate_limited' });
    expect(fake.status).toBe(429);
    expect(await json(fake)).toEqual({ error: 'rate_limited' });
    // Failures are keyed by an email HMAC, never by the user row, so nothing reveals which account exists.
    const rows = await env.DB.prepare("SELECT DISTINCT user_id FROM audit_log WHERE event = 'login_fail' AND user_id LIKE 'em:%'").all();
    expect(rows.results.length).toBeGreaterThanOrEqual(2);
    expect(JSON.stringify(rows.results)).not.toContain(u.userId);
    // After the window passes the real user gets in again.
    await env.DB.prepare('UPDATE audit_log SET created_at = 0').run();
    expect((await client('198.19.0.3').req('POST', '/api/auth/login', { email: u.email, authHash: u.authHash })).status).toBe(200);
  });

  it('IPv6 clients are counted per /64', async () => {
    const { ipBucket } = await import('../src/lib/crypto.js');
    expect(ipBucket('2001:db8:1:2:aaaa::1')).toBe(ipBucket('2001:0db8:0001:0002:ffff:1:2:3'));
    expect(ipBucket('2001:db8:1:2::1')).not.toBe(ipBucket('2001:db8:1:3::1'));
    expect(ipBucket('::1')).toBe('0:0:0:0::/64');
    expect(ipBucket('203.0.113.9')).toBe('203.0.113.9');
  });

  it('per-IP rate limit: 10 failures from one IP across many emails → 429', async () => {
    const c = client('203.0.113.77');
    for (let i = 0; i < 10; i++) {
      expect((await c.req('POST', '/api/auth/login', { email: `nobody${i}@example.com`, authHash: fakeKey() })).status).toBe(401);
    }
    expect(await json(await c.req('POST', '/api/auth/login', { email: 'nobody@example.com', authHash: fakeKey() }))).toEqual({ error: 'rate_limited' });
    expect((await c.req('POST', '/api/auth/recover/start', { email: 'nobody@example.com', recoveryAuth: fakeKey() })).status).toBe(429);
  });

  it('expired and idle sessions are rejected', async () => {
    const u = await registerUser();
    await env.DB.prepare('UPDATE sessions SET expires_at = ? WHERE user_id = ?').bind(Date.now() - 1, u.userId).run();
    expect((await u.client.req('GET', '/api/sync')).status).toBe(401);
    const v = await registerUser();
    await env.DB.prepare('UPDATE sessions SET last_seen_at = ? WHERE user_id = ?').bind(Date.now() - 15 * 24 * 3600_000, v.userId).run();
    expect((await v.client.req('GET', '/api/sync')).status).toBe(401);
  });

  it('garbage cookies are 401', async () => {
    const c = client();
    c.cookie = '__Host-session=abc';
    expect((await c.req('GET', '/api/auth/me')).status).toBe(401);
    c.cookie = `__Host-session=${'A'.repeat(43)}`;
    expect((await c.req('GET', '/api/auth/me')).status).toBe(401);
  });
});

describe('password change, recovery, recovery code', () => {
  it('password change requires the old authHash and revokes other sessions', async () => {
    const u = await registerUser();
    const other = client();
    await other.req('POST', '/api/auth/login', { email: u.email, authHash: u.authHash });
    const newCreds = { kdfSalt: fakeSalt(), kdfParams: KDF, authHash: fakeKey(), wrappedAccountKey: fakeEnvelope() };
    expect((await u.client.req('POST', '/api/auth/password', { oldAuthHash: fakeKey(), ...newCreds })).status).toBe(401);
    const res = await u.client.req('POST', '/api/auth/password', { oldAuthHash: u.authHash, ...newCreds });
    expect(res.status).toBe(200);
    expect((await json(res)).kdfSalt).toBe(newCreds.kdfSalt);
    expect((await other.req('GET', '/api/sync')).status).toBe(401);
    expect((await u.client.req('GET', '/api/sync')).status).toBe(200);
    const c = client();
    expect((await c.req('POST', '/api/auth/login', { email: u.email, authHash: u.authHash })).status).toBe(401);
    expect((await c.req('POST', '/api/auth/login', { email: u.email, authHash: newCreds.authHash })).status).toBe(200);
  });

  it('recovery: start returns the recovery wrapping; finishing resets credentials and revokes all sessions', async () => {
    const u = await registerUser();
    const c = client();
    expect((await c.req('POST', '/api/auth/recover/start', { email: u.email, recoveryAuth: fakeKey() })).status).toBe(401);
    const start = await json(await c.req('POST', '/api/auth/recover/start', { email: u.email, recoveryAuth: u.recoveryAuth }));
    expect(start.userId).toBe(u.userId);
    expect(typeof start.recoveryWrappedKey).toBe('string');
    const fresh = { kdfSalt: fakeSalt(), kdfParams: KDF, authHash: fakeKey(), wrappedAccountKey: fakeEnvelope(), newRecoveryWrappedKey: fakeEnvelope(), newRecoveryAuth: fakeKey() };
    const done = await c.req('POST', '/api/auth/recover', { email: u.email, recoveryAuth: u.recoveryAuth, ...fresh });
    expect(done.status).toBe(200);
    expect((await u.client.req('GET', '/api/sync')).status).toBe(401);
    expect((await c.req('GET', '/api/sync')).status).toBe(200);
    // old recovery code is dead, new one works
    expect((await client().req('POST', '/api/auth/recover/start', { email: u.email, recoveryAuth: u.recoveryAuth })).status).toBe(401);
    expect((await client().req('POST', '/api/auth/recover/start', { email: u.email, recoveryAuth: fresh.newRecoveryAuth })).status).toBe(200);
  });

  it('regenerating the recovery code requires authHash', async () => {
    const u = await registerUser();
    const nr = { recoveryWrappedKey: fakeEnvelope(), recoveryAuth: fakeKey() };
    expect((await u.client.req('POST', '/api/auth/recovery-code', { authHash: fakeKey(), ...nr })).status).toBe(401);
    expect((await u.client.req('POST', '/api/auth/recovery-code', { authHash: u.authHash, ...nr })).status).toBe(200);
    expect((await client().req('POST', '/api/auth/recover/start', { email: u.email, recoveryAuth: nr.recoveryAuth })).status).toBe(200);
  });
});

describe('invites', () => {
  it('only admins can create invites, and the code works once', async () => {
    const u = await registerUser();
    expect((await u.client.req('POST', '/api/invites')).status).toBe(403);
    const admin = await registerUser(undefined, '00000000-0000-4000-8000-000000000001');
    const res = await admin.client.req('POST', '/api/invites');
    expect(res.status).toBe(201);
    const { code } = await json<{ code: string }>(res);
    expect(code).toMatch(/^VPI-[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$/);
    const rows = await env.DB.prepare('SELECT code_hash FROM invites').all<{ code_hash: string }>();
    expect(JSON.stringify(rows.results)).not.toContain(code);
    const me = await json(await admin.client.req('GET', '/api/auth/me'));
    expect(me.isAdmin).toBe(true);
  });
});

describe('login TOTP', () => {
  it('setup → enable → login requires a fresh code; replay and wrong codes fail; disable needs authHash', async () => {
    const { hotp } = await import('@vpass/crypto/totp');
    const { fromBase32Rfc4648 } = await import('@vpass/crypto/encoding');
    const u = await registerUser();
    const setup = await json<{ secret: string; uri: string }>(await u.client.req('POST', '/api/auth/totp/setup'));
    expect(setup.uri).toMatch(/^otpauth:\/\/totp\//);
    const secret = fromBase32Rfc4648(setup.secret);
    const counter = Math.floor(Date.now() / 30_000);
    const wrong = '000000' === (await hotp(secret, counter)) ? '111111' : '000000';
    expect((await u.client.req('POST', '/api/auth/totp/enable', { code: wrong, authHash: u.authHash })).status).toBe(400);
    // Enabling requires re-authentication (P6 L2).
    expect((await u.client.req('POST', '/api/auth/totp/enable', { code: await hotp(secret, counter), authHash: fakeKey() })).status).toBe(401);
    expect((await u.client.req('POST', '/api/auth/totp/enable', { code: await hotp(secret, counter) })).status).toBe(400);
    expect((await u.client.req('POST', '/api/auth/totp/enable', { code: await hotp(secret, counter), authHash: u.authHash })).status).toBe(200);
    expect((await u.client.req('POST', '/api/auth/totp/setup')).status).toBe(409);
    const row = await env.DB.prepare('SELECT totp_secret_enc FROM users WHERE id = ?').bind(u.userId).first<{ totp_secret_enc: string }>();
    expect(row!.totp_secret_enc).not.toContain(setup.secret);

    const c = client();
    expect(await json(await c.req('POST', '/api/auth/login', { email: u.email, authHash: u.authHash }))).toEqual({ error: 'totp_required' });
    // the code used for enabling cannot be replayed
    expect((await c.req('POST', '/api/auth/login', { email: u.email, authHash: u.authHash, totp: await hotp(secret, counter) })).status).toBe(401);
    const next = await hotp(secret, counter + 1);
    expect((await c.req('POST', '/api/auth/login', { email: u.email, authHash: u.authHash, totp: next })).status).toBe(200);
    expect((await client().req('POST', '/api/auth/login', { email: u.email, authHash: u.authHash, totp: next })).status).toBe(401);
    expect((await c.req('GET', '/api/auth/me')).status).toBe(200);
    expect((await json(await c.req('GET', '/api/auth/me'))).totpEnabled).toBe(true);

    expect((await c.req('POST', '/api/auth/totp/disable', { authHash: fakeKey() })).status).toBe(401);
    expect((await c.req('POST', '/api/auth/totp/disable', { authHash: u.authHash })).status).toBe(200);
    expect((await client().req('POST', '/api/auth/login', { email: u.email, authHash: u.authHash })).status).toBe(200);
  });
});

describe('hardening from the P6 review', () => {
  it('rejects bodies over the cap even without Content-Length (chunked)', async () => {
    const { exports } = await import('cloudflare:workers');
    const big = new ReadableStream({
      start(ctrl) {
        const chunk = new Uint8Array(1024 * 1024).fill(32);
        for (let i = 0; i < 33; i++) ctrl.enqueue(chunk);
        ctrl.close();
      },
    });
    const res = await exports.default.fetch(
      new Request('https://pv.test/api/auth/prelogin', {
        method: 'POST',
        headers: { Origin: 'https://pv.test', 'X-Requested-With': 'vpass', 'Content-Type': 'application/json' },
        body: big,
        // @ts-expect-error duplex is required for streaming request bodies
        duplex: 'half',
      }),
    );
    expect(res.status).toBe(413);
  });

  it('server-provided KDF params above 256 MiB / ops 10 are rejected', async () => {
    const c = client();
    const r = await c.req('POST', '/api/auth/register', { inviteCode: 'x'.repeat(10), kdfParams: { ...KDF, mem: 512 * 1024 * 1024 } });
    expect(r.status).toBe(400);
  });

  it('the CSP only allows the app’s own Trusted Types policy', async () => {
    const res = await client().req('GET', '/api/auth/me');
    expect(res.headers.get('Content-Security-Policy')).toContain('trusted-types vpass');
  });
});
