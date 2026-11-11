import { exports } from 'cloudflare:workers';
import { env } from 'cloudflare:workers';

export const ORIGIN = 'https://pv.test';

function rand(n: number): string {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(b.subarray(i, Math.min(n, i + 65536)));
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Shape-valid ciphertext; the server never decrypts, so random bytes are enough for API tests. */
export function fakeEnvelope(len = 272): string {
  return JSON.stringify({ v: 1, alg: 'xc20p', n: rand(24), c: rand(len) });
}
export const fakeKey = () => rand(32);
export const fakeSealed = () => rand(80);
export const fakeSalt = () => rand(16);
export const KDF = { alg: 'argon2id13', ops: 3, mem: 67108864, v: 1 } as const;

export interface Client {
  cookie: string | null;
  ip: string;
  req(method: string, path: string, body?: unknown, extraHeaders?: Record<string, string>): Promise<Response>;
}

export function client(ip = `10.${crypto.getRandomValues(new Uint8Array(3)).join('.')}`): Client {
  const c: Client = {
    cookie: null,
    ip,
    async req(method, path, body, extraHeaders = {}) {
      const headers: Record<string, string> = {
        'CF-Connecting-IP': c.ip,
        ...(method !== 'GET' ? { Origin: ORIGIN, 'X-Requested-With': 'vpass' } : {}),
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(c.cookie ? { Cookie: c.cookie } : {}),
        ...extraHeaders,
      };
      const res = await exports.default.fetch(
        new Request(ORIGIN + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }),
      );
      const set = res.headers.get('Set-Cookie');
      if (set) {
        const m = /__Host-session=([^;]*)/.exec(set);
        if (m) c.cookie = m[1] ? `__Host-session=${m[1]}` : null;
      }
      return res;
    },
  };
  return c;
}

async function sha256Hex(s: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)));
  return [...d].map((x) => x.toString(16).padStart(2, '0')).join('');
}

export async function seedInvite(code = `INV${rand(9).toUpperCase().replace(/[^A-Z0-9]/g, 'X')}`, expiresAt = Date.now() + 3600_000): Promise<string> {
  await env.DB.prepare('INSERT INTO invites (code_hash, created_by, used_by, expires_at) VALUES (?, NULL, NULL, ?)')
    .bind(await sha256Hex(code.toUpperCase()), expiresAt)
    .run();
  return code;
}

export interface TestUser {
  client: Client;
  userId: string;
  email: string;
  authHash: string;
  recoveryAuth: string;
  personalVaultId: string;
  publicKey: string;
}

export async function registerUser(email = `u${crypto.randomUUID().slice(0, 8)}@example.com`, userId: string = crypto.randomUUID()): Promise<TestUser> {
  const c = client();
  const inviteCode = await seedInvite();
  const u = {
    inviteCode,
    userId,
    email,
    kdfSalt: fakeSalt(),
    kdfParams: KDF,
    authHash: fakeKey(),
    wrappedAccountKey: fakeEnvelope(),
    recoveryWrappedKey: fakeEnvelope(),
    recoveryAuth: fakeKey(),
    publicKey: fakeKey(),
    wrappedPrivateKey: fakeEnvelope(),
    personalVault: { id: crypto.randomUUID(), sealedVaultKey: fakeSealed() },
  };
  const res = await c.req('POST', '/api/auth/register', u);
  if (res.status !== 201) throw new Error(`register failed ${res.status} ${await res.text()}`);
  return { client: c, userId: u.userId, email, authHash: u.authHash, recoveryAuth: u.recoveryAuth, personalVaultId: u.personalVault.id, publicKey: u.publicKey };
}

export async function json<T = Record<string, unknown>>(res: Response): Promise<T> {
  return (await res.json()) as T;
}
