// Server-side crypto: WebCrypto only. The server never sees keys or plaintext; these helpers only
// hash high-entropy client values with the pepper, hash tokens, and encrypt the login-TOTP secret.
import { bytes, fromB64u, toB64u, toHex, utf8 } from '@vpass/crypto/encoding';

function fromStdB64(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s.trim());
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const keyCache = new Map<string, Promise<CryptoKey>>();

function secretBytes(name: string, value: string | undefined): Uint8Array<ArrayBuffer> {
  if (!value) throw new Error(`missing_secret_${name}`);
  const b = fromStdB64(value);
  if (b.length < 32) throw new Error(`weak_secret_${name}`);
  return b;
}

function hmacKey(pepper: string): Promise<CryptoKey> {
  const id = `hmac:${pepper}`;
  let k = keyCache.get(id);
  if (!k) {
    k = crypto.subtle.importKey('raw', secretBytes('AUTH_PEPPER', pepper), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    keyCache.set(id, k);
  }
  return k;
}

export async function hmac(pepper: string, data: Uint8Array | string): Promise<Uint8Array<ArrayBuffer>> {
  const k = await hmacKey(pepper);
  const msg = typeof data === 'string' ? utf8(data) : bytes(data);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, msg));
}

/** HMAC(PEPPER, authHash) stored as base64url. Domain-separated by label. */
export async function hmacB64(pepper: string, label: string, value: Uint8Array): Promise<string> {
  const msg = new Uint8Array(label.length + 1 + value.length);
  msg.set(utf8(label + '|'));
  msg.set(value, label.length + 1);
  return toB64u(await hmac(pepper, msg));
}

/** Constant-time compare of two base64url strings of HMAC output. */
export function timingSafeEqualB64(a: string, b: string): boolean {
  const x = fromB64u(a);
  const y = fromB64u(b);
  if (x.length !== y.length) {
    // Still do a comparison so the time doesn't depend on which branch was taken.
    crypto.subtle.timingSafeEqual(x, x);
    return false;
  }
  return crypto.subtle.timingSafeEqual(x, y);
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const msg = typeof data === 'string' ? utf8(data) : bytes(data);
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', msg)));
}

export function randomToken(n = 32): string {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return toB64u(b);
}

/** decisions D-06: deterministic fake salt for unknown emails (prevents user enumeration). */
export async function fakeSalt(pepper: string, email: string): Promise<string> {
  const h = await hmac(pepper, `fake-salt|v1|${email.toLowerCase()}`);
  return toB64u(h.subarray(0, 16));
}

/** Rate-limit key for an email, identical whether or not the account exists (decisions D-23). */
export async function emailKey(pepper: string, email: string): Promise<string> {
  const h = await hmac(pepper, `email|v1|${email.trim().toLowerCase()}`);
  return `em:${toHex(h.subarray(0, 16))}`;
}

/** IPv6 clients usually control a whole /64, so count them per /64. */
export function ipBucket(ip: string): string {
  if (!ip.includes(':')) return ip;
  const [head = '', tail = ''] = ip.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const full = ip.includes('::') ? [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t] : h;
  return `${full
    .slice(0, 4)
    .map((x) => (parseInt(x || '0', 16) || 0).toString(16))
    .join(':')}::/64`;
}

export async function ipHash(pepper: string, ip: string): Promise<string> {
  const h = await hmac(pepper, `ip|v1|${ipBucket(ip)}`);
  return toHex(h.subarray(0, 16));
}

// ---- login TOTP secret at rest (decisions D-15): AES-256-GCM under TOTP_ENC_KEY.

function aesKey(secret: string): Promise<CryptoKey> {
  const id = `aes:${secret}`;
  let k = keyCache.get(id);
  if (!k) {
    k = crypto.subtle.importKey('raw', secretBytes('TOTP_ENC_KEY', secret).subarray(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']);
    keyCache.set(id, k);
  }
  return k;
}

export interface TotpState {
  enabled: boolean;
  /** Last accepted time-step counter, to block replay. */
  lastCounter: number;
  iv: string;
  ct: string;
}

export async function encryptTotpSecret(secret: string, userId: string, totpSecret: Uint8Array): Promise<{ iv: string; ct: string }> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8(`totp|v1|${userId}`) }, await aesKey(secret), bytes(totpSecret));
  return { iv: toB64u(iv), ct: toB64u(new Uint8Array(ct)) };
}

export async function decryptTotpSecret(secret: string, userId: string, state: TotpState): Promise<Uint8Array<ArrayBuffer>> {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64u(state.iv), additionalData: utf8(`totp|v1|${userId}`) },
    await aesKey(secret),
    fromB64u(state.ct),
  );
  return new Uint8Array(pt);
}
