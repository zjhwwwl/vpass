// RFC 6238 TOTP / RFC 4226 HOTP via WebCrypto HMAC. No libsodium: also used by the Worker.
import { bytes, fromBase32Rfc4648, toBase32Rfc4648, type Bytes } from './encoding.js';

export type TotpAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-512';

export interface TotpParams {
  secret: Bytes;
  digits: number;
  period: number;
  algorithm: TotpAlgorithm;
}

export async function hotp(secret: Uint8Array, counter: number, digits = 6, algorithm: TotpAlgorithm = 'SHA-1'): Promise<string> {
  if (!Number.isInteger(digits) || digits < 6 || digits > 10) throw new Error('invalid_totp');
  const key = await crypto.subtle.importKey('raw', bytes(secret), { name: 'HMAC', hash: algorithm }, false, ['sign']);
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setBigUint64(0, BigInt(counter));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return String(bin % 10 ** digits).padStart(digits, '0');
}

/** TOTP code at unix time `nowSeconds`. */
export async function totp(params: TotpParams, nowSeconds: number): Promise<string> {
  return hotp(params.secret, Math.floor(nowSeconds / params.period), params.digits, params.algorithm);
}

export function totpRemaining(period: number, nowSeconds: number): number {
  return period - (Math.floor(nowSeconds) % period);
}

const ALGS: Record<string, TotpAlgorithm> = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

/** Parse an item's `totp` field: either an otpauth:// URI or a bare base32 secret. */
export function parseTotp(input: string): TotpParams {
  const s = input.trim();
  if (!s) throw new Error('invalid_totp');
  let secretStr = s;
  let digits = 6;
  let period = 30;
  let algorithm: TotpAlgorithm = 'SHA-1';
  if (/^otpauth:\/\//i.test(s)) {
    let url: URL;
    try {
      url = new URL(s);
    } catch {
      throw new Error('invalid_totp');
    }
    if (url.host.toLowerCase() !== 'totp') throw new Error('invalid_totp');
    secretStr = url.searchParams.get('secret') ?? '';
    const d = url.searchParams.get('digits');
    const p = url.searchParams.get('period');
    const a = url.searchParams.get('algorithm');
    if (d !== null) digits = Number(d);
    if (p !== null) period = Number(p);
    if (a !== null) {
      const alg = ALGS[a.toUpperCase()];
      if (!alg) throw new Error('invalid_totp');
      algorithm = alg;
    }
  }
  if (!Number.isInteger(digits) || digits < 6 || digits > 10) throw new Error('invalid_totp');
  if (!Number.isInteger(period) || period < 1 || period > 300) throw new Error('invalid_totp');
  let secret: Bytes;
  try {
    secret = fromBase32Rfc4648(secretStr);
  } catch {
    throw new Error('invalid_totp');
  }
  if (secret.length < 10) throw new Error('invalid_totp');
  return { secret, digits, period, algorithm };
}

/** Verify a 6-digit code within ±window steps. Returns the matched counter, or null. */
export async function verifyTotp(secret: Uint8Array, code: string, nowSeconds: number, window = 1): Promise<number | null> {
  if (!/^\d{6}$/.test(code)) return null;
  const counter = Math.floor(nowSeconds / 30);
  let match: number | null = null;
  for (let d = -window; d <= window; d++) {
    const c = await hotp(secret, counter + d);
    // Compare every candidate (no early exit) to keep timing independent of which window matched.
    let diff = 0;
    for (let i = 0; i < 6; i++) diff |= c.charCodeAt(i) ^ code.charCodeAt(i);
    if (diff === 0) match = counter + d;
  }
  return match;
}

export function otpauthUri(secret: Uint8Array, account: string, issuer = 'VPass'): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  return `otpauth://totp/${label}?secret=${toBase32Rfc4648(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}
