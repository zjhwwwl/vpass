// Pure encoding helpers. No cryptography here, no libsodium: safe to import from the Worker.

export type Bytes = Uint8Array<ArrayBuffer>;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false });

export function utf8(s: string): Bytes {
  return textEncoder.encode(s) as Bytes;
}

export function fromUtf8(b: Uint8Array): string {
  return textDecoder.decode(b);
}

/** Copy into a fresh ArrayBuffer-backed array (WebCrypto wants BufferSource over ArrayBuffer). */
export function bytes(b: Uint8Array): Bytes {
  const out = new Uint8Array(b.length);
  out.set(b);
  return out;
}

export function toB64u(b: Uint8Array): string {
  let bin = '';
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const B64U_RE = /^[A-Za-z0-9_-]*$/;

export function fromB64u(s: string): Bytes {
  if (!B64U_RE.test(s) || s.length % 4 === 1) throw new Error('invalid_base64url');
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toHex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

export function fromHex(s: string): Bytes {
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(s)) throw new Error('invalid_hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** RFC 4648 base32 (used by otpauth:// TOTP secrets). Lenient: ignores spaces, case and padding. */
const RFC4648 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function fromBase32Rfc4648(input: string): Bytes {
  const s = input.toUpperCase().replace(/[\s=-]/g, '');
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of s) {
    const v = RFC4648.indexOf(ch);
    if (v < 0) throw new Error('invalid_base32');
    buffer = (buffer << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >>> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

export function toBase32Rfc4648(b: Uint8Array): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const x of b) {
    buffer = (buffer << 8) | x;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += RFC4648[(buffer >>> bits) & 31];
    }
  }
  if (bits > 0) out += RFC4648[(buffer << (5 - bits)) & 31];
  return out;
}

/** Strict lowercase UUIDv4 check (all IDs are client-generated v4 UUIDs). */
export const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function isUuidV4(s: string): boolean {
  return UUID_V4_RE.test(s);
}
