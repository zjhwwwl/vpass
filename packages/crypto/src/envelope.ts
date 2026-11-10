import { bytes, fromB64u, fromUtf8, toB64u, utf8, type Bytes } from './encoding.js';
import { getSodium, wipe } from './sodium.js';

/** crypto-spec 4.3. All ciphertext is stored as this versioned JSON. */
export interface Envelope {
  v: 1;
  alg: 'xc20p';
  n: string;
  c: string;
}

export const PAD_BLOCK = 256;
const NONCE_BYTES = 24;
const TAG_BYTES = 16;

export function parseEnvelope(json: string): Envelope {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    throw new Error('invalid_envelope');
  }
  if (typeof raw !== 'object' || raw === null) throw new Error('invalid_envelope');
  const e = raw as Record<string, unknown>;
  if (e.v !== 1) throw new Error('unsupported_envelope_version');
  if (e.alg !== 'xc20p') throw new Error('unsupported_envelope_alg');
  if (typeof e.n !== 'string' || typeof e.c !== 'string') throw new Error('invalid_envelope');
  return { v: 1, alg: 'xc20p', n: e.n, c: e.c };
}

export function serializeEnvelope(e: Envelope): string {
  return JSON.stringify({ v: e.v, alg: e.alg, n: e.n, c: e.c });
}

function assertKey(key: Uint8Array): void {
  if (key.length !== 32) throw new Error('invalid_key');
}

/**
 * Encrypt: pad(plaintext, 256) → XChaCha20-Poly1305 with a fresh 24-byte nonce and mandatory AAD.
 * Returns the serialized envelope JSON.
 */
export async function seal(key: Uint8Array, plaintext: Uint8Array, aad: string): Promise<string> {
  assertKey(key);
  if (!aad) throw new Error('aad_required');
  const sodium = await getSodium();
  const nonce = sodium.randombytes_buf(NONCE_BYTES);
  const padded = sodium.pad(bytes(plaintext), PAD_BLOCK);
  const c = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(padded, utf8(aad), null, nonce, key);
  wipe(padded);
  return serializeEnvelope({ v: 1, alg: 'xc20p', n: toB64u(nonce), c: toB64u(c) });
}

/** Decrypt an envelope. Any failure (format, version, tag, AAD, padding) throws. */
export async function open(key: Uint8Array, envelopeJson: string, aad: string): Promise<Bytes> {
  assertKey(key);
  if (!aad) throw new Error('aad_required');
  const env = parseEnvelope(envelopeJson);
  const nonce = fromB64u(env.n);
  const c = fromB64u(env.c);
  if (nonce.length !== NONCE_BYTES || c.length < TAG_BYTES + PAD_BLOCK) throw new Error('invalid_envelope');
  const sodium = await getSodium();
  let padded: Uint8Array;
  try {
    padded = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, c, utf8(aad), nonce, key);
  } catch {
    throw new Error('decrypt_failed');
  }
  try {
    return bytes(sodium.unpad(padded, PAD_BLOCK));
  } catch {
    throw new Error('decrypt_failed');
  } finally {
    wipe(padded);
  }
}

export async function sealString(key: Uint8Array, s: string, aad: string): Promise<string> {
  return seal(key, utf8(s), aad);
}

export async function openString(key: Uint8Array, envelopeJson: string, aad: string): Promise<string> {
  return fromUtf8(await open(key, envelopeJson, aad));
}

export async function sealJson(key: Uint8Array, value: unknown, aad: string): Promise<string> {
  return sealString(key, JSON.stringify(value), aad);
}

export async function openJson<T = unknown>(key: Uint8Array, envelopeJson: string, aad: string): Promise<T> {
  return JSON.parse(await openString(key, envelopeJson, aad)) as T;
}
