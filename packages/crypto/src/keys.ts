import { bytes, type Bytes } from './encoding.js';
import { open, seal } from './envelope.js';
import { getSodium } from './sodium.js';

export async function randomBytes(n: number): Promise<Bytes> {
  const sodium = await getSodium();
  return bytes(sodium.randombytes_buf(n));
}

/** Random 32-byte symmetric key (accountKey, vaultKey). */
export async function generateKey(): Promise<Bytes> {
  return randomBytes(32);
}

/** UUIDv4 from the CSPRNG. */
export function uuid(): string {
  return crypto.randomUUID();
}

export async function wrapKey(wrappingKey: Uint8Array, key: Uint8Array, aad: string): Promise<string> {
  if (key.length !== 32) throw new Error('invalid_key');
  return seal(wrappingKey, key, aad);
}

export async function unwrapKey(wrappingKey: Uint8Array, wrapped: string, aad: string): Promise<Bytes> {
  const k = await open(wrappingKey, wrapped, aad);
  if (k.length !== 32) throw new Error('decrypt_failed');
  return k;
}

export interface KeyPair {
  publicKey: Bytes;
  privateKey: Bytes;
}

/** X25519 key pair for crypto_box_seal. */
export async function generateKeyPair(): Promise<KeyPair> {
  const sodium = await getSodium();
  const kp = sodium.crypto_box_keypair();
  return { publicKey: bytes(kp.publicKey), privateKey: bytes(kp.privateKey) };
}

// ---------------------------------------------------------------------------
// Secret Key (decision D-01) and recovery code: human-transcribable base32.
// ---------------------------------------------------------------------------

/** Base32 alphabet without I, L, O, U. */
export const HUMAN_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function humanEncode(b: Uint8Array): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const x of b) {
    buffer = ((buffer << 8) | x) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += HUMAN_ALPHABET[(buffer >>> bits) & 31];
    }
  }
  if (bits > 0) out += HUMAN_ALPHABET[(buffer << (5 - bits)) & 31];
  return out;
}

function normalizeHuman(s: string): string {
  return s.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
}

function humanValues(s: string): number[] {
  const out: number[] = [];
  for (const ch of s) {
    const v = HUMAN_ALPHABET.indexOf(ch);
    if (v < 0) throw new Error('invalid_character');
    out.push(v);
  }
  return out;
}

function humanDecode(values: number[], byteLength: number): Bytes {
  const out = new Uint8Array(byteLength);
  let buffer = 0;
  let bits = 0;
  let i = 0;
  for (const v of values) {
    buffer = ((buffer << 5) | v) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[i++] = (buffer >>> bits) & 0xff;
    }
  }
  // Leftover bits must be zero padding.
  if ((buffer & ((1 << bits) - 1)) !== 0) throw new Error('invalid_code');
  return out;
}

function checkChar(values: number[]): number {
  let sum = 0;
  values.forEach((v, i) => {
    sum += (2 * i + 1) * v;
  });
  return sum % 32;
}

const SECRET_KEY_PREFIX = 'VP1';
export const SECRET_KEY_BYTES = 16;
const SECRET_KEY_DATA_CHARS = 26;

/** Random 128-bit Secret Key (raw bytes). */
export async function generateSecretKey(): Promise<Bytes> {
  return randomBytes(SECRET_KEY_BYTES);
}

/** Format: VP1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XX (26 data chars + 1 check char). */
export function formatSecretKey(raw: Uint8Array): string {
  if (raw.length !== SECRET_KEY_BYTES) throw new Error('invalid_secret_key');
  const data = humanEncode(raw);
  const all = data + HUMAN_ALPHABET[checkChar(humanValues(data))];
  const groups = all.match(/.{1,5}/g)!;
  return [SECRET_KEY_PREFIX, ...groups].join('-');
}

export type SecretKeyError = 'secret_key_format' | 'secret_key_checksum';

/** Parse user input. Throws Error('secret_key_format' | 'secret_key_checksum') locally, before any network call. */
export function parseSecretKey(input: string): Bytes {
  let s = normalizeHuman(input);
  if (!s.startsWith('VP1')) throw new Error('secret_key_format');
  s = s.slice(3);
  if (s.length !== SECRET_KEY_DATA_CHARS + 1) throw new Error('secret_key_format');
  let values: number[];
  try {
    values = humanValues(s);
  } catch {
    throw new Error('secret_key_format');
  }
  const data = values.slice(0, SECRET_KEY_DATA_CHARS);
  if (checkChar(data) !== values[SECRET_KEY_DATA_CHARS]) throw new Error('secret_key_checksum');
  try {
    return humanDecode(data, SECRET_KEY_BYTES);
  } catch {
    throw new Error('secret_key_checksum');
  }
}

export const RECOVERY_CODE_BYTES = 20;

/** 160-bit recovery code, shown once. Returns raw bytes and the display string (8 groups of 4). */
export async function createRecoveryCode(): Promise<{ raw: Bytes; display: string }> {
  const raw = await randomBytes(RECOVERY_CODE_BYTES);
  return { raw, display: formatRecoveryCode(raw) };
}

export function formatRecoveryCode(raw: Uint8Array): string {
  if (raw.length !== RECOVERY_CODE_BYTES) throw new Error('invalid_recovery_code');
  return humanEncode(raw).match(/.{4}/g)!.join('-');
}

export function parseRecoveryCode(input: string): Bytes {
  const s = normalizeHuman(input);
  if (s.length !== 32) throw new Error('recovery_code_format');
  try {
    return humanDecode(humanValues(s), RECOVERY_CODE_BYTES);
  } catch {
    throw new Error('recovery_code_format');
  }
}
