import { bytes, utf8, type Bytes } from './encoding.js';
import { getSodium, wipe } from './sodium.js';

export { DEFAULT_KDF_PARAMS, type KdfParams } from './params.js';
import { DEFAULT_KDF_PARAMS, type KdfParams } from './params.js';

export const KEY_BYTES = 32;
export const SALT_BYTES = 16;

export const INFO = Object.freeze({
  secretKey: 'vpass/v1/secret-key',
  enc: 'vpass/v1/enc',
  auth: 'vpass/v1/auth',
  recovery: 'vpass/v1/recovery',
  recoveryAuth: 'vpass/v1/recovery-auth',
});

export function assertKdfParams(p: KdfParams): void {
  if (p.alg !== 'argon2id13' || p.v !== 1) throw new Error('unsupported_kdf');
  // Never accept parameters weaker than the v1 defaults (protects against a malicious server downgrading).
  if (!Number.isInteger(p.ops) || !Number.isInteger(p.mem) || p.ops < DEFAULT_KDF_PARAMS.ops || p.mem < DEFAULT_KDF_PARAMS.mem) {
    throw new Error('weak_kdf_params');
  }
  if (p.ops > 20 || p.mem > 1024 * 1024 * 1024) throw new Error('unsupported_kdf');
}

/** pwPart = Argon2id(NFKC(password), salt). */
export async function argon2id(password: string, salt: Uint8Array, params: KdfParams = DEFAULT_KDF_PARAMS): Promise<Bytes> {
  assertKdfParams(params);
  if (salt.length !== SALT_BYTES) throw new Error('invalid_salt');
  const sodium = await getSodium();
  const pw = utf8(password.normalize('NFKC'));
  try {
    return bytes(sodium.crypto_pwhash(KEY_BYTES, pw, salt, params.ops, params.mem, sodium.crypto_pwhash_ALG_ARGON2ID13));
  } finally {
    wipe(pw);
  }
}

/**
 * HKDF-SHA256 via WebCrypto, 32-byte output.
 * `ikm` may be raw bytes or a non-extractable HKDF CryptoKey (device-stored Secret Key).
 */
export async function hkdf(ikm: Uint8Array | CryptoKey, info: string | Uint8Array, salt: Uint8Array = new Uint8Array(0), length = KEY_BYTES): Promise<Bytes> {
  const key = ikm instanceof Uint8Array ? await crypto.subtle.importKey('raw', bytes(ikm), 'HKDF', false, ['deriveBits']) : ikm;
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: bytes(salt), info: typeof info === 'string' ? utf8(info) : bytes(info) }, key, length * 8);
  return new Uint8Array(bits);
}

/** Import a raw Secret Key as a non-extractable HKDF key for device storage (IndexedDB). */
export async function importSecretKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', bytes(raw), 'HKDF', false, ['deriveBits']);
}

/** masterKey = Argon2id(password) XOR HKDF(SecretKey, salt=kdfSalt). */
export async function deriveMasterKey(
  password: string,
  secretKey: Uint8Array | CryptoKey,
  kdfSalt: Uint8Array,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<Bytes> {
  const pwPart = await argon2id(password, kdfSalt, params);
  const skPart = await hkdf(secretKey, INFO.secretKey, kdfSalt);
  const out = new Uint8Array(KEY_BYTES);
  for (let i = 0; i < KEY_BYTES; i++) out[i] = pwPart[i]! ^ skPart[i]!;
  wipe(pwPart, skPart);
  return out;
}

export interface Subkeys {
  encKey: Bytes;
  authHash: Bytes;
}

export async function deriveSubkeys(masterKey: Uint8Array): Promise<Subkeys> {
  const encKey = await hkdf(masterKey, INFO.enc);
  const authHash = await hkdf(masterKey, INFO.auth);
  return { encKey, authHash };
}

export interface RecoveryKeys {
  recoveryKey: Bytes;
  recoveryAuth: Bytes;
}

export async function deriveRecoveryKeys(code: Uint8Array): Promise<RecoveryKeys> {
  return {
    recoveryKey: await hkdf(code, INFO.recovery),
    recoveryAuth: await hkdf(code, INFO.recoveryAuth),
  };
}

export async function randomSalt(): Promise<Bytes> {
  const sodium = await getSodium();
  return bytes(sodium.randombytes_buf(SALT_BYTES));
}
