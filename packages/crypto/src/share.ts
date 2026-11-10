import { bytes, toHex, type Bytes } from './encoding.js';
import { getSodium } from './sodium.js';

/** crypto_box_seal(message, recipientPublicKey). Used to hand a vaultKey to a member. */
export async function sealToPublicKey(message: Uint8Array, publicKey: Uint8Array): Promise<Bytes> {
  if (publicKey.length !== 32) throw new Error('invalid_public_key');
  const sodium = await getSodium();
  return bytes(sodium.crypto_box_seal(message, publicKey));
}

export async function openSealed(sealed: Uint8Array, publicKey: Uint8Array, privateKey: Uint8Array): Promise<Bytes> {
  const sodium = await getSodium();
  try {
    return bytes(sodium.crypto_box_seal_open(sealed, publicKey, privateKey));
  } catch {
    throw new Error('decrypt_failed');
  }
}

/** Public key fingerprint: SHA-256(publicKey)[0..20] as 10 groups of 4 hex digits. */
export async function fingerprint(publicKey: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes(publicKey)));
  const hex = toHex(digest.subarray(0, 20));
  return hex.match(/.{4}/g)!.join(' ');
}

/** Constant-time-ish comparison of two public keys (both public, but keep it tidy). */
export async function samePublicKey(a: Uint8Array, b: Uint8Array): Promise<boolean> {
  const sodium = await getSodium();
  return a.length === b.length && sodium.memcmp(a, b);
}
