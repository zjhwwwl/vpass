import sodium from 'libsodium-wrappers-sumo';

export type Sodium = typeof sodium;

let readyPromise: Promise<Sodium> | null = null;

/** Resolve the initialised libsodium instance. Every function that needs libsodium awaits this. */
export function getSodium(): Promise<Sodium> {
  readyPromise ??= sodium.ready.then(() => sodium);
  return readyPromise;
}

/** Call before any synchronous helper in this package. Idempotent. */
export async function initCrypto(): Promise<void> {
  await getSodium();
}

/** Best-effort zeroing of key material. */
export function wipe(...keys: (Uint8Array | null | undefined)[]): void {
  for (const k of keys) {
    if (k) sodium.memzero(k);
  }
}
