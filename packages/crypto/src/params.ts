// Sodium-free constants (importable by the Worker).
export interface KdfParams {
  alg: 'argon2id13';
  ops: number;
  mem: number;
  v: 1;
}

/** crypto-spec 4.1: opslimit 3, memlimit 64 MiB. */
export const DEFAULT_KDF_PARAMS: KdfParams = Object.freeze({
  alg: 'argon2id13',
  ops: 3,
  mem: 64 * 1024 * 1024,
  v: 1,
}) as KdfParams;
