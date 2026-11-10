/** decisions D-18. Must match DEFAULT_KDF_PARAMS in packages/crypto (asserted in tests). */
export const DEFAULT_KDF_PARAMS_JSON = JSON.stringify({ alg: 'argon2id13', ops: 3, mem: 67108864, v: 1 });

/** Same human alphabet as Secret Keys (no I, L, O, U). */
export const HUMAN_INVITE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
