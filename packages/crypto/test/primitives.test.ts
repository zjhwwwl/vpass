import { describe, expect, it } from 'vitest';
import argonVectors from './vectors/argon2id.json';
import hkdfVectors from './vectors/hkdf-rfc5869.json';
import {
  AAD,
  DEFAULT_KDF_PARAMS,
  argon2id,
  assertKdfParams,
  bytes,
  deriveMasterKey,
  deriveRecoveryKeys,
  deriveSubkeys,
  fingerprint,
  fromB64u,
  fromBase32Rfc4648,
  fromHex,
  fromUtf8,
  generateKey,
  generateKeyPair,
  hkdf,
  importSecretKey,
  initCrypto,
  isUuidV4,
  open,
  openJson,
  openSealed,
  openString,
  parseEnvelope,
  randomSalt,
  samePublicKey,
  seal,
  sealJson,
  sealString,
  sealToPublicKey,
  serializeEnvelope,
  toB64u,
  toBase32Rfc4648,
  toHex,
  unwrapKey,
  utf8,
  uuid,
  wipe,
  wrapKey,
  type KdfParams,
} from '../src/index.js';

describe('encoding', () => {
  it('base64url round-trips and rejects junk', () => {
    for (const n of [0, 1, 2, 3, 4, 31, 32, 33]) {
      const b = new Uint8Array(n).map((_, i) => (i * 37 + 250) & 0xff);
      expect(fromB64u(toB64u(b))).toEqual(b);
    }
    expect(toB64u(new Uint8Array([0xfb, 0xff]))).toBe('-_8');
    expect(() => fromB64u('a+b')).toThrow('invalid_base64url');
    expect(() => fromB64u('abcde')).toThrow('invalid_base64url');
  });

  it('hex round-trips and rejects junk', () => {
    expect(toHex(fromHex('00ff10'))).toBe('00ff10');
    expect(() => fromHex('0')).toThrow('invalid_hex');
    expect(() => fromHex('zz')).toThrow('invalid_hex');
  });

  it('utf8 is strict', () => {
    expect(fromUtf8(utf8('密码'))).toBe('密码');
    expect(() => fromUtf8(new Uint8Array([0xff]))).toThrow();
  });

  it('RFC 4648 base32', () => {
    expect(toBase32Rfc4648(utf8('foobar'))).toBe('MZXW6YTBOI');
    expect(toBase32Rfc4648(utf8('f'))).toBe('MY');
    expect(fromUtf8(fromBase32Rfc4648('mzxw 6ytb-oi======'))).toBe('foobar');
    expect(() => fromBase32Rfc4648('1')).toThrow('invalid_base32');
  });

  it('uuid v4', () => {
    const id = uuid();
    expect(isUuidV4(id)).toBe(true);
    expect(isUuidV4(id.toUpperCase())).toBe(false);
    expect(isUuidV4('00000000-0000-1000-8000-000000000000')).toBe(false);
  });

  it('bytes copies', () => {
    const a = new Uint8Array([1, 2]);
    const b = bytes(a);
    b[0] = 9;
    expect(a[0]).toBe(1);
  });
});

describe('HKDF (RFC 5869)', () => {
  for (const v of hkdfVectors) {
    it(v.name, async () => {
      const okm = await hkdf(fromHex(v.ikm), fromHex(v.info), fromHex(v.salt), v.length);
      expect(toHex(okm)).toBe(v.okm);
    });
  }

  it('CryptoKey input equals raw input', async () => {
    const raw = fromHex('0b'.repeat(16));
    const ck = await importSecretKey(raw);
    expect(ck.extractable).toBe(false);
    expect(await hkdf(ck, 'x')).toEqual(await hkdf(raw, 'x'));
  });
});

describe('Argon2id (cross-checked with argon2-cffi)', () => {
  for (const v of argonVectors) {
    it(`matches python vector for ${JSON.stringify(v.password)}`, async () => {
      const h = await argon2id(v.password, fromHex(v.saltHex), { ...DEFAULT_KDF_PARAMS, ops: v.ops, mem: v.memBytes });
      expect(toHex(h)).toBe(v.hashHex);
    });
  }

  it('applies NFKC before hashing', async () => {
    const salt = fromHex('0f0e0d0c0b0a09080706050403020100');
    expect(await argon2id('ｐａｓｓｗｏｒｄ①', salt)).toEqual(await argon2id('password1', salt));
  });

  it('rejects bad salt and downgraded / unknown params', async () => {
    await expect(argon2id('x', new Uint8Array(15))).rejects.toThrow('invalid_salt');
    const bad: KdfParams[] = [
      { ...DEFAULT_KDF_PARAMS, ops: 2 },
      { ...DEFAULT_KDF_PARAMS, mem: 1024 * 1024 },
      { ...DEFAULT_KDF_PARAMS, ops: 3.5 },
      { ...DEFAULT_KDF_PARAMS, mem: 1.5 },
    ];
    for (const p of bad) expect(() => assertKdfParams(p)).toThrow('weak_kdf_params');
    expect(() => assertKdfParams({ ...DEFAULT_KDF_PARAMS, alg: 'argon2i13' as 'argon2id13' })).toThrow('unsupported_kdf');
    expect(() => assertKdfParams({ ...DEFAULT_KDF_PARAMS, v: 2 as 1 })).toThrow('unsupported_kdf');
    expect(() => assertKdfParams({ ...DEFAULT_KDF_PARAMS, ops: 21 })).toThrow('unsupported_kdf');
    expect(() => assertKdfParams({ ...DEFAULT_KDF_PARAMS, mem: 2 * 1024 * 1024 * 1024 })).toThrow('unsupported_kdf');
  });
});

describe('master key derivation', () => {
  it('needs both password and Secret Key', async () => {
    const salt = await randomSalt();
    const sk = fromHex('11'.repeat(16));
    const base = await deriveMasterKey('pw', sk, salt);
    expect(base).toHaveLength(32);
    expect(await deriveMasterKey('pw', await importSecretKey(sk), salt)).toEqual(base);
    expect(await deriveMasterKey('pw!', sk, salt)).not.toEqual(base);
    const sk2 = bytes(sk);
    sk2[15] = sk2[15]! ^ 1;
    expect(await deriveMasterKey('pw', sk2, salt)).not.toEqual(base);
  });

  it('enc and auth subkeys are independent; recovery keys differ', async () => {
    const mk = fromHex('22'.repeat(32));
    const { encKey, authHash } = await deriveSubkeys(mk);
    expect(encKey).not.toEqual(authHash);
    const r = await deriveRecoveryKeys(fromHex('33'.repeat(20)));
    expect(r.recoveryKey).not.toEqual(r.recoveryAuth);
  });
});

describe('envelope (XChaCha20-Poly1305 + AAD + padding)', () => {
  it('round-trips and pads to 256-byte blocks', async () => {
    const key = await generateKey();
    for (const len of [0, 1, 255, 256, 1000]) {
      const pt = new Uint8Array(len).fill(7);
      const env = await seal(key, pt, 'aad');
      const parsed = parseEnvelope(env);
      expect(parsed.v).toBe(1);
      expect(parsed.alg).toBe('xc20p');
      expect(fromB64u(parsed.n)).toHaveLength(24);
      expect((fromB64u(parsed.c).length - 16) % 256).toBe(0);
      expect(await open(key, env, 'aad')).toEqual(pt);
    }
    const short = parseEnvelope(await seal(key, utf8('a'), 'x'));
    const long = parseEnvelope(await seal(key, utf8('a'.repeat(200)), 'x'));
    expect(fromB64u(short.c).length).toBe(fromB64u(long.c).length);
  });

  it('string and json helpers', async () => {
    const key = await generateKey();
    expect(await openString(key, await sealString(key, '你好', 'a'), 'a')).toBe('你好');
    expect(await openJson(key, await sealJson(key, { x: [1] }, 'a'), 'a')).toEqual({ x: [1] });
  });

  it('fails on any tampered byte of nonce, ciphertext or tag', async () => {
    const key = await generateKey();
    const env = parseEnvelope(await seal(key, utf8('secret'), 'aad'));
    const flip = (s: string, i: number) => {
      const b = fromB64u(s);
      b[i] = b[i]! ^ 0x01;
      return toB64u(b);
    };
    const c = fromB64u(env.c);
    const positions = [0, 100, c.length - 17, c.length - 16, c.length - 1];
    for (const i of positions) {
      await expect(open(key, serializeEnvelope({ ...env, c: flip(env.c, i) }), 'aad')).rejects.toThrow('decrypt_failed');
    }
    for (const i of [0, 12, 23]) {
      await expect(open(key, serializeEnvelope({ ...env, n: flip(env.n, i) }), 'aad')).rejects.toThrow('decrypt_failed');
    }
  });

  it('fails on wrong AAD, wrong key, missing AAD', async () => {
    const key = await generateKey();
    const env = await seal(key, utf8('x'), AAD.item('v', 'i1'));
    await expect(open(key, env, AAD.item('v', 'i2'))).rejects.toThrow('decrypt_failed');
    await expect(open(await generateKey(), env, AAD.item('v', 'i1'))).rejects.toThrow('decrypt_failed');
    await expect(open(key, env, '')).rejects.toThrow('aad_required');
    await expect(seal(key, utf8('x'), '')).rejects.toThrow('aad_required');
    await expect(seal(new Uint8Array(16), utf8('x'), 'a')).rejects.toThrow('invalid_key');
    await expect(open(new Uint8Array(16), env, 'a')).rejects.toThrow('invalid_key');
  });

  it('rejects malformed and unknown-version envelopes', async () => {
    const key = await generateKey();
    const env = parseEnvelope(await seal(key, utf8('x'), 'a'));
    expect(() => parseEnvelope('not json')).toThrow('invalid_envelope');
    expect(() => parseEnvelope('null')).toThrow('invalid_envelope');
    expect(() => parseEnvelope('5')).toThrow('invalid_envelope');
    expect(() => parseEnvelope(JSON.stringify({ ...env, v: 2 }))).toThrow('unsupported_envelope_version');
    expect(() => parseEnvelope(JSON.stringify({ ...env, alg: 'aes' }))).toThrow('unsupported_envelope_alg');
    expect(() => parseEnvelope(JSON.stringify({ ...env, n: 1 }))).toThrow('invalid_envelope');
    expect(() => parseEnvelope(JSON.stringify({ ...env, c: null }))).toThrow('invalid_envelope');
    await expect(open(key, serializeEnvelope({ ...env, n: toB64u(new Uint8Array(12)) }), 'a')).rejects.toThrow('invalid_envelope');
    await expect(open(key, serializeEnvelope({ ...env, c: toB64u(new Uint8Array(100)) }), 'a')).rejects.toThrow('invalid_envelope');
  });

  it('rejects ciphertext whose padding is invalid even though the tag verifies', async () => {
    // Build a valid AEAD ciphertext over unpadded data with the raw primitive; open() must refuse it.
    const sodium = (await import('libsodium-wrappers-sumo')).default;
    await initCrypto();
    const key = await generateKey();
    const nonce = sodium.randombytes_buf(24);
    const bogus = new Uint8Array(256); // all zero: no 0x80 padding marker
    const c = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(bogus, utf8('a'), null, nonce, key);
    const env = serializeEnvelope({ v: 1, alg: 'xc20p', n: toB64u(nonce), c: toB64u(c) });
    await expect(open(key, env, 'a')).rejects.toThrow('decrypt_failed');
  });

  it('never repeats a nonce over 10,000 encryptions', async () => {
    const key = await generateKey();
    const seen = new Set<string>();
    for (let i = 0; i < 10_000; i++) seen.add(parseEnvelope(await seal(key, new Uint8Array(1), 'a')).n);
    expect(seen.size).toBe(10_000);
  });
});

describe('key wrapping', () => {
  it('wraps 32-byte keys only and unwraps with the same AAD', async () => {
    const kek = await generateKey();
    const k = await generateKey();
    const w = await wrapKey(kek, k, AAD.accountKey('u'));
    expect(await unwrapKey(kek, w, AAD.accountKey('u'))).toEqual(k);
    await expect(unwrapKey(kek, w, AAD.accountKey('v'))).rejects.toThrow('decrypt_failed');
    await expect(wrapKey(kek, new Uint8Array(16), 'a')).rejects.toThrow('invalid_key');
    const notAKey = await seal(kek, new Uint8Array(16), 'a');
    await expect(unwrapKey(kek, notAKey, 'a')).rejects.toThrow('decrypt_failed');
  });

  it('AAD ids are lowercased', () => {
    expect(AAD.item('ABC', 'DEF')).toBe('item|v1|abc|def');
    expect(AAD.vaultName('X')).toBe('vault-name|v1|x');
    expect(AAD.privateKey('X')).toBe('private-key|v1|x');
    expect(AAD.recoveryKey('X')).toBe('recovery-key|v1|x');
    expect(AAD.deviceSecretKey('X')).toBe('device-secret-key|v1|x');
    expect(AAD.export()).toBe('export|v1');
  });

  it('wipe zeroes and tolerates null', async () => {
    const k = await generateKey();
    wipe(k, null, undefined);
    expect(k.every((x) => x === 0)).toBe(true);
  });
});

describe('sealed boxes and fingerprints', () => {
  it('opens with the right key pair only', async () => {
    const a = await generateKeyPair();
    const b = await generateKeyPair();
    const msg = await generateKey();
    const sealed = await sealToPublicKey(msg, a.publicKey);
    expect(await openSealed(sealed, a.publicKey, a.privateKey)).toEqual(msg);
    await expect(openSealed(sealed, b.publicKey, b.privateKey)).rejects.toThrow('decrypt_failed');
    await expect(openSealed(sealed, a.publicKey, b.privateKey)).rejects.toThrow('decrypt_failed');
    await expect(sealToPublicKey(msg, new Uint8Array(31))).rejects.toThrow('invalid_public_key');
  });

  it('fingerprint is 10 groups of 4 hex of SHA-256[0..20]', async () => {
    const pk = fromHex('00'.repeat(32));
    // SHA-256 of 32 zero bytes = 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
    expect(await fingerprint(pk)).toBe('6668 7aad f862 bd77 6c8f c18b 8e9f 8e20 0897 1485');
    const kp = await generateKeyPair();
    expect(await samePublicKey(kp.publicKey, bytes(kp.publicKey))).toBe(true);
    expect(await samePublicKey(kp.publicKey, pk)).toBe(false);
    expect(await samePublicKey(kp.publicKey, new Uint8Array(3))).toBe(false);
  });
});
