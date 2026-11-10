import { describe, expect, it } from 'vitest';
import {
  AAD,
  createAccount,
  createRecoveryMaterial,
  createVault,
  decryptExport,
  decryptItem,
  decryptVaultName,
  deriveLoginKeys,
  encryptExport,
  encryptItem,
  encryptVaultName,
  fromB64u,
  generateKey,
  generateKeyPair,
  generateSecretKey,
  importSecretKey,
  openAccount,
  openAccountKeyWithRecovery,
  openAccountWithAccountKey,
  openDeviceSecretKey,
  openVaultKey,
  parseRecoveryCode,
  parseSecretKey,
  recoveryAuthFromCode,
  sealVaultKeyFor,
  wrapAccountKeyWithPassword,
  wrapDeviceSecretKey,
  type UnlockedAccount,
} from '../src/index.js';

const PW = 'correct horse battery staple';

async function login(reg: Awaited<ReturnType<typeof createAccount>>, pw: string, sk: Uint8Array | CryptoKey, payload = reg.payload) {
  const keys = await deriveLoginKeys(pw, sk, fromB64u(payload.kdfSalt), payload.kdfParams);
  return { keys, account: await openAccount(keys.encKey, payload) };
}

describe('account flows', () => {
  it('register → login → unlock every layer', async () => {
    const reg = await createAccount('a@example.com', PW);
    expect(parseSecretKey(reg.secretKeyDisplay)).toEqual(reg.secretKey);
    expect(reg.payload.authHash).not.toContain(PW);
    // Login on a new device from the emergency kit:
    const sk = await importSecretKey(parseSecretKey(reg.secretKeyDisplay));
    const { keys, account } = await login(reg, PW, sk);
    expect(keys.authHash).toEqual(fromB64u(reg.payload.authHash));
    expect(account.accountKey).toEqual(reg.account.accountKey);
    expect(account.privateKey).toEqual(reg.account.privateKey);
    const vaultKey = await openVaultKey(account, reg.payload.personalVault.sealedVaultKey);
    expect(vaultKey).toEqual(reg.personalVaultKey);
    const vid = reg.payload.personalVault.id;
    const item = { type: 'login', name: 'Example', password: 'SENTINEL' };
    const enc = await encryptItem(vaultKey, vid, 'item-1', item);
    expect(enc).not.toContain('SENTINEL');
    expect(await decryptItem(vaultKey, vid, 'item-1', enc)).toEqual(item);
    await expect(decryptItem(vaultKey, vid, 'item-2', enc)).rejects.toThrow('decrypt_failed');
  });

  it('missing or one-bit-wrong Secret Key cannot unlock', async () => {
    const reg = await createAccount('b@example.com', PW);
    const wrong = new Uint8Array(reg.secretKey);
    wrong[0] = wrong[0]! ^ 0x80;
    await expect(login(reg, PW, wrong)).rejects.toThrow('decrypt_failed');
    await expect(login(reg, PW, await generateSecretKey())).rejects.toThrow('decrypt_failed');
    await expect(login(reg, PW + ' ', reg.secretKey)).rejects.toThrow('decrypt_failed');
  });

  it('change password: old items still decrypt, old password fails', async () => {
    const reg = await createAccount('c@example.com', PW);
    const vid = reg.payload.personalVault.id;
    const enc = await encryptItem(reg.personalVaultKey, vid, 'i', { n: 1 });
    const creds = await wrapAccountKeyWithPassword(reg.account.userId, reg.account.accountKey, 'new password!', reg.secretKey);
    const payload2 = { ...reg.payload, ...creds };
    expect(creds.kdfSalt).not.toBe(reg.payload.kdfSalt);
    expect(creds.authHash).not.toBe(reg.payload.authHash);
    await expect(login(reg, PW, reg.secretKey, payload2)).rejects.toThrow('decrypt_failed');
    const { account } = await login(reg, 'new password!', reg.secretKey, payload2);
    const vk = await openVaultKey(account, reg.payload.personalVault.sealedVaultKey);
    expect(await decryptItem(vk, vid, 'i', enc)).toEqual({ n: 1 });
  });

  it('rotate Secret Key: old Secret Key stops working', async () => {
    const reg = await createAccount('d@example.com', PW);
    const newSk = await generateSecretKey();
    const creds = await wrapAccountKeyWithPassword(reg.account.userId, reg.account.accountKey, PW, newSk);
    const payload2 = { ...reg.payload, ...creds };
    await expect(login(reg, PW, reg.secretKey, payload2)).rejects.toThrow('decrypt_failed');
    expect((await login(reg, PW, newSk, payload2)).account.accountKey).toEqual(reg.account.accountKey);
  });

  it('recovery code resets the account with data intact', async () => {
    const reg = await createAccount('e@example.com', PW);
    const vid = reg.payload.personalVault.id;
    const enc = await encryptItem(reg.personalVaultKey, vid, 'i', { keep: true });
    const code = parseRecoveryCode(reg.recoveryCode);
    expect(await recoveryAuthFromCode(code)).toBe(reg.payload.recoveryAuth);
    const accountKey = await openAccountKeyWithRecovery(code, reg.account.userId, reg.payload.recoveryWrappedKey);
    const account = await openAccountWithAccountKey(accountKey, reg.payload);
    // New password, new Secret Key, new recovery code.
    const sk2 = await generateSecretKey();
    const creds = await wrapAccountKeyWithPassword(account.userId, account.accountKey, 'fresh', sk2);
    const rec2 = await createRecoveryMaterial(account.userId, account.accountKey);
    expect(rec2.recoveryCode).not.toBe(reg.recoveryCode);
    const payload2 = { ...reg.payload, ...creds, recoveryWrappedKey: rec2.recoveryWrappedKey, recoveryAuth: rec2.recoveryAuth };
    const { account: a2 } = await login(reg, 'fresh', sk2, payload2);
    const vk = await openVaultKey(a2, reg.payload.personalVault.sealedVaultKey);
    expect(await decryptItem(vk, vid, 'i', enc)).toEqual({ keep: true });
    // The old recovery code no longer opens the new wrapping.
    await expect(openAccountKeyWithRecovery(code, account.userId, rec2.recoveryWrappedKey)).rejects.toThrow('decrypt_failed');
    // A recovery wrapping cannot be replayed onto another user.
    await expect(openAccountKeyWithRecovery(code, 'someone-else', reg.payload.recoveryWrappedKey)).rejects.toThrow('decrypt_failed');
  });

  it('openAccountWithAccountKey wipes the account key on failure', async () => {
    const reg = await createAccount('f@example.com', PW);
    const wrongKey = await generateKey();
    await expect(openAccountWithAccountKey(wrongKey, reg.payload)).rejects.toThrow('decrypt_failed');
    expect(wrongKey.every((x) => x === 0)).toBe(true);
  });
});

describe('vaults and sharing', () => {
  async function member(): Promise<UnlockedAccount> {
    const kp = await generateKeyPair();
    return { userId: crypto.randomUUID(), accountKey: await generateKey(), ...kp };
  }

  it('shared vault: name encrypted, members open their copy, rotation locks out removed member', async () => {
    const owner = await member();
    const bob = await member();
    const v = await createVault(owner.publicKey, 'Family');
    expect(v.nameEnc).not.toContain('Family');
    expect(await decryptVaultName(v.vaultKey, v.vaultId, v.nameEnc!)).toBe('Family');
    await expect(decryptVaultName(v.vaultKey, crypto.randomUUID(), v.nameEnc!)).rejects.toThrow('decrypt_failed');
    const forBob = await sealVaultKeyFor(v.vaultKey, bob.publicKey);
    expect(await openVaultKey(bob, forBob)).toEqual(v.vaultKey);
    await expect(openVaultKey(owner, forBob)).rejects.toThrow('decrypt_failed');

    // Rotation: new key, re-encrypt; bob's old key cannot open new items.
    const newKey = await generateKey();
    const enc = await encryptItem(newKey, v.vaultId, 'i', { secret: 1 });
    await expect(decryptItem(v.vaultKey, v.vaultId, 'i', enc)).rejects.toThrow('decrypt_failed');
    expect(await encryptVaultName(newKey, v.vaultId, 'x')).toBeTypeOf('string');
  });

  it('personal vault has no name; a sealed non-32-byte payload is rejected', async () => {
    const owner = await member();
    const v = await createVault(owner.publicKey, null);
    expect(v.nameEnc).toBeNull();
    const { sealToPublicKey, toB64u } = await import('../src/index.js');
    const bad = toB64u(await sealToPublicKey(new Uint8Array(5), owner.publicKey));
    await expect(openVaultKey(owner, bad)).rejects.toThrow('decrypt_failed');
  });
});

describe('device Secret Key copy and export', () => {
  it('device copy round-trips under accountKey + userId', async () => {
    const ak = await generateKey();
    const sk = await generateSecretKey();
    const w = await wrapDeviceSecretKey(ak, 'u1', sk);
    expect(parseSecretKey(await openDeviceSecretKey(ak, 'u1', w))).toEqual(sk);
    await expect(openDeviceSecretKey(ak, 'u2', w)).rejects.toThrow('decrypt_failed');
  });

  it('encrypted export round-trips and rejects wrong password / format', async () => {
    const file = await encryptExport('export pw', { items: [{ password: 'SENTINEL' }] });
    expect(JSON.stringify(file)).not.toContain('SENTINEL');
    expect(await decryptExport('export pw', file)).toEqual({ items: [{ password: 'SENTINEL' }] });
    await expect(decryptExport('wrong', file)).rejects.toThrow('decrypt_failed');
    await expect(decryptExport('export pw', { ...file, v: 2 as 1 })).rejects.toThrow('unsupported_export');
    await expect(decryptExport('export pw', { ...file, format: 'x' as 'vpass-export' })).rejects.toThrow('unsupported_export');
    expect(AAD.export()).toBe('export|v1');
  });
});
