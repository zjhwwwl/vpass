// High-level flows from crypto-spec 4.4. Everything here returns ciphertext/public material for the
// server plus in-memory key material for the caller. Callers own wiping the returned keys.
import { AAD } from './aead.js';
import { fromB64u, toB64u, type Bytes } from './encoding.js';
import { openJson, sealJson, sealString, openString } from './envelope.js';
import { DEFAULT_KDF_PARAMS, deriveMasterKey, deriveRecoveryKeys, deriveSubkeys, randomSalt, argon2id, type KdfParams } from './kdf.js';
import {
  createRecoveryCode,
  formatSecretKey,
  generateKey,
  generateKeyPair,
  generateSecretKey,
  unwrapKey,
  uuid,
  wrapKey,
} from './keys.js';
import { openSealed, sealToPublicKey } from './share.js';
import { wipe } from './sodium.js';

export interface LoginKeys {
  encKey: Bytes;
  authHash: Bytes;
}

/** Derive encKey and authHash from password + Secret Key (raw or device CryptoKey). */
export async function deriveLoginKeys(
  password: string,
  secretKey: Uint8Array | CryptoKey,
  kdfSalt: Uint8Array,
  params: KdfParams,
): Promise<LoginKeys> {
  const masterKey = await deriveMasterKey(password, secretKey, kdfSalt, params);
  try {
    return await deriveSubkeys(masterKey);
  } finally {
    wipe(masterKey);
  }
}

export interface Credentials {
  kdfSalt: string;
  kdfParams: KdfParams;
  authHash: string;
  wrappedAccountKey: string;
}

/** Wrap an existing accountKey under a (new) password + Secret Key. Used by register, password change, Secret Key rotation, recovery. */
export async function wrapAccountKeyWithPassword(
  userId: string,
  accountKey: Uint8Array,
  password: string,
  secretKey: Uint8Array | CryptoKey,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<Credentials> {
  const salt = await randomSalt();
  const { encKey, authHash } = await deriveLoginKeys(password, secretKey, salt, params);
  try {
    return {
      kdfSalt: toB64u(salt),
      kdfParams: { ...params },
      authHash: toB64u(authHash),
      wrappedAccountKey: await wrapKey(encKey, accountKey, AAD.accountKey(userId)),
    };
  } finally {
    wipe(encKey, authHash);
  }
}

export interface RecoveryMaterial {
  /** Display string, shown once on the emergency kit. */
  recoveryCode: string;
  recoveryWrappedKey: string;
  recoveryAuth: string;
}

export async function createRecoveryMaterial(userId: string, accountKey: Uint8Array): Promise<RecoveryMaterial> {
  const { raw, display } = await createRecoveryCode();
  const { recoveryKey, recoveryAuth } = await deriveRecoveryKeys(raw);
  try {
    return {
      recoveryCode: display,
      recoveryWrappedKey: await wrapKey(recoveryKey, accountKey, AAD.recoveryKey(userId)),
      recoveryAuth: toB64u(recoveryAuth),
    };
  } finally {
    wipe(raw, recoveryKey, recoveryAuth);
  }
}

export interface UnlockedAccount {
  userId: string;
  accountKey: Bytes;
  publicKey: Bytes;
  privateKey: Bytes;
}

export interface NewVault {
  vaultId: string;
  vaultKey: Bytes;
  sealedVaultKey: string;
  nameEnc: string | null;
}

export async function createVault(ownerPublicKey: Uint8Array, name: string | null): Promise<NewVault> {
  const vaultId = uuid();
  const vaultKey = await generateKey();
  return {
    vaultId,
    vaultKey,
    sealedVaultKey: toB64u(await sealToPublicKey(vaultKey, ownerPublicKey)),
    nameEnc: name === null ? null : await sealString(vaultKey, name, AAD.vaultName(vaultId)),
  };
}

export async function sealVaultKeyFor(vaultKey: Uint8Array, memberPublicKey: Uint8Array): Promise<string> {
  return toB64u(await sealToPublicKey(vaultKey, memberPublicKey));
}

export async function openVaultKey(account: UnlockedAccount, sealedVaultKey: string): Promise<Bytes> {
  const k = await openSealed(fromB64u(sealedVaultKey), account.publicKey, account.privateKey);
  if (k.length !== 32) throw new Error('decrypt_failed');
  return k;
}

export async function decryptVaultName(vaultKey: Uint8Array, vaultId: string, nameEnc: string): Promise<string> {
  return openString(vaultKey, nameEnc, AAD.vaultName(vaultId));
}

export async function encryptVaultName(vaultKey: Uint8Array, vaultId: string, name: string): Promise<string> {
  return sealString(vaultKey, name, AAD.vaultName(vaultId));
}

export interface Registration {
  /** Sent to the server. */
  payload: {
    userId: string;
    email: string;
    kdfSalt: string;
    kdfParams: KdfParams;
    authHash: string;
    wrappedAccountKey: string;
    recoveryWrappedKey: string;
    recoveryAuth: string;
    publicKey: string;
    wrappedPrivateKey: string;
    personalVault: { id: string; sealedVaultKey: string };
  };
  /** Shown to the user once (emergency kit). Never sent. */
  secretKey: Bytes;
  secretKeyDisplay: string;
  recoveryCode: string;
  /** In-memory key material for the freshly registered session. */
  account: UnlockedAccount;
  personalVaultKey: Bytes;
}

/** Registration (crypto-spec 4.4). */
export async function createAccount(email: string, password: string, params: KdfParams = DEFAULT_KDF_PARAMS): Promise<Registration> {
  const userId = uuid();
  const secretKey = await generateSecretKey();
  const accountKey = await generateKey();
  const { publicKey, privateKey } = await generateKeyPair();
  const creds = await wrapAccountKeyWithPassword(userId, accountKey, password, secretKey, params);
  const recovery = await createRecoveryMaterial(userId, accountKey);
  const vault = await createVault(publicKey, null);
  return {
    payload: {
      userId,
      email,
      ...creds,
      recoveryWrappedKey: recovery.recoveryWrappedKey,
      recoveryAuth: recovery.recoveryAuth,
      publicKey: toB64u(publicKey),
      wrappedPrivateKey: await wrapKey(accountKey, privateKey, AAD.privateKey(userId)),
      personalVault: { id: vault.vaultId, sealedVaultKey: vault.sealedVaultKey },
    },
    secretKey,
    secretKeyDisplay: formatSecretKey(secretKey),
    recoveryCode: recovery.recoveryCode,
    account: { userId, accountKey, publicKey, privateKey },
    personalVaultKey: vault.vaultKey,
  };
}

export interface KeyBundle {
  userId: string;
  wrappedAccountKey: string;
  publicKey: string;
  wrappedPrivateKey: string;
}

/** Open accountKey with encKey, then the private key. */
export async function openAccount(encKey: Uint8Array, bundle: KeyBundle): Promise<UnlockedAccount> {
  const accountKey = await unwrapKey(encKey, bundle.wrappedAccountKey, AAD.accountKey(bundle.userId));
  return openAccountWithAccountKey(accountKey, bundle);
}

export async function openAccountWithAccountKey(accountKey: Bytes, bundle: KeyBundle): Promise<UnlockedAccount> {
  try {
    const privateKey = await unwrapKey(accountKey, bundle.wrappedPrivateKey, AAD.privateKey(bundle.userId));
    return { userId: bundle.userId, accountKey, publicKey: fromB64u(bundle.publicKey), privateKey };
  } catch (e) {
    wipe(accountKey);
    throw e;
  }
}

/** Recovery step 1: derive recoveryAuth (to prove to the server) from the typed code. */
export async function recoveryAuthFromCode(code: Uint8Array): Promise<string> {
  const { recoveryKey, recoveryAuth } = await deriveRecoveryKeys(code);
  wipe(recoveryKey);
  const out = toB64u(recoveryAuth);
  wipe(recoveryAuth);
  return out;
}

/** Recovery step 2: open accountKey with the recovery code. */
export async function openAccountKeyWithRecovery(code: Uint8Array, userId: string, recoveryWrappedKey: string): Promise<Bytes> {
  const { recoveryKey, recoveryAuth } = await deriveRecoveryKeys(code);
  try {
    return await unwrapKey(recoveryKey, recoveryWrappedKey, AAD.recoveryKey(userId));
  } finally {
    wipe(recoveryKey, recoveryAuth);
  }
}

// ---------------------------------------------------------------------------
// Items
// ---------------------------------------------------------------------------

export async function encryptItem(vaultKey: Uint8Array, vaultId: string, itemId: string, item: unknown): Promise<string> {
  return sealJson(vaultKey, item, AAD.item(vaultId, itemId));
}

export async function decryptItem<T = unknown>(vaultKey: Uint8Array, vaultId: string, itemId: string, data: string): Promise<T> {
  return openJson<T>(vaultKey, data, AAD.item(vaultId, itemId));
}

// ---------------------------------------------------------------------------
// Device copy of the Secret Key (decision D-13) — lets an unlocked device show its QR code.
// ---------------------------------------------------------------------------

export async function wrapDeviceSecretKey(accountKey: Uint8Array, userId: string, secretKey: Uint8Array): Promise<string> {
  return sealString(accountKey, formatSecretKey(secretKey), AAD.deviceSecretKey(userId));
}

export async function openDeviceSecretKey(accountKey: Uint8Array, userId: string, wrapped: string): Promise<string> {
  return openString(accountKey, wrapped, AAD.deviceSecretKey(userId));
}

// ---------------------------------------------------------------------------
// Encrypted export (decision D-16)
// ---------------------------------------------------------------------------

export interface EncryptedExport {
  format: 'vpass-export';
  v: 1;
  kdf: { salt: string; params: KdfParams };
  data: string;
}

export async function encryptExport(exportPassword: string, value: unknown): Promise<EncryptedExport> {
  const salt = await randomSalt();
  const key = await argon2id(exportPassword, salt, DEFAULT_KDF_PARAMS);
  try {
    return {
      format: 'vpass-export',
      v: 1,
      kdf: { salt: toB64u(salt), params: { ...DEFAULT_KDF_PARAMS } },
      data: await sealJson(key, value, AAD.export()),
    };
  } finally {
    wipe(key);
  }
}

export async function decryptExport<T = unknown>(exportPassword: string, file: EncryptedExport): Promise<T> {
  if (file.format !== 'vpass-export' || file.v !== 1) throw new Error('unsupported_export');
  const key = await argon2id(exportPassword, fromB64u(file.kdf.salt), file.kdf.params);
  try {
    return await openJson<T>(key, file.data, AAD.export());
  } finally {
    wipe(key);
  }
}
