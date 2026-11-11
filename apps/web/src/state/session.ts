// VaultSession: the only place keys and decrypted items live. Module-level, never persisted, never put in a
// React store. React reads it through useSyncExternalStore via a version counter. lock() wipes everything.
import {
  createRecoveryMaterial,
  createVault,
  decryptItem,
  decryptVaultName,
  encryptItem,
  formatSecretKey,
  fromB64u,
  generateKey,
  generateSecretKey,
  importSecretKey,
  initCrypto,
  openAccount,
  openAccountKeyWithRecovery,
  openAccountWithAccountKey,
  openDeviceSecretKey,
  openVaultKey,
  parseRecoveryCode,
  parseSecretKey,
  recoveryAuthFromCode,
  sealVaultKeyFor,
  uuid,
  wipe,
  wrapDeviceSecretKey,
  encryptVaultName,
  type Bytes,
  type Registration,
  type UnlockedAccount,
} from '@vpass/crypto';
import type { ItemDto, KeyBundleDto, MemberDto, Role, VaultDto } from '@vpass/shared';
import { api, ApiError, OfflineError } from '../lib/api.js';
import { idb, type Settings, DEFAULT_SETTINGS } from '../lib/idb.js';
import { kdf, terminateKdfWorker } from '../lib/kdfWorker.js';
import { normalizeItem, type Item } from '../lib/item.js';

export type Status = 'booting' | 'loggedOut' | 'locked' | 'unlocked';

export interface DecryptedItem {
  id: string;
  vaultId: string;
  revision: number;
  updatedAt: number;
  item: Item;
}

export interface VaultView {
  id: string;
  kind: 'personal' | 'shared';
  name: string;
  role: Role;
  ownerId: string;
  revision: number;
  keyEpoch: number;
}

interface VaultState {
  meta: VaultView;
  sealedVaultKey: string;
  nameEnc: string | null;
  key: Bytes;
  items: Map<string, DecryptedItem>;
  /** ciphertext, for the offline cache */
  raw: Map<string, ItemDto>;
}

export interface PublicState {
  status: Status;
  bundle: KeyBundleDto | null;
  /** Session cookie still valid (false = offline unlock from cache). */
  online: boolean;
  hasDeviceKey: boolean;
  syncing: boolean;
  /**
   * Data the server sent that could not be decrypted or does not add up (P6 H1, partial mitigation): vault keys
   * that do not open, items that fail authentication, or more than one "personal" vault. Never silently ignored.
   */
  integrityIssues: string[];
  lastSyncAt: number | null;
  lastError: string | null;
  settings: Settings;
  version: number;
}

export class ConflictError extends Error {
  constructor(
    public readonly mine: Item,
    public readonly theirs: DecryptedItem | null,
    /** Server revision to pass as expectedRevision to overwrite (null = row absent). */
    public readonly serverRevision: number | null,
  ) {
    super('conflict');
  }
}

let state: PublicState = {
  status: 'booting',
  bundle: null,
  online: true,
  hasDeviceKey: false,
  syncing: false,
  integrityIssues: [],
  lastSyncAt: null,
  lastError: null,
  settings: DEFAULT_SETTINGS,
  version: 0,
};

let account: UnlockedAccount | null = null;
const vaults = new Map<string, VaultState>();
const listeners = new Set<() => void>();

function emit(patch: Partial<PublicState> = {}): void {
  state = { ...state, ...patch, version: state.version + 1 };
  for (const l of listeners) l();
}

export const session = {
  subscribe(l: () => void): () => void {
    listeners.add(l);
    return () => listeners.delete(l);
  },
  getSnapshot: (): PublicState => state,

  // ------------------------------------------------------------- read access (unlocked only)
  vaults(): VaultView[] {
    return [...vaults.values()].map((v) => v.meta).sort((a, b) => (a.kind === b.kind ? a.name.localeCompare(b.name) : a.kind === 'personal' ? -1 : 1));
  },
  items(vaultId?: string): DecryptedItem[] {
    const out: DecryptedItem[] = [];
    for (const v of vaults.values()) if (!vaultId || v.meta.id === vaultId) out.push(...v.items.values());
    return out;
  },
  item(vaultId: string, itemId: string): DecryptedItem | undefined {
    return vaults.get(vaultId)?.items.get(itemId);
  },
  vault(vaultId: string): VaultView | undefined {
    return vaults.get(vaultId)?.meta;
  },
  personalVaultId(): string | null {
    for (const v of vaults.values()) if (v.meta.kind === 'personal') return v.meta.id;
    return null;
  },
  userId: () => account?.userId ?? state.bundle?.userId ?? null,
  publicKey: () => state.bundle?.publicKey ?? null,

  // ------------------------------------------------------------- lifecycle

  async boot(): Promise<void> {
    await initCrypto();
    const settings = await idb.getSettings();
    emit({ settings });
    try {
      const bundle = await api.me();
      const dev = await idb.getDevice(bundle.userId);
      emit({ status: 'locked', bundle, online: true, hasDeviceKey: !!dev });
    } catch (e) {
      if (e instanceof OfflineError && settings.lastEmail) {
        const dev = await idb.findDeviceByEmail(settings.lastEmail);
        const cache = dev ? await idb.getCache(dev.id) : undefined;
        if (dev && cache) {
          emit({ status: 'locked', bundle: cache.bundle, online: false, hasDeviceKey: true });
          return;
        }
      }
      emit({ status: 'loggedOut', bundle: null });
    }
  },

  /** Is a Secret Key stored on this device for this email? */
  async deviceKnows(email: string): Promise<boolean> {
    return !!(await idb.findDeviceByEmail(email));
  },

  /**
   * Login (crypto-spec 4.4). `secretKeyInput` is required on a new device; it is checksum-validated locally
   * before any request. Returns 'totp' when the server asks for a second factor; call again with `totp`.
   */
  async login(email: string, password: string, secretKeyInput: string | null, totp?: string): Promise<'ok' | 'totp'> {
    const dev = await idb.findDeviceByEmail(email);
    let rawSk: Bytes | null = null;
    let sk: CryptoKey;
    if (dev) {
      sk = dev.secretKey;
    } else {
      if (!secretKeyInput) throw new Error('secret_key_format');
      rawSk = parseSecretKey(secretKeyInput); // throws locally on typos
      sk = await importSecretKey(rawSk);
    }
    const pre = await api.prelogin(email);
    const keys = await kdf.deriveLoginKeys(password, sk, fromB64u(pre.kdfSalt), pre.kdfParams);
    let bundle: KeyBundleDto;
    try {
      bundle = await api.login(email, toB64(keys.authHash), totp);
    } catch (e) {
      wipe(keys.encKey, keys.authHash);
      if (e instanceof ApiError && e.code === 'totp_required') {
        wipe(rawSk);
        return 'totp';
      }
      throw e;
    }
    const acct = await openAccount(keys.encKey, bundle);
    wipe(keys.encKey, keys.authHash);
    if (rawSk) {
      await idb.putDevice({ id: bundle.userId, email: bundle.email, secretKey: sk, wrappedSecretKey: await wrapDeviceSecretKey(acct.accountKey, bundle.userId, rawSk) });
      wipe(rawSk);
    }
    await this.afterUnlock(acct, bundle, true);
    return 'ok';
  },

  /** Unlock while the session is still valid: local derivation only, no server round trip. */
  async unlock(password: string, secretKeyInput?: string): Promise<void> {
    const bundle = state.bundle;
    if (!bundle) throw new Error('unauthorized');
    const dev = await idb.getDevice(bundle.userId);
    let rawSk: Bytes | null = null;
    let sk: CryptoKey;
    if (dev) sk = dev.secretKey;
    else {
      rawSk = parseSecretKey(secretKeyInput ?? '');
      sk = await importSecretKey(rawSk);
    }
    const keys = await kdf.deriveLoginKeys(password, sk, fromB64u(bundle.kdfSalt), bundle.kdfParams);
    wipe(keys.authHash);
    let acct: UnlockedAccount;
    try {
      acct = await openAccount(keys.encKey, bundle);
    } finally {
      wipe(keys.encKey);
    }
    if (rawSk) {
      await idb.putDevice({ id: bundle.userId, email: bundle.email, secretKey: sk, wrappedSecretKey: await wrapDeviceSecretKey(acct.accountKey, bundle.userId, rawSk) });
      wipe(rawSk);
    }
    await this.afterUnlock(acct, bundle, state.online);
  },

  async register(inviteCode: string, reg: Registration): Promise<void> {
    const bundle = await api.register({ inviteCode, ...reg.payload, deviceLabel: deviceLabel() });
    await idb.putDevice({
      id: bundle.userId,
      email: bundle.email,
      secretKey: await importSecretKey(reg.secretKey),
      wrappedSecretKey: await wrapDeviceSecretKey(reg.account.accountKey, bundle.userId, reg.secretKey),
    });
    wipe(reg.secretKey);
    await this.afterUnlock(reg.account, bundle, true);
    wipe(reg.personalVaultKey);
  },

  async afterUnlock(acct: UnlockedAccount, bundle: KeyBundleDto, online: boolean): Promise<void> {
    account = acct;
    const settings = await idb.patchSettings({ lastEmail: bundle.email });
    emit({ status: 'unlocked', bundle, online, hasDeviceKey: true, settings, lastError: null });
    const cache = settings.offlineCache ? await idb.getCache(bundle.userId) : undefined;
    if (cache) await applyVaults(cache.vaults, true);
    emit();
    if (online) await this.sync().catch(() => undefined);
  },

  lock(): void {
    terminateKdfWorker();
    if (account) wipe(account.accountKey, account.privateKey);
    account = null;
    for (const v of vaults.values()) wipe(v.key);
    vaults.clear();
    if (state.status === 'unlocked') emit({ status: 'locked' });
  },

  async logout(forgetDevice = false): Promise<void> {
    const uid = this.userId();
    this.lock();
    try {
      await api.logout();
    } catch {
      /* already gone */
    }
    if (uid) {
      await idb.deleteCache(uid);
      if (forgetDevice) await idb.deleteDevice(uid);
    }
    emit({ status: 'loggedOut', bundle: null });
  },

  // ------------------------------------------------------------- sync

  async sync(): Promise<void> {
    if (!account || state.syncing) return;
    emit({ syncing: true });
    try {
      const since = [...vaults.values()].map((v) => `${v.meta.id}.${v.meta.revision}`).join(',');
      const res = await api.sync(since);
      if (await applyVaults(res.vaults, false)) {
        // A vault key changed under a delta response: fetch that vault in full.
        const again = [...vaults.values()].map((v) => `${v.meta.id}.${v.meta.revision}`).join(',');
        await applyVaults((await api.sync(again)).vaults, false);
      }
      await saveCache();
      emit({ syncing: false, lastSyncAt: Date.now(), lastError: null, online: true });
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        this.lock();
        emit({ syncing: false, status: 'loggedOut', bundle: null });
        return;
      }
      emit({ syncing: false, lastError: e instanceof OfflineError ? 'offline' : 'sync_failed', online: !(e instanceof OfflineError) });
    }
  },

  // ------------------------------------------------------------- items

  async saveItem(vaultId: string, itemId: string | null, item: Item, expectedRevision?: number | null): Promise<string> {
    const v = need(vaultId);
    const id = itemId ?? uuid();
    const existing = itemId ? v.items.get(itemId) : undefined;
    const expected = expectedRevision !== undefined ? expectedRevision : (existing?.revision ?? null);
    const data = await encryptItem(v.key, vaultId, id, item);
    try {
      const res = await api.putItem(vaultId, id, data, v.meta.keyEpoch, expected);
      v.items.set(id, { id, vaultId, revision: res.revision, updatedAt: Date.now(), item });
      v.raw.set(id, { id, data, keyEpoch: v.meta.keyEpoch, revision: res.revision, deleted: false, updatedAt: Date.now() });
      // Only advance our vault revision if nothing else happened in between; otherwise the next sync fetches the gap.
      if (res.vaultRevision === v.meta.revision + 1) v.meta = { ...v.meta, revision: res.vaultRevision };
      emit();
      void saveCache();
      return id;
    } catch (e) {
      if (e instanceof ApiError && e.code === 'conflict') {
        const cur = e.body.current as ItemDto | null | undefined;
        if (e.body.reason === 'key_epoch') {
          await this.sync();
          throw e;
        }
        let theirs: DecryptedItem | null = null;
        if (cur && !cur.deleted) {
          theirs = { id, vaultId, revision: cur.revision, updatedAt: cur.updatedAt, item: normalizeItem(await decryptItem(v.key, vaultId, id, cur.data)) };
        }
        throw new ConflictError(item, theirs, cur ? cur.revision : null);
      }
      throw e;
    }
  },

  async deleteItem(vaultId: string, itemId: string): Promise<void> {
    const v = need(vaultId);
    const it = v.items.get(itemId);
    if (!it) return;
    await api.deleteItem(vaultId, itemId, it.revision);
    v.items.delete(itemId);
    v.raw.delete(itemId);
    emit();
    await this.sync();
  },

  // ------------------------------------------------------------- shared vaults (section 8)

  async createSharedVault(name: string): Promise<string> {
    const acct = needAccount();
    const nv = await createVault(acct.publicKey, name);
    await api.createVault(nv.vaultId, nv.nameEnc!, nv.sealedVaultKey);
    wipe(nv.vaultKey);
    await this.sync();
    return nv.vaultId;
  },

  async members(vaultId: string): Promise<MemberDto[]> {
    return (await api.members(vaultId)).members;
  },

  /** Add or change a member. The public key must come from a verified contact (checked by the caller UI). */
  async putMember(vaultId: string, userId: string, publicKeyB64: string, role: 'editor' | 'viewer'): Promise<void> {
    const v = need(vaultId);
    const sealed = await sealVaultKeyFor(v.key, fromB64u(publicKeyB64));
    await api.putMember(vaultId, userId, sealed, role, v.meta.keyEpoch);
  },

  /**
   * Remove members by rotating the vault key: new key, epoch+1, every item re-encrypted, remaining members re-sealed.
   * `keep` maps userId → verified public key (base64url). One D1 transaction server-side.
   */
  async rotateVault(vaultId: string, keep: Map<string, string>): Promise<string[]> {
    await this.sync();
    const v = need(vaultId);
    const newKey = await generateKey();
    const epoch = v.meta.keyEpoch + 1;
    try {
      const members = await Promise.all([...keep].map(async ([userId, pk]) => ({ userId, sealedVaultKey: await sealVaultKeyFor(newKey, fromB64u(pk)) })));
      const items = await Promise.all(
        [...v.items.values()].map(async (it) => ({ id: it.id, data: await encryptItem(newKey, vaultId, it.id, it.item), expectedRevision: it.revision })),
      );
      const res = await api.rotate(vaultId, {
        keyEpoch: epoch,
        expectedVaultRevision: v.meta.revision,
        nameEnc: await encryptVaultName(newKey, vaultId, v.meta.name),
        members,
        items,
      });
      // Force a full refetch of this vault under the new key.
      wipe(v.key);
      vaults.delete(vaultId);
      await this.sync();
      return res.removed;
    } finally {
      wipe(newKey);
    }
  },

  // ------------------------------------------------------------- account settings

  /** authHash for the current password, derived locally (for server-side re-authentication). */
  async currentAuthHash(password: string): Promise<string> {
    const bundle = needBundle();
    const dev = await idb.getDevice(bundle.userId);
    if (!dev) throw new Error('secret_key_format');
    const keys = await kdf.deriveLoginKeys(password, dev.secretKey, fromB64u(bundle.kdfSalt), bundle.kdfParams);
    try {
      // Verify locally first so a typo doesn't count as a failed login.
      const probe = await openAccount(keys.encKey, bundle);
      wipe(probe.accountKey, probe.privateKey);
      return toB64(keys.authHash);
    } finally {
      wipe(keys.encKey, keys.authHash);
    }
  },

  async changePassword(oldPassword: string, newPassword: string): Promise<void> {
    const acct = needAccount();
    const bundle = needBundle();
    const oldAuthHash = await this.currentAuthHash(oldPassword);
    const dev = (await idb.getDevice(bundle.userId))!;
    const creds = await kdf.wrapAccountKey(acct.userId, acct.accountKey, newPassword, dev.secretKey);
    const nb = await api.changePassword(oldAuthHash, creds);
    emit({ bundle: nb });
    await saveCache();
  },

  /** Rotate the Secret Key (blueprint 4.4). Returns the new formatted key for a fresh emergency kit. */
  async rotateSecretKey(password: string): Promise<string> {
    const acct = needAccount();
    const bundle = needBundle();
    const oldAuthHash = await this.currentAuthHash(password);
    const raw = await generateSecretKey();
    try {
      const creds = await kdf.wrapAccountKey(acct.userId, acct.accountKey, password, raw);
      const nb = await api.changePassword(oldAuthHash, creds);
      await idb.putDevice({ id: bundle.userId, email: bundle.email, secretKey: await importSecretKey(raw), wrappedSecretKey: await wrapDeviceSecretKey(acct.accountKey, bundle.userId, raw) });
      emit({ bundle: nb });
      await saveCache();
      return formatSecretKey(raw);
    } finally {
      wipe(raw);
    }
  },

  async regenerateRecoveryCode(password: string): Promise<string> {
    const acct = needAccount();
    const authHash = await this.currentAuthHash(password);
    const rec = await createRecoveryMaterial(acct.userId, acct.accountKey);
    await api.recoveryCode(authHash, rec.recoveryWrappedKey, rec.recoveryAuth);
    return rec.recoveryCode;
  },

  async secretKeyDisplay(): Promise<string> {
    const acct = needAccount();
    const dev = await idb.getDevice(acct.userId);
    if (!dev) throw new Error('secret_key_format');
    return openDeviceSecretKey(acct.accountKey, acct.userId, dev.wrappedSecretKey);
  },

  async patchSettings(p: Partial<Settings>): Promise<void> {
    const settings = await idb.patchSettings(p);
    if (p.offlineCache === false) await idb.clearCache();
    emit({ settings });
    if (p.offlineCache === true) await saveCache();
  },

  // ------------------------------------------------------------- recovery (4.4)

  /** Step 1+2: verify the code with the server and open accountKey locally. */
  async recoverOpen(email: string, codeInput: string): Promise<{ accountKey: Bytes; userId: string; publicKey: string; wrappedPrivateKey: string; recoveryAuth: string }> {
    const code = parseRecoveryCode(codeInput);
    try {
      const recoveryAuth = await recoveryAuthFromCode(code);
      const start = await api.recoverStart(email, recoveryAuth);
      const accountKey = await openAccountKeyWithRecovery(code, start.userId, start.recoveryWrappedKey);
      return { accountKey, userId: start.userId, publicKey: start.publicKey, wrappedPrivateKey: start.wrappedPrivateKey, recoveryAuth };
    } finally {
      wipe(code);
    }
  },

  /** Step 3: new password + new Secret Key + new recovery code; all sessions revoked; logged in here. */
  async recoverFinish(
    email: string,
    opened: { accountKey: Bytes; userId: string; publicKey: string; wrappedPrivateKey: string; recoveryAuth: string },
    newPassword: string,
  ): Promise<{ secretKey: string; recoveryCode: string; enter: () => Promise<void> }> {
    const raw = await generateSecretKey();
    const creds = await kdf.wrapAccountKey(opened.userId, opened.accountKey, newPassword, raw);
    const rec = await createRecoveryMaterial(opened.userId, opened.accountKey);
    const bundle = await api.recover({
      email,
      recoveryAuth: opened.recoveryAuth,
      ...creds,
      newRecoveryWrappedKey: rec.recoveryWrappedKey,
      newRecoveryAuth: rec.recoveryAuth,
      deviceLabel: deviceLabel(),
    });
    const acct = await openAccountWithAccountKey(opened.accountKey, { userId: opened.userId, wrappedAccountKey: creds.wrappedAccountKey, publicKey: opened.publicKey, wrappedPrivateKey: opened.wrappedPrivateKey });
    await idb.putDevice({ id: bundle.userId, email: bundle.email, secretKey: await importSecretKey(raw), wrappedSecretKey: await wrapDeviceSecretKey(acct.accountKey, bundle.userId, raw) });
    const display = formatSecretKey(raw);
    wipe(raw);
    // The caller shows the new emergency kit first, then enters the vault.
    return { secretKey: display, recoveryCode: rec.recoveryCode, enter: () => this.afterUnlock(acct, bundle, true) };
  },

  setBundle(bundle: KeyBundleDto): void {
    emit({ bundle });
  },
};

// ---------------------------------------------------------------- internals

function needAccount(): UnlockedAccount {
  if (!account) throw new Error('locked');
  return account;
}
function needBundle(): KeyBundleDto {
  if (!state.bundle) throw new Error('unauthorized');
  return state.bundle;
}
function need(vaultId: string): VaultState {
  const v = vaults.get(vaultId);
  if (!v) throw new Error('not_found');
  return v;
}

function toB64(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function deviceLabel(): string {
  const ua = navigator.userAgent;
  const os = /Windows/.test(ua) ? 'Windows' : /iPhone|iPad/.test(ua) ? 'iOS' : /Android/.test(ua) ? 'Android' : /Mac OS X/.test(ua) ? 'macOS' : 'Linux';
  const br = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : 'Safari';
  return `${br} · ${os}`;
}

/** Merge server (or cached) vault data. Ciphertext that fails to decrypt is dropped, never silently accepted. */
async function applyVaults(list: VaultDto[], fromCache: boolean): Promise<boolean> {
  const acct = account;
  if (!acct) return false;
  let resync = false;
  const seen = new Set<string>();
  const issues: string[] = [];
  const personal = list.filter((d) => d.kind === 'personal');
  if (personal.length > 1) issues.push(`服务器返回了 ${personal.length} 个“个人保管库”，正常应只有 1 个`);
  for (const dto of list) {
    seen.add(dto.id);
    let v = vaults.get(dto.id);
    if (v && (v.sealedVaultKey !== dto.sealedVaultKey || v.meta.keyEpoch !== dto.keyEpoch)) {
      // Key changed (rotation or re-share): start over for this vault.
      wipe(v.key);
      vaults.delete(dto.id);
      v = undefined;
      if (!dto.full) {
        resync = true; // next sync without `since` gets the full set
        continue;
      }
    }
    if (!v) {
      let key: Bytes;
      try {
        key = await openVaultKey(acct, dto.sealedVaultKey);
      } catch {
        issues.push(`保管库 ${dto.id.slice(0, 8)} 的密钥无法用你的私钥打开`);
        continue;
      }
      let name = '个人保管库';
      if (dto.kind === 'shared' && dto.nameEnc) {
        try {
          name = await decryptVaultName(key, dto.id, dto.nameEnc);
        } catch {
          name = '（名称无法解密）';
        }
      }
      v = {
        meta: { id: dto.id, kind: dto.kind, name, role: dto.role, ownerId: dto.ownerId, revision: 0, keyEpoch: dto.keyEpoch },
        sealedVaultKey: dto.sealedVaultKey,
        nameEnc: dto.nameEnc,
        key,
        items: new Map(),
        raw: new Map(),
      };
      vaults.set(dto.id, v);
    } else if (dto.nameEnc !== v.nameEnc && dto.nameEnc) {
      try {
        v.meta = { ...v.meta, name: await decryptVaultName(v.key, dto.id, dto.nameEnc) };
        v.nameEnc = dto.nameEnc;
      } catch {
        /* keep old */
      }
    }
    if (dto.full) {
      v.items.clear();
      v.raw.clear();
    }
    for (const it of dto.items) {
      if (it.deleted) {
        v.items.delete(it.id);
        v.raw.delete(it.id);
        continue;
      }
      if (it.keyEpoch !== dto.keyEpoch) continue;
      try {
        const item = normalizeItem(await decryptItem(v.key, dto.id, it.id, it.data));
        v.items.set(it.id, { id: it.id, vaultId: dto.id, revision: it.revision, updatedAt: it.updatedAt, item });
        v.raw.set(it.id, it);
      } catch {
        // Tampered or foreign ciphertext: refuse it, and tell the user.
        issues.push(`保管库 ${dto.id.slice(0, 8)} 中的条目 ${it.id.slice(0, 8)} 无法解密`);
      }
    }
    v.meta = { ...v.meta, role: dto.role, revision: dto.revision };
  }
  if (!fromCache) {
    for (const [id, v] of vaults) {
      if (!seen.has(id)) {
        wipe(v.key);
        vaults.delete(id);
      }
    }
  }
  if (!fromCache) state = { ...state, integrityIssues: issues };
  return resync;
}

async function saveCache(): Promise<void> {
  if (!state.settings.offlineCache || !state.bundle) return;
  const list: VaultDto[] = [...vaults.values()].map((v) => ({
    id: v.meta.id,
    kind: v.meta.kind,
    ownerId: v.meta.ownerId,
    nameEnc: v.nameEnc,
    revision: v.meta.revision,
    keyEpoch: v.meta.keyEpoch,
    role: v.meta.role,
    sealedVaultKey: v.sealedVaultKey,
    full: true,
    items: [...v.raw.values()],
  }));
  await idb.putCache({ id: state.bundle.userId, bundle: state.bundle, vaults: list, savedAt: Date.now() });
}

