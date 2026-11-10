// IndexedDB: ciphertext-only offline cache, device Secret Key (non-extractable CryptoKey), and settings.
// Nothing here is plaintext or an exportable key. localStorage/sessionStorage are never used.
import type { KeyBundleDto, VaultDto } from '@vpass/shared';

const DB_NAME = 'vpass';
const DB_VERSION = 1;

export interface DeviceRecord {
  /** userId */
  id: string;
  email: string;
  /** Non-extractable HKDF CryptoKey. */
  secretKey: CryptoKey;
  /** AEAD(accountKey, formatted Secret Key) — only to display the QR code while unlocked (D-13). */
  wrappedSecretKey: string;
}

export interface CacheRecord {
  /** userId */
  id: string;
  bundle: KeyBundleDto;
  vaults: VaultDto[];
  savedAt: number;
}

export interface Settings {
  lastEmail: string | null;
  autoLockMinutes: number;
  hiddenLockMinutes: number;
  offlineCache: boolean;
  clipboardSeconds: number;
}

export const DEFAULT_SETTINGS: Settings = { lastEmail: null, autoLockMinutes: 10, hiddenLockMinutes: 5, offlineCache: true, clipboardSeconds: 30 };

let dbp: Promise<IDBDatabase> | null = null;

function openDb(): Promise<IDBDatabase> {
  dbp ??= new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      db.createObjectStore('device', { keyPath: 'id' });
      db.createObjectStore('cache', { keyPath: 'id' });
      db.createObjectStore('settings');
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('idb'));
  });
  return dbp;
}

function tx<T>(store: string, mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return openDb().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const t = db.transaction(store, mode);
        const req = fn(t.objectStore(store));
        t.oncomplete = () => resolve(req.result);
        t.onerror = () => reject(t.error ?? new Error('idb'));
        t.onabort = () => reject(t.error ?? new Error('idb'));
      }),
  );
}

export const idb = {
  getDevice: (userId: string) => tx<DeviceRecord | undefined>('device', 'readonly', (s) => s.get(userId) as IDBRequest<DeviceRecord | undefined>),
  async findDeviceByEmail(email: string): Promise<DeviceRecord | undefined> {
    const all = await tx<DeviceRecord[]>('device', 'readonly', (s) => s.getAll() as IDBRequest<DeviceRecord[]>);
    return all.find((d) => d.email.toLowerCase() === email.toLowerCase());
  },
  putDevice: (d: DeviceRecord) => tx('device', 'readwrite', (s) => s.put(d)),
  deleteDevice: (userId: string) => tx('device', 'readwrite', (s) => s.delete(userId)),
  getCache: (userId: string) => tx<CacheRecord | undefined>('cache', 'readonly', (s) => s.get(userId) as IDBRequest<CacheRecord | undefined>),
  putCache: (c: CacheRecord) => tx('cache', 'readwrite', (s) => s.put(c)),
  deleteCache: (userId: string) => tx('cache', 'readwrite', (s) => s.delete(userId)),
  clearCache: () => tx('cache', 'readwrite', (s) => s.clear()),
  async getSettings(): Promise<Settings> {
    const s = await tx<Partial<Settings> | undefined>('settings', 'readonly', (st) => st.get('settings') as IDBRequest<Partial<Settings> | undefined>);
    return { ...DEFAULT_SETTINGS, ...(s ?? {}) };
  },
  async patchSettings(p: Partial<Settings>): Promise<Settings> {
    const next = { ...(await idb.getSettings()), ...p };
    await tx('settings', 'readwrite', (s) => s.put(next, 'settings'));
    return next;
  },
};
