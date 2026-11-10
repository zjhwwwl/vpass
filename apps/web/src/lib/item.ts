// Item plaintext model (crypto-spec 4.3). Exists only in memory after decryption.

export type ItemType = 'login' | 'note' | 'card' | 'contact';

export interface Field {
  label: string;
  value: string;
  hidden: boolean;
}

export interface ContactInfo {
  userId: string;
  email: string;
  publicKey: string;
  verifiedAt: string;
}

export interface Item {
  type: ItemType;
  name: string;
  username: string;
  password: string;
  urls: string[];
  totp: string;
  notes: string;
  fields: Field[];
  favorite: boolean;
  passwordHistory: { value: string; changedAt: string }[];
  contact?: ContactInfo;
}

export function emptyItem(type: ItemType = 'login'): Item {
  const fields: Field[] =
    type === 'card'
      ? [
          { label: '持卡人', value: '', hidden: false },
          { label: '卡号', value: '', hidden: true },
          { label: '有效期', value: '', hidden: false },
          { label: 'CVV', value: '', hidden: true },
        ]
      : [];
  return { type, name: '', username: '', password: '', urls: type === 'login' ? [''] : [], totp: '', notes: '', fields, favorite: false, passwordHistory: [] };
}

/** Defensive normalization of decrypted JSON (older/foreign shapes). */
export function normalizeItem(raw: unknown): Item {
  const r = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>;
  const str = (v: unknown) => (typeof v === 'string' ? v : '');
  const type = (['login', 'note', 'card', 'contact'] as const).includes(r.type as ItemType) ? (r.type as ItemType) : 'login';
  const item: Item = {
    type,
    name: str(r.name),
    username: str(r.username),
    password: str(r.password),
    urls: Array.isArray(r.urls) ? r.urls.filter((u): u is string => typeof u === 'string') : [],
    totp: str(r.totp),
    notes: str(r.notes),
    fields: Array.isArray(r.fields)
      ? r.fields
          .filter((f): f is Record<string, unknown> => typeof f === 'object' && f !== null)
          .map((f) => ({ label: str(f.label), value: str(f.value), hidden: f.hidden === true }))
      : [],
    favorite: r.favorite === true,
    passwordHistory: Array.isArray(r.passwordHistory)
      ? r.passwordHistory
          .filter((h): h is Record<string, unknown> => typeof h === 'object' && h !== null)
          .map((h) => ({ value: str(h.value), changedAt: str(h.changedAt) }))
      : [],
  };
  if (type === 'contact' && typeof r.contact === 'object' && r.contact !== null) {
    const c = r.contact as Record<string, unknown>;
    item.contact = { userId: str(c.userId), email: str(c.email), publicKey: str(c.publicKey), verifiedAt: str(c.verifiedAt) };
  }
  return item;
}

/** Only http(s) URLs may become links (blueprint section 7). */
export function safeHttpUrl(u: string): string | null {
  const s = u.trim();
  if (!s) return null;
  try {
    const url = new URL(/^[a-z][a-z0-9+.-]*:/i.test(s) ? s : `https://${s}`);
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : null;
  } catch {
    return null;
  }
}

export function hostOf(u: string): string {
  const s = safeHttpUrl(u);
  return s ? new URL(s).hostname : u;
}

/** Record the previous password when it changes. */
export function withPasswordHistory(prev: Item | null, next: Item): Item {
  if (!prev || !prev.password || prev.password === next.password) return next;
  return { ...next, passwordHistory: [{ value: prev.password, changedAt: new Date().toISOString() }, ...next.passwordHistory].slice(0, 20) };
}
