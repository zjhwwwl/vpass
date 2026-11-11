// RFC 4180 CSV parsing and writing, plus importers for Bitwarden / 1Password / Chrome (all in-browser).
import { emptyItem, type Item } from './item.js';

export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  const s = text.replace(/^\uFEFF/, '');
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (quoted) {
      if (ch === '"') {
        if (s[i + 1] === '"') {
          field += '"';
          i++;
        } else quoted = false;
      } else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ',') {
      row.push(field);
      field = '';
    } else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && s[i + 1] === '\n') i++;
      row.push(field);
      field = '';
      if (row.length > 1 || row[0] !== '') rows.push(row);
      row = [];
    } else field += ch;
  }
  if (field !== '' || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

/** Spreadsheet formula prefixes. Quoting alone does not stop Excel from evaluating them (P6 L4). */
const FORMULA_START = /^[=+\-@\t\r]/;

export function toCsv(rows: string[][]): string {
  return rows
    .map((r) =>
      r
        .map((raw) => {
          const f = FORMULA_START.test(raw) ? `'${raw}` : raw;
          return /[",\r\n']/.test(f) ? `"${f.replace(/"/g, '""')}"` : f;
        })
        .join(','),
    )
    .join('\r\n');
}

/** Undo the export-side formula escape when re-importing our own CSV. */
function unescapeFormula(f: string): string {
  return /^'[=+\-@\t\r]/.test(f) ? f.slice(1) : f;
}

function records(text: string): Record<string, string>[] {
  const [header, ...rest] = parseCsv(text);
  if (!header) return [];
  const keys = header.map((h) => h.trim().toLowerCase());
  return rest.map((r) => Object.fromEntries(keys.map((k, i) => [k, r[i] ?? ''])));
}

export type ImportFormat = 'bitwarden-csv' | 'bitwarden-json' | '1password-csv' | 'chrome-csv' | 'vpass-csv';

export function detectFormat(text: string): ImportFormat | null {
  const t = text.trimStart();
  if (t.startsWith('{')) return 'bitwarden-json';
  const header = (parseCsv(t.split(/\r?\n/, 1)[0] ?? '')[0] ?? []).map((h) => h.trim().toLowerCase());
  const has = (...k: string[]) => k.every((x) => header.includes(x));
  if (has('login_uri', 'login_username', 'login_password')) return 'bitwarden-csv';
  if (has('name', 'url', 'username', 'password') && header.includes('note')) return 'chrome-csv';
  if (has('title', 'username', 'password') && (header.includes('url') || header.includes('website'))) return '1password-csv';
  if (has('type', 'name', 'username', 'password', 'urls')) return 'vpass-csv';
  if (has('name', 'url', 'username', 'password')) return 'chrome-csv';
  return null;
}

function login(name: string, username: string, password: string, urls: string[], notes: string, totp = '', favorite = false): Item {
  return { ...emptyItem('login'), name: name || urls[0] || username || '未命名', username, password, urls: urls.filter(Boolean), notes, totp, favorite };
}

export function importItems(text: string, format: ImportFormat): Item[] {
  switch (format) {
    case 'bitwarden-csv':
      return records(text).map((r) =>
        r.type === 'note'
          ? { ...emptyItem('note'), name: r.name || '未命名', notes: r.notes ?? '', favorite: r.favorite === '1' }
          : login(r.name ?? '', r.login_username ?? '', r.login_password ?? '', (r.login_uri ?? '').split(','), r.notes ?? '', r.login_totp ?? '', r.favorite === '1'),
      );
    case 'chrome-csv':
      return records(text).map((r) => login(r.name ?? '', r.username ?? '', r.password ?? '', [r.url ?? ''], r.note ?? ''));
    case '1password-csv':
      return records(text).map((r) =>
        login(r.title ?? '', r.username ?? '', r.password ?? '', [r.url ?? r.website ?? ''], r.notes ?? r.notesplain ?? '', r['one-time password'] ?? r.otpauth ?? ''),
      );
    case 'vpass-csv':
      return records(text)
        .map((r) => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, unescapeFormula(v)])) as Record<string, string>)
        .map((r) => ({
        ...emptyItem(r.type === 'note' ? 'note' : 'login'),
        name: r.name ?? '',
        username: r.username ?? '',
        password: r.password ?? '',
        urls: (r.urls ?? '').split(' ').filter(Boolean),
        totp: r.totp ?? '',
        notes: r.notes ?? '',
        favorite: r.favorite === 'true',
      }));
    case 'bitwarden-json': {
      const j = JSON.parse(text) as { encrypted?: boolean; items?: Record<string, unknown>[] };
      if (j.encrypted) throw new Error('bitwarden_encrypted'); // decisions D-21
      return (j.items ?? []).map((it) => {
        const l = (it.login ?? {}) as { username?: string; password?: string; totp?: string; uris?: { uri?: string }[] };
        const fields = Array.isArray(it.fields)
          ? (it.fields as { name?: string; value?: string; type?: number }[]).map((f) => ({ label: f.name ?? '', value: f.value ?? '', hidden: f.type === 1 }))
          : [];
        if (it.type === 2) return { ...emptyItem('note'), name: String(it.name ?? '未命名'), notes: String(it.notes ?? ''), fields, favorite: it.favorite === true };
        return {
          ...login(String(it.name ?? ''), l.username ?? '', l.password ?? '', (l.uris ?? []).map((u) => u.uri ?? ''), String(it.notes ?? ''), l.totp ?? '', it.favorite === true),
          fields,
        };
      });
    }
  }
}

export function exportCsv(items: Item[]): string {
  const rows = [['type', 'name', 'username', 'password', 'urls', 'totp', 'notes', 'favorite']];
  for (const i of items) {
    if (i.type === 'contact') continue;
    rows.push([i.type, i.name, i.username, i.password, i.urls.join(' '), i.totp, i.notes, String(i.favorite)]);
  }
  return toCsv(rows);
}
