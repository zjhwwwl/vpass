import { describe, expect, it } from 'vitest';
import { detectFormat, exportCsv, importItems, parseCsv, toCsv } from '../src/lib/csv.js';
import { emptyItem, normalizeItem, safeHttpUrl, withPasswordHistory } from '../src/lib/item.js';

describe('csv', () => {
  it('parses quotes, commas, newlines and BOM', () => {
    expect(parseCsv('\uFEFFa,b\r\n"x, y","he said ""hi""\nok"\n')).toEqual([
      ['a', 'b'],
      ['x, y', 'he said "hi"\nok'],
    ]);
    expect(parseCsv(toCsv([['=cmd', 'a"b']]))).toEqual([["'=cmd", 'a"b']]);
    for (const evil of ['=HYPERLINK("http://x")', '+1', '-1+1', '@SUM(1)', String.fromCharCode(9) + 'x']) expect(toCsv([[evil]]).replace(/^"/, '')).toMatch(/^'/);
  });

  it('imports Chrome, Bitwarden CSV/JSON and 1Password', () => {
    const chrome = 'name,url,username,password,note\nGitHub,https://github.com/login,me,pw1,hi\n';
    expect(detectFormat(chrome)).toBe('chrome-csv');
    expect(importItems(chrome, 'chrome-csv')[0]).toMatchObject({ name: 'GitHub', username: 'me', password: 'pw1', urls: ['https://github.com/login'], notes: 'hi' });

    const bw = 'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,1,login,Mail,,,0,https://mail.example,u,p,JBSWY3DPEHPK3PXP\n,,note,Secret,body,,0,,,,\n';
    expect(detectFormat(bw)).toBe('bitwarden-csv');
    const items = importItems(bw, 'bitwarden-csv');
    expect(items[0]).toMatchObject({ type: 'login', favorite: true, totp: 'JBSWY3DPEHPK3PXP' });
    expect(items[1]).toMatchObject({ type: 'note', notes: 'body' });

    const op = 'Title,Url,Username,Password,Notes\nBank,https://bank.example,acc,pw,\n';
    expect(detectFormat(op)).toBe('1password-csv');
    expect(importItems(op, '1password-csv')[0]).toMatchObject({ name: 'Bank', urls: ['https://bank.example'] });

    const json = JSON.stringify({ encrypted: false, items: [{ type: 1, name: 'A', login: { username: 'u', password: 'p', uris: [{ uri: 'https://a.example' }] }, fields: [{ name: 'pin', value: '1', type: 1 }] }] });
    expect(importItems(json, 'bitwarden-json')[0]).toMatchObject({ name: 'A', fields: [{ label: 'pin', value: '1', hidden: true }] });
    expect(() => importItems(JSON.stringify({ encrypted: true }), 'bitwarden-json')).toThrow('bitwarden_encrypted');
  });

  it('round-trips its own CSV export and skips contacts', () => {
    const a = { ...emptyItem('login'), name: 'X', username: 'u', password: '=p,"q"', urls: ['https://x.example'] };
    const csv = exportCsv([a, { ...emptyItem('contact'), name: 'friend' }]);
    expect(csv).not.toContain('friend');
    expect(importItems(csv, detectFormat(csv)!)[0]).toMatchObject({ name: 'X', password: '=p,"q"', urls: ['https://x.example'] });
  });
});

describe('items', () => {
  it('only http(s) urls become links', () => {
    expect(safeHttpUrl('example.com')).toBe('https://example.com/');
    expect(safeHttpUrl('http://a.example/x')).toBe('http://a.example/x');
    expect(safeHttpUrl('javascript:alert(1)')).toBeNull();
    expect(safeHttpUrl('data:text/html,hi')).toBeNull();
    expect(safeHttpUrl('')).toBeNull();
  });

  it('normalizes foreign shapes and records password history', () => {
    expect(normalizeItem({ type: 'evil', name: 5, urls: ['a', 1] })).toMatchObject({ type: 'login', name: '', urls: ['a'] });
    const prev = { ...emptyItem(), password: 'old' };
    const next = withPasswordHistory(prev, { ...prev, password: 'new' });
    expect(next.passwordHistory[0]!.value).toBe('old');
    expect(withPasswordHistory(prev, prev).passwordHistory).toHaveLength(0);
  });
});
