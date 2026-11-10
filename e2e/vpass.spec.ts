import { expect, test, type Browser, type Page } from '@playwright/test';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';

const root = join(import.meta.dirname, '..');
const invites: string[] = JSON.parse(readFileSync(join(root, 'e2e', '.invites.json'), 'utf8'));
// Fixed per account: Playwright restarts the worker after a failure, so a module counter would reuse codes.
const INVITE_INDEX: Record<string, number> = { 'sentinel@example.com': 0, 'lock@example.com': 1, 'owner@example.com': 2, 'bob@example.com': 3 };

/** Full dump of every local D1 SQLite file (the "stolen database"). */
function dumpD1(): string {
  const dir = join(root, 'e2e', '.state', 'v3', 'd1');
  const walk = (d: string): string[] => readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : [join(d, f)]));
  const out: string[] = [];
  for (const file of walk(dir).filter((f) => f.endsWith('.sqlite'))) {
    const db = new DatabaseSync(file, { readOnly: true });
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as { name: string }[];
    for (const t of tables) out.push(t.name, JSON.stringify(db.prepare(`SELECT * FROM "${t.name}"`).all()));
    db.close();
  }
  return out.join(String.fromCharCode(10));
}

const SENTINEL = 'SENTINEL-明文-7f3a';
const PASSWORD = 'violet-harbor-quantum-maple-71';

interface Account {
  email: string;
  secretKey: string;
  recoveryCode: string;
}

/** Captures every request body + URL and every /api response body the page sees. */
function wiretap(page: Page): string[] {
  const seen: string[] = [];
  page.on('request', (r) => seen.push(`${r.method()} ${r.url()}\n${r.postData() ?? ''}`));
  page.on('response', async (r) => {
    if (r.url().includes('/api/')) seen.push(await r.text().catch(() => ''));
  });
  return seen;
}

async function register(page: Page, email: string): Promise<Account> {
  await page.goto('/');
  await page.getByRole('tab', { name: '注册' }).click();
  await page.getByLabel('邀请码').fill(invites[INVITE_INDEX[email]!]!);
  await page.getByLabel('邮箱').fill(email);
  await page.getByLabel('主密码', { exact: true }).fill(PASSWORD);
  await page.getByLabel('再输入一次').fill(PASSWORD);
  await page.getByRole('button', { name: '下一步：生成应急卡' }).click();
  await expect(page.getByText('VPass 应急卡').first()).toBeVisible({ timeout: 30_000 });
  const dd = await page.locator('.kit-card dd').allTextContents();
  const [, , secretKey, recoveryCode] = dd as [string, string, string, string];
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: '下载文本' }).click();
  await download;
  const label = await page.getByText(/请输入恢复码的第 \d 组/).textContent();
  const group = Number(/第 (\d) 组/.exec(label!)![1]) - 1;
  await page.getByLabel(/请输入恢复码的第/).fill(recoveryCode.split('-')[group]!);
  await page.getByRole('button', { name: '完成注册' }).click();
  await expect(page.getByRole('button', { name: /个人保管库/ })).toBeVisible({ timeout: 30_000 });
  return { email, secretKey, recoveryCode };
}

async function newLogin(page: Page, name: string, fields: { username?: string; password?: string; url?: string; notes?: string }) {
  await page.locator('select.new-select').selectOption('login');
  await page.getByLabel('名称').fill(name);
  if (fields.username) await page.getByLabel('用户名').fill(fields.username);
  if (fields.password) await page.getByLabel('密码', { exact: true }).fill(fields.password);
  if (fields.url) await page.getByLabel('网址').fill(fields.url);
  if (fields.notes) await page.getByLabel('备注').fill(fields.notes);
  await page.getByRole('button', { name: '保存' }).click();
  await expect(page.locator('.item-view h2', { hasText: name })).toBeVisible();
}

async function unlock(page: Page) {
  await page.getByLabel('主密码').fill(PASSWORD);
  await page.getByRole('button', { name: '解锁' }).click();
  await expect(page.getByRole('button', { name: /个人保管库/ })).toBeVisible({ timeout: 30_000 });
}

async function loginNewDevice(browser: Browser, a: Account): Promise<Page> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto('/');
  await page.getByLabel('邮箱').fill(a.email);
  await page.getByLabel('主密码').fill(PASSWORD);
  await page.getByLabel(/Secret Key/).fill(a.secretKey);
  await page.getByRole('button', { name: '登录' }).click();
  await expect(page.getByRole('button', { name: /个人保管库/ })).toBeVisible({ timeout: 30_000 });
  return page;
}

test('the server never sees plaintext (sentinel in password, URL and notes)', async ({ page, browser }) => {
  const seen = wiretap(page);
  const a = await register(page, 'sentinel@example.com');
  await newLogin(page, '哨兵站点', {
    username: 'me@example.com',
    password: SENTINEL,
    url: `https://${SENTINEL.replace(/[^a-z0-9-]/gi, '')}.example/${encodeURIComponent(SENTINEL)}`,
    notes: `备注里也有 ${SENTINEL}`,
  });
  await page.locator('select.new-select').selectOption('note');
  await page.getByLabel('名称').fill(`笔记 ${SENTINEL}`);
  await page.getByLabel('备注').fill(SENTINEL);
  await page.getByRole('button', { name: '保存' }).click();
  await expect(page.locator('.item-view h2', { hasText: '笔记' })).toBeVisible();

  // Reload → unlock → items come back decrypted from the server.
  await page.reload();
  await unlock(page);
  await expect(page.getByText('哨兵站点')).toBeVisible();

  // A second device with the emergency kit sees the same data.
  const other = await loginNewDevice(browser, a);
  const seen2 = wiretap(other);
  await expect(other.getByText('哨兵站点')).toBeVisible();
  await other.getByText('哨兵站点').click();
  await other.getByRole('button', { name: '显示' }).first().click();
  await expect(other.getByText(SENTINEL).first()).toBeVisible();

  // 1) No request or API response ever carried the sentinel.
  const traffic = [...seen, ...seen2].join('\n');
  expect(traffic.length).toBeGreaterThan(1000);
  expect(traffic).not.toContain(SENTINEL);
  expect(traffic).not.toContain(encodeURIComponent(SENTINEL));
  expect(traffic).not.toContain(PASSWORD);
  expect(traffic).not.toContain(a.secretKey);
  expect(traffic).not.toContain(a.recoveryCode);

  // 2) Nothing in browser storage either.
  const storage = await page.evaluate(async () => {
    const out: string[] = [String(localStorage.length), String(sessionStorage.length)];
    const db = await new Promise<IDBDatabase>((res, rej) => {
      const r = indexedDB.open('vpass');
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
    for (const name of Array.from(db.objectStoreNames)) {
      const all = await new Promise<unknown[]>((res) => {
        const r = db.transaction(name).objectStore(name).getAll();
        r.onsuccess = () => res(r.result);
      });
      out.push(JSON.stringify(all));
    }
    return out;
  });
  expect(storage[0]).toBe('0');
  expect(storage[1]).toBe('0');
  const idbDump = storage.slice(2).join('\n');
  expect(idbDump).toContain('wrappedSecretKey');
  expect(idbDump).not.toContain(SENTINEL);
  expect(idbDump).not.toContain(a.secretKey);

  // 3) A full D1 export contains no sentinel (nor the URL host, nor the item titles).
  const dump = dumpD1();
  expect(dump).toContain('sentinel@example.com'); // sanity: we really dumped the right DB
  expect(dump).toContain('xc20p');
  for (const s of [SENTINEL, encodeURIComponent(SENTINEL), '哨兵站点', 'SENTINEL', PASSWORD, a.secretKey, a.recoveryCode]) expect(dump).not.toContain(s);
});

test('lock, wrong Secret Key is caught locally, auto-lock shortcut', async ({ page, browser }) => {
  const a = await register(page, 'lock@example.com');
  await page.keyboard.press('Alt+l');
  await expect(page.getByRole('button', { name: '解锁' })).toBeVisible();
  await page.getByLabel('主密码').fill('wrong password');
  await page.getByRole('button', { name: '解锁' }).click();
  await expect(page.getByText(/解密失败/)).toBeVisible({ timeout: 30_000 });
  await unlock(page);

  // New device with a one-character typo in the Secret Key: rejected before any login request.
  const ctx = await browser.newContext();
  const p2 = await ctx.newPage();
  const loginCalls: string[] = [];
  p2.on('request', (r) => r.url().includes('/api/auth/login') && loginCalls.push(r.url()));
  await p2.goto('/');
  await p2.getByLabel('邮箱').fill(a.email);
  await p2.getByLabel('主密码').fill(PASSWORD);
  const typo = a.secretKey.slice(0, -1) + (a.secretKey.endsWith('0') ? '1' : '0');
  await p2.getByLabel(/Secret Key/).fill(typo);
  await expect(p2.getByText(/Secret Key 校验失败|格式不对/)).toBeVisible();
  await p2.getByRole('button', { name: '登录' }).click();
  await p2.waitForTimeout(500);
  expect(loginCalls).toEqual([]);
});

test('sharing: verify fingerprint, add, demote, remove with key rotation', async ({ page, browser }) => {
  const owner = await register(page, 'owner@example.com');
  const ctxB = await browser.newContext();
  const pb = await ctxB.newPage();
  const bob = await register(pb, 'bob@example.com');
  void owner;
  void bob;

  // Bob's own fingerprint (what he would read out over a voice call).
  await pb.getByRole('button', { name: '设置' }).click();
  const bobFp = (await pb.locator('.fingerprint').first().textContent())!.trim();
  await pb.keyboard.press('Escape');

  // Owner creates a shared vault with one item.
  await page.getByRole('button', { name: '+ 新建共享库' }).click();
  await page.getByLabel(/名称/).fill('家庭');
  await page.getByRole('button', { name: '创建' }).click();
  await page.getByRole('button', { name: /家庭/ }).click();
  await newLogin(page, '家里 Wi-Fi', { password: 'wifi-secret-123' });

  // Add Bob: the fingerprint shown must equal the one Bob sees.
  await page.getByRole('button', { name: '成员与共享' }).click();
  await page.getByRole('button', { name: '添加成员' }).click();
  await page.getByLabel('对方邮箱').fill('bob@example.com');
  await page.getByRole('button', { name: '查找' }).click();
  await expect(page.locator('.fingerprint.big')).toHaveText(bobFp);
  await page.locator('.add-member select').selectOption('editor');
  await page.getByRole('button', { name: /已核验并添加/ }).click();
  await expect(page.locator('table.members')).toContainText('bob@example.com');
  await page.keyboard.press('Escape');

  // Bob sees the vault and the item, and can edit.
  await pb.reload();
  await unlock(pb);
  await pb.getByRole('button', { name: /家庭/ }).click();
  await expect(pb.getByText('家里 Wi-Fi')).toBeVisible();
  await expect(pb.locator('select.new-select')).toBeVisible();

  // Demote to viewer.
  await page.getByRole('button', { name: '成员与共享' }).click();
  await page.locator('table.members tr', { hasText: 'bob@example.com' }).locator('select').selectOption('viewer');
  await expect(page.locator('table.members tr', { hasText: 'bob@example.com' }).locator('select')).toHaveValue('viewer');
  await pb.reload();
  await unlock(pb);
  await pb.getByRole('button', { name: /家庭/ }).click();
  await expect(pb.getByText('家里 Wi-Fi')).toBeVisible();
  await expect(pb.locator('select.new-select')).toHaveCount(0);

  // Remove Bob → key rotation; Bob loses the vault.
  page.once('dialog', (d) => void d.accept());
  await page.locator('table.members tr', { hasText: 'bob@example.com' }).getByRole('button', { name: '移除' }).click();
  await expect(page.locator('table.members')).not.toContainText('bob@example.com', { timeout: 30_000 });
  await page.keyboard.press('Escape');
  await expect(page.locator('.li-title', { hasText: '家里 Wi-Fi' })).toBeVisible();
  await pb.reload();
  await unlock(pb);
  await expect(pb.getByRole('button', { name: /家庭/ })).toHaveCount(0);
});

test('security headers are present on the page and assets', async ({ request }) => {
  for (const path of ['/', '/manifest.webmanifest', '/api/auth/me']) {
    const r = await request.get(path);
    const h = r.headers();
    expect(h['content-security-policy']).toContain("require-trusted-types-for 'script'");
    expect(h['strict-transport-security']).toContain('max-age=63072000');
    expect(h['x-content-type-options']).toBe('nosniff');
    expect(h['referrer-policy']).toBe('no-referrer');
    expect(h['cross-origin-opener-policy']).toBe('same-origin');
    expect(h['permissions-policy']).toContain('camera=()');
  }
});
