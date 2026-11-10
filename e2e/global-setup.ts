import { execSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const root = join(import.meta.dirname, '..');

export const wrangler = (args: string) =>
  execSync(`pnpm --filter @vpass/api exec wrangler ${args} --persist-to ../../e2e/.state`, { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] }).toString();

export default function globalSetup(): void {
  if (!existsSync(join(root, 'apps/web/dist/index.html'))) execSync('pnpm build', { cwd: root, stdio: 'inherit' });
  // Playwright starts webServer before globalSetup, so the state dir is already in use: reset by SQL.
  wrangler('d1 migrations apply vpass --local');
  wrangler(
    'd1 execute vpass --local --command "DELETE FROM items; DELETE FROM vault_members; DELETE FROM vaults; DELETE FROM sessions; DELETE FROM invites; DELETE FROM audit_log; DELETE FROM users;"',
  );
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const codes = Array.from({ length: 6 }, () => 'VPI-' + [...randomBytes(16)].map((b) => alphabet[b & 31]).join('').match(/.{4}/g)!.join('-'));
  const exp = Date.now() + 3600_000;
  const values = codes.map((c) => `('${createHash('sha256').update(c.replace(/-/g, '')).digest('hex')}', NULL, NULL, ${exp})`).join(',');
  wrangler(`d1 execute vpass --local --command "INSERT INTO invites (code_hash, created_by, used_by, expires_at) VALUES ${values};"`);
  writeFileSync(join(root, 'e2e', '.invites.json'), JSON.stringify(codes));
}
