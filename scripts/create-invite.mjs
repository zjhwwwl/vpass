// Create an invite code (e.g. the very first one, for the admin) directly in D1.
// Usage: node scripts/create-invite.mjs --local | --remote
import { createHash, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';

const target = process.argv.includes('--remote') ? '--remote' : '--local';
const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const chars = [...randomBytes(16)].map((b) => alphabet[b & 31]).join('');
const code = `VPI-${chars.slice(0, 4)}-${chars.slice(4, 8)}-${chars.slice(8, 12)}-${chars.slice(12, 16)}`;
const hash = createHash('sha256').update(code.replace(/-/g, '')).digest('hex');
const expires = Date.now() + 7 * 24 * 3600 * 1000;
const sql = `INSERT INTO invites (code_hash, created_by, used_by, expires_at) VALUES ('${hash}', NULL, NULL, ${expires});`;
const r = spawnSync('pnpm', ['--filter', '@vpass/api', 'exec', 'wrangler', 'd1', 'execute', 'vpass', target, '--command', `"${sql}"`], {
  stdio: ['ignore', 'ignore', 'inherit'],
  shell: true,
});
if (r.status !== 0) process.exit(r.status ?? 1);
console.log(`Invite code (shown once, valid 7 days): ${code}`);
