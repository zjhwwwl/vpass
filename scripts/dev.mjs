// Local development: build the frontend once, then rebuild on change while `wrangler dev` serves
// the Worker + static assets + local D1 on http://localhost:8787 (same origin, real CSP).
import { spawn, spawnSync } from 'node:child_process';

const run = (cmd, args, opts = {}) => spawn(cmd, args, { stdio: 'inherit', shell: true, ...opts });

spawnSync('pnpm', ['--filter', '@vpass/web', 'build'], { stdio: 'inherit', shell: true });
spawnSync('pnpm', ['--filter', '@vpass/api', 'exec', 'wrangler', 'd1', 'migrations', 'apply', 'DB', '--local'], { stdio: 'inherit', shell: true });
const children = [
  run('pnpm', ['--filter', '@vpass/web', 'exec', 'vite', 'build', '--watch']),
  run('pnpm', ['--filter', '@vpass/api', 'exec', 'wrangler', 'dev', '--port', '8787', '--ip', '127.0.0.1']),
];
const stop = () => children.forEach((c) => c.kill());
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
