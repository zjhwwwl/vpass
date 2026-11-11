import { defineConfig, devices } from '@playwright/test';

const PORT = 8788;
// Test-only values (same as the Worker integration tests). Passed explicitly so e2e works without a local .dev.vars, e.g. in CI.
const TEST_VARS = [
  'AUTH_PEPPER:dGVzdC1wZXBwZXItdGVzdC1wZXBwZXItdGVzdC1wZXBwZXI=',
  'TOTP_ENC_KEY:dGVzdC10b3RwLWtleS10ZXN0LXRvdHAta2V5LXRlc3QtdG8=',
  'ADMIN_USER_IDS:00000000-0000-4000-8000-000000000001',
]
  .map((v) => `--var ${v}`)
  .join(' ');

export default defineConfig({
  testDir: './e2e',
  timeout: 120_000,
  fullyParallel: false,
  workers: 1,
  reporter: [['list'], ['html', { open: 'never' }]],
  globalSetup: './e2e/global-setup.ts',
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: 'retain-on-failure',
    ...devices['Desktop Chrome'],
    permissions: ['clipboard-read', 'clipboard-write'],
  },
  webServer: {
    command: `pnpm --filter @vpass/api exec wrangler dev --port ${PORT} --ip 127.0.0.1 --persist-to ../../e2e/.state ${TEST_VARS}`,
    url: `http://localhost:${PORT}/`,
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
