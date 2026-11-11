import path from 'node:path';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(import.meta.dirname, 'migrations'));
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: './wrangler.test.toml' },
        miniflare: {
          bindings: {
            TEST_MIGRATIONS: migrations,
            AUTH_PEPPER: 'dGVzdC1wZXBwZXItdGVzdC1wZXBwZXItdGVzdC1wZXBwZXI=',
            TOTP_ENC_KEY: 'dGVzdC10b3RwLWtleS10ZXN0LXRvdHAta2V5LXRlc3QtdG8=',
            ADMIN_USER_IDS: '00000000-0000-4000-8000-000000000001',
          },
        },
      }),
    ],
    test: {
      setupFiles: ['./test/apply-migrations.ts'],
      testTimeout: 60_000,
    },
  };
});
