declare namespace Cloudflare {
  interface Env extends Omit<import('../src/env.js').Env, never> {
    TEST_MIGRATIONS: import('cloudflare:test').D1Migration[];
  }
  interface GlobalProps {
    mainModule: typeof import('../src/index.js');
  }
}
