// Trusted Types: the CSP has `require-trusted-types-for 'script'`, so the only script URLs this app may
// create (Web Worker, Service Worker) go through this one policy, which accepts same-origin paths only.

interface TrustedTypePolicyLike {
  createScriptURL(input: string): unknown;
}
interface TrustedTypesLike {
  createPolicy(name: string, rules: { createScriptURL(input: string): string }): TrustedTypePolicyLike;
}

let policy: TrustedTypePolicyLike | null = null;

function getPolicy(): TrustedTypePolicyLike | null {
  const tt = (globalThis as { trustedTypes?: TrustedTypesLike }).trustedTypes;
  if (!tt) return null;
  policy ??= tt.createPolicy('vpass', {
    createScriptURL(input: string) {
      const u = new URL(input, location.origin);
      if (u.origin !== location.origin) throw new TypeError('blocked script url');
      return u.href;
    },
  });
  return policy;
}

/** Returns a TrustedScriptURL (or the plain string where Trusted Types are unsupported). */
export function scriptUrl(path: string): string {
  const p = getPolicy();
  return (p ? p.createScriptURL(path) : new URL(path, location.origin).href) as string;
}
