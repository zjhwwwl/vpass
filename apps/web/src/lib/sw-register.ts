import { scriptUrl } from './tt.js';

const listeners = new Set<() => void>();
let updateReady = false;

export function onUpdateReady(fn: () => void): () => void {
  listeners.add(fn);
  if (updateReady) fn();
  return () => listeners.delete(fn);
}

/** Service Worker caches only versioned static assets, never /api. A new version prompts a refresh. */
export function registerServiceWorker(): void {
  if (!('serviceWorker' in navigator) || import.meta.env.DEV) return;
  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register(scriptUrl('/sw.js'), { scope: '/' })
      .then((reg) => {
        const flag = () => {
          updateReady = true;
          for (const l of listeners) l();
        };
        if (reg.waiting && navigator.serviceWorker.controller) flag();
        reg.addEventListener('updatefound', () => {
          const w = reg.installing;
          w?.addEventListener('statechange', () => {
            if (w.state === 'installed' && navigator.serviceWorker.controller) flag();
          });
        });
        setInterval(() => void reg.update(), 60 * 60 * 1000);
      })
      .catch(() => undefined);
  });
}

export async function applyUpdate(): Promise<void> {
  const reg = await navigator.serviceWorker.getRegistration();
  reg?.waiting?.postMessage({ type: 'SKIP_WAITING' });
  navigator.serviceWorker.addEventListener('controllerchange', () => location.reload(), { once: true });
}
