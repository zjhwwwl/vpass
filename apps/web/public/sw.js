// VPass service worker. Caches only this build's versioned static assets (from asset-manifest.json)
// plus this build's index.html as an offline fallback. Never touches /api.
const VERSION = '__BUILD_VERSION__';
const CACHE = `vpass-${VERSION}`;

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const res = await fetch('/asset-manifest.json', { cache: 'no-store' });
      const manifest = await res.json();
      const cache = await caches.open(CACHE);
      await cache.addAll(['/', ...manifest.files.map((f) => '/' + f.path)]);
    })(),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      for (const key of await caches.keys()) if (key !== CACHE) await caches.delete(key);
      await self.clients.claim();
    })(),
  );
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin || url.pathname.startsWith('/api/')) return;
  if (event.request.mode === 'navigate') {
    // Network first; the cached index.html of this exact build only when offline.
    event.respondWith(fetch(event.request).catch(() => caches.match('/', { cacheName: CACHE })));
    return;
  }
  if (url.pathname.startsWith('/assets/')) {
    event.respondWith(caches.match(event.request, { cacheName: CACHE }).then((hit) => hit || fetch(event.request)));
  }
});
