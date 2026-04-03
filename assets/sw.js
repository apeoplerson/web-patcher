// Service Worker for OWTK Patcher PWA
//
// Strategy: network-first with cache fallback for ALL requests.
//
// Because Trunk builds use static file names (filehash = false) and
// embeds SRI integrity hashes in index.html, we MUST fetch assets
// from the network to keep them in sync with the HTML. Serving stale
// cached JS/WASM alongside fresh HTML causes SRI hash mismatches and
// loading failures. The cache exists purely as an offline fallback.

const CACHE_NAME = "owtk-patcher-v1";

const PRECACHE_URLS = [
  "./",
  "./index.html",
  "./owtk_patcher.js",
  "./owtk_patcher_bg.wasm",
  "./notifications.json",
];

// ── Install ─────────────────────────────────────────────────────────
self.addEventListener("install", (e) => {
  e.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE_NAME);
      await cache.addAll(PRECACHE_URLS);
      await self.skipWaiting();
    })(),
  );
});

// ── Activate ────────────────────────────────────────────────────────
// Purge old caches and claim clients immediately.
self.addEventListener("activate", (e) => {
  e.waitUntil(
    (async () => {
      const names = await caches.keys();
      await Promise.all(
        names.map((name) => {
          if (name !== CACHE_NAME) {
            return caches.delete(name);
          }
        }),
      );
      await self.clients.claim();
    })(),
  );
});

// ── Fetch ───────────────────────────────────────────────────────────
// Network-first for everything. When online, always fetch from the
// network so HTML and its assets stay in sync (no SRI mismatches).
// Cache the successful response for offline use.
self.addEventListener("fetch", (e) => {
  if (e.request.method !== "GET") {
    return;
  }

  e.respondWith(
    (async () => {
      try {
        const response = await fetch(e.request);
        if (response && response.status === 200 && response.type === "basic") {
          const cache = await caches.open(CACHE_NAME);
          cache.put(e.request, response.clone());
        }
        return response;
      } catch {
        return caches.match(e.request);
      }
    })(),
  );
});
