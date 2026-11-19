const CACHE = 'cybershield-0.9.3-connected';
const OFFLINE = ['./','./index.html','./app.mjs','./detector.mjs','./styles.css','./ui-refresh.css','./extras.css','./intelligence.mjs','./extras.mjs','./easy-touch.mjs','./easy-touch.css','./online.mjs','./release-policy.mjs','./online.css','./trust-report.mjs','./trust-insights.mjs','./trust-insights.css','./archive-intelligence.mjs','./file-security.mjs','./device-security.mjs','./device-security.css','./manifest.webmanifest','./icons/icon-192.png','./icons/icon-512.png'];
self.addEventListener('install', event => event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(OFFLINE)).then(()=>self.skipWaiting())));
self.addEventListener('activate', event => event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim())));
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET' || new URL(event.request.url).origin !== self.location.origin) return;
  if (new URL(event.request.url).pathname.endsWith('/releases/latest.json') || new URL(event.request.url).pathname.endsWith('/api/updates')) { event.respondWith(fetch(event.request,{cache:'no-store'})); return; }
  if(event.request.mode==='navigate') {
    event.respondWith(fetch(event.request,{cache:'no-store'}).catch(()=>caches.match(event.request)));
    return;
  }
  event.respondWith(caches.match(event.request).then(found => found || fetch(event.request)));
});
