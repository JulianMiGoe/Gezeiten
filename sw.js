/* Gezeiten — Service Worker: empfängt Push-Nachrichten und zeigt sie an */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

self.addEventListener('push', event => {
  let msg = { title: 'Gezeiten', body: 'Es gibt etwas Neues.' };
  try { if (event.data) msg = Object.assign(msg, event.data.json()); } catch (e) {}
  event.waitUntil(self.registration.showNotification(msg.title, {
    body: msg.body,
    icon: 'icon-192.png',
    badge: 'icon-badge.png',
    tag: msg.tag || 'gezeiten',
    renotify: true,
    data: { tab: msg.tab || '' }
  }));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const tab = (event.notification.data && event.notification.data.tab) || '';
  event.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const w of wins) {
      if (w.url.startsWith(self.registration.scope)) {
        await w.focus();
        if (tab) w.postMessage({ type: 'open-tab', tab });
        return;
      }
    }
    await self.clients.openWindow(self.registration.scope + (tab ? '#tab=' + tab : ''));
  })());
});
