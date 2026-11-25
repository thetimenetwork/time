// The wallet's service worker. It does two things and nothing else:
// - when the alert service wakes this browser (deploy/alerts/README.md), it shows one notification with fixed words,
//   "Open your wallet to check your account.". Whatever the push carries is never read or shown: the words are
//   written here, and several pushes are one notification (the same tag);
// - when that notification is tapped, it closes it and brings an open window of the wallet to the front, or opens the
//   wallet at this worker's own scope. It never opens any other address.
// It has NO fetch handler, keeps NO cache and imports NOTHING: it cannot change what the wallet page loads, and it
// cannot be made to load code from anywhere. sw.test.mjs reads this file and holds it to that.
const TITLE = 'Time';
const BODY = 'Open your wallet to check your account.';
const TAG = 'time-account-alert';

self.addEventListener('install', () => { self.skipWaiting(); });
self.addEventListener('activate', (event) => { event.waitUntil(self.clients.claim()); });

self.addEventListener('push', (event) => {
  event.waitUntil(self.registration.showNotification(TITLE, { body: BODY, tag: TAG, renotify: true }));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const scope = self.registration.scope;
  event.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windows) => {
    for (const client of windows) if (typeof client.url === 'string' && client.url.startsWith(scope) && typeof client.focus === 'function') return client.focus();
    return self.clients.openWindow(scope);
  }));
});
