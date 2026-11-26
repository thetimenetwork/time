self.addEventListener('push', (event) => {
  event.waitUntil(
    self.registration.showNotification('Time Chat', {
      body: 'Open Time Chat to check for new messages.',
      tag: 'time-chat',
      icon: '/icon-192.png',
    })
  );
});
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    (async () => {
      const pages = await self.clients.matchAll({
        type: 'window',
        includeUncontrolled: true,
      });
      const page = pages.find(
        (candidate) => new URL(candidate.url).origin === self.location.origin
      );
      if (page) return page.focus();
      return self.clients.openWindow('/');
    })()
  );
});
