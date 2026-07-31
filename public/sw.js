// sw.js — Service Worker Gleam, dédié aux notifications push.
// Doit être servi à la racine du site (même dossier que index.html) pour pouvoir
// contrôler l'ensemble du site.

self.addEventListener('push', function(event) {
  var data = {};
  try { data = event.data ? event.data.json() : {}; } catch (e) {}
  var titre = data.title || 'Gleam';
  var options = {
    body: data.body || '',
    icon: 'https://gleam-app.fr/icon-192.png',
    badge: 'https://gleam-app.fr/icon-192.png',
    data: { url: data.url || '/' }
  };
  event.waitUntil(self.registration.showNotification(titre, options));
});

self.addEventListener('notificationclick', function(event) {
  event.notification.close();
  var url = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(clientList) {
      // Si l'app est déjà ouverte dans un onglet, on le remet au premier plan plutôt que
      // d'en ouvrir un nouveau — évite de multiplier les onglets à chaque notification.
      for (var i = 0; i < clientList.length; i++) {
        var client = clientList[i];
        if (client.url.indexOf(self.location.origin) === 0 && 'focus' in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) return clients.openWindow(url);
    })
  );
});
