// sw.js — Service Worker Gleam, dédié aux notifications push.
//
// Doit être servi à la RACINE du site (même dossier que index.html), avec le
// type MIME text/javascript. Un service worker servi en text/html — ce qui
// arrive quand l'hébergeur redirige les adresses inconnues vers index.html —
// est refusé par le navigateur, sans message explicite sur iOS.
//
// ─────────────────────────────────────────────────────────────────────────────
// CE QUI CHANGE PAR RAPPORT À LA VERSION PRÉCÉDENTE
//
// 1. Les icônes utilisaient une adresse absolue vers gleam-app.fr. Le service
//    worker n'affichait donc aucune icône lorsqu'il tournait sur une autre
//    origine — préproduction Netlify, GitHub Pages, ou test en local. Les
//    chemins sont désormais relatifs à la portée du service worker.
//
// 2. Au clic sur une notification, l'ancienne version remettait bien l'onglet
//    existant au premier plan, mais sans jamais l'amener à l'adresse contenue
//    dans la notification. Cliquer sur « Nouveau devis reçu » ramenait donc
//    l'application au premier plan, sur l'écran où elle était restée. La
//    navigation est maintenant effectuée.
//
// 3. Ajout de install et activate. Sans eux, une nouvelle version du service
//    worker reste en attente jusqu'à la fermeture complète de tous les onglets
//    — ce qui, sur une application installée, peut prendre des jours. Pendant
//    ce temps, vos corrections ne s'appliquent pas.
//
// 4. Un numéro de version permet de vérifier d'un coup d'œil, dans les outils
//    développeur, quelle version est réellement active sur l'appareil.
// ─────────────────────────────────────────────────────────────────────────────

const VERSION = 'gleam-sw-2026-08-03';

self.addEventListener('install', function () {
  // La nouvelle version prend la main immédiatement, sans attendre la fermeture
  // des onglets ouverts.
  self.skipWaiting();
});

self.addEventListener('activate', function (event) {
  // Et prend le contrôle des pages déjà chargées, sans exiger un rechargement.
  event.waitUntil(self.clients.claim());
  console.log('[Gleam] Service worker actif —', VERSION);
});

// Permet à la page de forcer l'activation d'une version en attente, si besoin :
//   navigator.serviceWorker.controller.postMessage({ type: 'PASSER_EN_ACTIF' })
self.addEventListener('message', function (event) {
  if (event.data && event.data.type === 'PASSER_EN_ACTIF') self.skipWaiting();
});

self.addEventListener('push', function (event) {
  var data = {};
  try { data = event.data ? event.data.json() : {}; } catch (e) {}

  var titre = data.title || 'Gleam';
  var options = {
    body: data.body || '',
    // Chemins relatifs à la portée : fonctionne sur n'importe quelle origine.
    icon: './icon-192.png',
    badge: './icon-192.png',
    data: { url: data.url || './' },
    // Regroupe les notifications d'une même prestation au lieu de les empiler,
    // et fait vibrer brièvement l'appareil à la réception.
    tag: data.tag || undefined,
    renotify: !!data.tag,
    vibrate: [80, 40, 80]
  };
  event.waitUntil(self.registration.showNotification(titre, options));
});

self.addEventListener('notificationclick', function (event) {
  event.notification.close();

  var cible = (event.notification.data && event.notification.data.url) || './';
  var urlComplete = new URL(cible, self.location.origin).href;

  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then(function (fenetres) {
        for (var i = 0; i < fenetres.length; i++) {
          var fenetre = fenetres[i];
          if (fenetre.url.indexOf(self.location.origin) !== 0) continue;

          // On remet la fenêtre existante au premier plan ET on l'amène à
          // l'adresse voulue. L'ancienne version se contentait du premier plan :
          // cliquer sur une notification de devis ne menait donc nulle part.
          if ('navigate' in fenetre) {
            return fenetre.navigate(urlComplete).then(function (f) {
              return f && 'focus' in f ? f.focus() : null;
            }).catch(function () {
              // navigate() peut échouer selon le navigateur : on se rabat sur
              // le simple retour au premier plan plutôt que de ne rien faire.
              return 'focus' in fenetre ? fenetre.focus() : null;
            });
          }
          if ('focus' in fenetre) return fenetre.focus();
        }
        if (self.clients.openWindow) return self.clients.openWindow(urlComplete);
      })
  );
});
