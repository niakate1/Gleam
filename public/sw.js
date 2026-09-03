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

// ── CETTE VERSION DOIT CHANGER À CHAQUE DÉPLOIEMENT ──────────────────────
// Elle nomme le cache. Si elle ne bouge pas, le navigateur continue de servir
// l'ancienne coquille indéfiniment — vos corrections ne parviendraient jamais
// aux utilisateurs déjà venus.
//
// La date suffit : une par jour de déploiement.
const VERSION = 'gleam-sw-2026-09-04-lucide';

// L'installation est désormais gérée plus bas, avec le précache de la
// coquille : deux gestionnaires `install` s'exécuteraient tous les deux, et le
// second `skipWaiting` masquerait l'échec du premier.

self.addEventListener('activate', function (event) {
  // Et prend le contrôle des pages déjà chargées, sans exiger un rechargement.
  event.waitUntil(
    // Les caches des versions précédentes n'ont plus lieu d'être : sans ce
    // ménage, ils s'accumuleraient à chaque déploiement.
    caches.keys().then(function (noms) {
      return Promise.all(noms
        .filter(function (n) { return n.startsWith('gleam-coquille-') && n !== CACHE_COQUILLE; })
        .map(function (n) { return caches.delete(n); }));
    }).then(function () { return self.clients.claim(); })
  );
  console.log('[Gleam] Service worker actif —', VERSION);
});

// Permet à la page de forcer l'activation d'une version en attente, si besoin :
//   navigator.serviceWorker.controller.postMessage({ type: 'PASSER_EN_ACTIF' })
self.addEventListener('message', function (event) {
  if (event.data && event.data.type === 'PASSER_EN_ACTIF') self.skipWaiting();
});

// ═══════════════════════════════════════════════════════════════════════════
// LA MISE EN CACHE — CE QUI REND UNE APPLICATION INSTANTANÉE
//
// Jusqu'ici ce service worker ne servait qu'aux notifications. Aucun
// événement `fetch`, aucun cache : à chaque lancement, le navigateur
// retéléchargeait 224 Ko et réinterprétait 563 Ko de JavaScript.
//
// C'est exactement la différence avec les applications qui s'affichent dès
// que leur icône a fini de charger. Elles ne retéléchargent rien : elles
// servent depuis le disque, puis vérifient en arrière-plan.
//
// LA STRATÉGIE : SERVIR D'ABORD, METTRE À JOUR ENSUITE
//
// À l'ouverture, la version en cache s'affiche IMMÉDIATEMENT. En parallèle,
// le réseau est interrogé et le cache mis à jour pour la fois suivante.
//
// Le prix à payer est honnête : après un déploiement, l'utilisateur voit
// encore l'ancienne version UNE fois. Au lancement suivant, il a la nouvelle.
//
// CE QUI N'EST JAMAIS MIS EN CACHE
//
// Les appels à l'API. Un devis, un paiement, un litige doivent toujours
// venir du serveur — servir un solde périmé serait pire que lent.
// ═══════════════════════════════════════════════════════════════════════════
const CACHE_COQUILLE = 'gleam-coquille-' + VERSION;

// Le strict nécessaire pour afficher quelque chose. Les icônes et la police
// arrivent ensuite, à l'usage.
const COQUILLE = [
  './',
  './index.html',
  './icon-192.png',
  './gleam-logo.svg'
];

self.addEventListener('install', function (event) {
  event.waitUntil(
    caches.open(CACHE_COQUILLE)
      .then(function (cache) { return cache.addAll(COQUILLE); })
      // Un fichier absent ne doit pas empêcher l'installation : mieux vaut un
      // cache partiel que pas de service worker du tout.
      .catch(function (e) { console.warn('[Gleam] Précache partiel :', e); })
  );
  self.skipWaiting();
});

self.addEventListener('fetch', function (event) {
  const requete = event.request;

  // Seules les lectures sont mises en cache. Un POST doit toujours partir.
  if (requete.method !== 'GET') return;

  const url = new URL(requete.url);

  // L'API, jamais. Ni les autres origines : tuiles, polices, Stripe ont
  // leur propre cache navigateur, et les intercepter compliquerait sans gain.
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/')) return;

  event.respondWith(
    caches.match(requete).then(function (enCache) {
      const surLeReseau = fetch(requete).then(function (reponse) {
        // On ne met en cache que ce qui a réussi. Une page d'erreur mise en
        // cache resservirait l'erreur indéfiniment.
        if (reponse && reponse.status === 200 && reponse.type === 'basic') {
          const copie = reponse.clone();
          caches.open(CACHE_COQUILLE).then(function (cache) {
            cache.put(requete, copie);
          });
        }
        return reponse;
      }).catch(function () {
        // Hors ligne : la version en cache, ou rien.
        return enCache;
      });

      // Le cache d'abord — c'est ce qui rend l'affichage immédiat.
      return enCache || surLeReseau;
    })
  );
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
