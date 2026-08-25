require('dotenv').config();
// Suivi des erreurs en production (Sentry) — protégé : si la clé DSN est absente ou invalide, le
// serveur démarre quand même normalement, exactement comme pour les autres services optionnels
// (Twilio, web-push) déjà protégés de la même façon plus loin dans ce fichier.
const Sentry = require('@sentry/node');
if (process.env.SENTRY_DSN) {
  try {
    Sentry.init({ dsn: process.env.SENTRY_DSN, environment: process.env.NODE_ENV || 'development' });
    console.log('✅ Suivi des erreurs (Sentry) configuré.');
  } catch (e) {
    console.error('⚠️ Sentry non configuré (erreur ignorée, le serveur démarre quand même):', e.message);
  }
} else {
  console.log('ℹ️ Suivi des erreurs (Sentry) non configuré (SENTRY_DSN absent).');
}
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const webpush = require('web-push');
// Notifications push (technologie Web Push, standard des navigateurs — gratuite, sans service
// tiers payant). Protection renforcée : ce code s'exécute au tout début, avant même que le
// serveur ne démarre — si les clés VAPID sont mal formées (espace superflu copié par erreur,
// mauvaise longueur...), l'appel peut lever une erreur immédiate qui ferait planter tout le
// serveur avant même qu'il ait pu démarrer. Le try/catch garantit que ça n'arrive plus jamais :
// au pire, les notifications restent simplement désactivées, mais le reste de l'application
// (connexion, paiements, tout le reste) continue de fonctionner normalement.
if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
  try {
    webpush.setVapidDetails(
      'mailto:' + (process.env.FROM_EMAIL || 'contact@gleam-app.fr'),
      process.env.VAPID_PUBLIC_KEY.trim(),
      process.env.VAPID_PRIVATE_KEY.trim()
    );
    console.log('✅ Notifications push configurées.');
  } catch (e) {
    console.error('⚠️ Configuration des notifications push échouée (le reste de l\'application fonctionne normalement) :', e.message);
  }
} else {
  console.log('ℹ️ Notifications push non configurées (VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY absents).');
}
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Le secret administrateur ne doit pas dériver du secret utilisateur : avec
// JWT_SECRET + '_admin', toute fuite de JWT_SECRET — capture d'écran du tableau
// de bord, ancien collaborateur — permettait de forger soi-même un jeton
// { admin: true } sans jamais connaître le mot de passe. Définissez
// ADMIN_JWT_SECRET (une longue chaîne aléatoire, sans rapport avec l'autre).
// Sans elle, l'ancien comportement est conservé pour ne rien casser.
// ── PLUS DE REPLI : LE SERVEUR REFUSE DE DÉMARRER ─────────────────────────
// Le repli sur `JWT_SECRET + '_admin'` était une commodité de développement.
// En production, il annulait la séparation qu'il prétendait établir : qui
// connaît JWT_SECRET forge un jeton { admin: true } sans mot de passe.
//
// Un avertissement dans les journaux ne suffit pas — personne ne les lit quand
// tout fonctionne. Le serveur s'arrête, et le problème se voit.
//
// Vérifié le 24 août : ADMIN_JWT_SECRET est bien définie dans Railway.
if (!process.env.ADMIN_JWT_SECRET) {
  console.error('🔴 ADMIN_JWT_SECRET absente. Le serveur ne démarrera pas :');
  console.error('   sans elle, le secret administrateur dériverait du secret');
  console.error('   utilisateur, et toute fuite du second compromettrait le premier.');
  console.error('   Définissez une longue chaîne aléatoire, sans rapport avec JWT_SECRET.');
  process.exit(1);
}
const SECRET_ADMIN = process.env.ADMIN_JWT_SECRET;

// Comparaison à temps constant : `!==` s'arrête au premier caractère différent,
// ce qui laisse fuiter la longueur du préfixe correct par le temps de réponse.
function comparaisonSure(a, b) {
  const ta = Buffer.from(String(a || ''), 'utf8');
  const tb = Buffer.from(String(b || ''), 'utf8');
  if (ta.length !== tb.length) return false;
  return crypto.timingSafeEqual(ta, tb);
}

// Mot de passe admin haché, si vous en définissez un.
// Format attendu pour ADMIN_PASSWORD_HASH : "scrypt$<selHex>$<empreinteHex>"
// Génération :
//   node -e "const c=require('crypto');const s=c.randomBytes(16);const m=process.argv[1];console.log('scrypt$'+s.toString('hex')+'$'+c.scryptSync(m,s,64).toString('hex'))" 'VotreMotDePasse'
function motDePasseAdminValide(saisi) {
  const empreinte = process.env.ADMIN_PASSWORD_HASH;
  if (empreinte) {
    const [algo, selHex, attenduHex] = String(empreinte).split('$');
    if (algo !== 'scrypt' || !selHex || !attenduHex) return false;
    const calcule = crypto.scryptSync(String(saisi || ''), Buffer.from(selHex, 'hex'), 64);
    return comparaisonSure(calcule.toString('hex'), attenduHex);
  }
  if (!process.env.ADMIN_PASSWORD) return false;
  return comparaisonSure(saisi, process.env.ADMIN_PASSWORD);
}
// ── IMPORT IMMUNISÉ À LA DÉPENDANCE CIRCULAIRE ──────────────────────────────
// Node avertissait : « Accessing non-existent property 'sendEmail' of module
// exports inside circular dependency ».
//
// La déstructuration `const { sendEmail } = require(...)` fige la valeur AU
// MOMENT DE L'IMPORT. Si email.js n'a pas fini de s'évaluer — parce qu'il
// dépend en retour de server.js —, on capture `undefined` pour toujours. C'est
// ce qui produisait « sendEmail is not a function » à chaque validation.
//
// On garde le MODULE et on lit la fonction à l'appel : à ce moment-là, le
// chargement est terminé depuis longtemps.
const moduleEmail = require('./email');

function sendEmail(...args) {
  if (typeof moduleEmail.sendEmail !== 'function') {
    // Un courriel qui ne part pas ne doit jamais interrompre un paiement ou
    // une validation. On le signale et on continue.
    console.error('⚠️ sendEmail indisponible — courriel non envoyé :', args[0]);
    return Promise.resolve();
  }
  return moduleEmail.sendEmail(...args);
}

// Envoie une notification push à toutes les inscriptions actives d'un utilisateur (un par
// appareil/navigateur) — nettoie automatiquement les abonnements devenus invalides (l'utilisateur
// a désinstallé l'app, changé de navigateur, etc.), sans jamais faire planter l'appel qui déclenche
// la notification si l'envoi échoue (le mail reste toujours envoyé en parallèle, indépendamment).
async function envoyerNotificationPush(userId, { titre, corps, url }) {
  if (!process.env.VAPID_PUBLIC_KEY || !process.env.VAPID_PRIVATE_KEY) return; // notifications désactivées, pas de clés configurées
  try {
    const { data: abonnements } = await supabase.from('push_subscriptions').select('*').eq('user_id', userId);
    if (!abonnements || !abonnements.length) return;
    const payload = JSON.stringify({ title: titre, body: corps, url: url || '/' });
    await Promise.all(abonnements.map(async (a) => {
      try {
        await webpush.sendNotification({ endpoint: a.endpoint, keys: { p256dh: a.keys_p256dh, auth: a.keys_auth } }, payload);
      } catch (e) {
        // 410/404 = l'abonnement n'existe plus côté navigateur (désinstallé, expiré) — on le retire
        if (e.statusCode === 410 || e.statusCode === 404) {
          await supabase.from('push_subscriptions').delete().eq('id', a.id);
        } else {
          console.error('Erreur envoi notification push:', e.message);
        }
      }
    }));
  } catch (e) {
    console.error('Erreur notification push (ignorée):', e.message);
  }
}

const app = express();

// ═══════════════════════════════════════════════════════════════════════════
// LES ERREURS QUE L'ON PEUT SUIVRE
//
// « Erreur serveur. » apparaissait 66 fois, et 54 d'entre elles ne
// journalisaient rien. Un utilisateur écrivait « ça ne marche pas », et il n'y
// avait rien à lire pour comprendre.
//
// Améliorer le message sans journaliser la cause n'aurait servi à rien : on
// aurait écrit joliment qu'on ne sait pas ce qui s'est passé.
//
// Chaque incident reçoit désormais une référence courte. L'utilisateur peut la
// citer, elle se retrouve dans les journaux Railway en une recherche.
// ═══════════════════════════════════════════════════════════════════════════
function referenceIncident() {
  // Six caractères : assez pour être unique à l'échelle d'une journée, assez
  // court pour être recopié au téléphone sans se tromper.
  return Math.random().toString(36).slice(2, 8).toUpperCase();
}

// Journalise la cause réelle et renvoie une réponse utilisable par l'humain
// qui la reçoit. Le détail technique reste côté serveur : « column x does not
// exist » n'aide personne et renseigne un attaquant.
function erreurServeur(res, contexte, e, messageUtilisateur) {
  const ref = referenceIncident();
  console.error('[' + ref + '] ' + contexte + ' —', (e && e.message) || e, (e && e.stack) || '');
  return res.status(500).json({
    error: (messageUtilisateur ||
      "Une erreur est survenue de notre côté. Réessayez dans un instant — " +
      "si cela persiste, contactez-nous en citant la référence ci-dessous.") +
      ' (réf. ' + ref + ')',
    reference: ref
  });
}



// ─────────────────────────────────────────────────────────────────────────────
// PAS D'ETAG, PAS DE CACHE SUR L'API
//
// Express ajoute par défaut un ETag aux réponses JSON. Le navigateur renvoie
// alors If-None-Match, et le serveur répond 304 Not Modified avec un corps vide.
//
// C'est correct pour une ressource statique, désastreux pour une API : côté
// client, fetch() expose un statut 304 dont `response.ok` vaut false. Tout code
// qui teste `r.ok` interprète donc une réponse parfaitement valide comme un
// échec — c'est ce qui déconnectait les utilisateurs au démarrage.
//
// Une réponse d'API dépend de l'utilisateur et de l'instant : elle n'a aucune
// raison d'être mise en cache.
// ─────────────────────────────────────────────────────────────────────────────
app.set('etag', false);
app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  next();
});
app.set('trust proxy', 1);

// Le client "temps réel" de Supabase (basé sur WebSocket) n'est jamais utilisé dans ce projet —
// aucune fonctionnalité de ce type nulle part dans ce fichier. Mais la bibliothèque l'initialise
// quand même en interne dès la création du client, quoi qu'il arrive. Les versions récentes
// exigent donc explicitement un transport WebSocket pour Node < 22 (Railway tourne sur Node 20),
// sans quoi la création du client échoue immédiatement au démarrage — solution officielle
// documentée par Supabase : fournir le paquet "ws" en transport, même sans s'en servir ensuite.
const WebSocketTransport = require('ws');
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  { realtime: { transport: WebSocketTransport }, auth: { persistSession: false } }
);

// ─────────────────────────────────────────────────────────────────────────────
// Client SÉPARÉ, réservé aux appels d'authentification qui ouvrent une session.
//
// Pourquoi : supabase-js mémorise la session renvoyée par signInWithPassword()
// DANS l'instance du client, même avec persistSession à false — l'option
// n'empêche que l'écriture sur disque, pas la mémorisation en mémoire. À partir
// de là, le client envoie le jeton de CET utilisateur en en-tête Authorization
// à la place de la clé de service. PostgREST en déduit le rôle `authenticated`,
// qui ne contourne pas RLS.
//
// Conséquence sur le client partagé : dès la première connexion d'un
// utilisateur, TOUTES les requêtes suivantes du serveur — pour tous les
// utilisateurs — cessaient de s'exécuter en service_role. C'est ce qui a produit
// l'erreur du 2 août, « new row violates row-level security policy for table
// users », sur l'insertion faite juste après signInWithPassword ci-dessous. Et
// c'est pourquoi push_subscriptions, seule table restée en RLS, n'a jamais
// enregistré la moindre ligne.
//
// En isolant cet appel, le client de données reste en service_role en
// permanence, et RLS peut être activé sans rien casser.
// ─────────────────────────────────────────────────────────────────────────────
const supabaseAuth = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  {
    // Le transport WebSocket est obligatoire ici aussi, pour la raison expliquée
    // plus haut : la bibliothèque initialise son client temps réel à la création,
    // qu'on s'en serve ou non, et Node 20 n'a pas de WebSocket natif. Sans cette
    // option, createClient lève une erreur AVANT même le démarrage du serveur.
    realtime: { transport: WebSocketTransport },
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false }
  }
);

// ═══════════════════════════════════════════════════════════════════════════
// LA POLITIQUE DE SÉCURITÉ DU CONTENU
//
// `helmet()` seul posait une CSP par défaut qui aurait bloqué l'application :
// 368 gestionnaires `onclick`, 710 styles en ligne, Stripe, les polices
// Google. Elle était donc… désactivée de fait, faute d'avoir été réglée.
//
// EN MODE RAPPORT D'ABORD
//
// `reportOnly: true` — le navigateur SIGNALE ce qui serait bloqué, sans rien
// bloquer. On observe quelques jours, on corrige ce qui remonte, puis on
// passe en mode réel.
//
// Poser une CSP stricte d'un coup sur une application de cette taille, c'est
// se réveiller avec un écran blanc sans savoir pourquoi.
//
// CE QU'ELLE NE PEUT PAS FAIRE ENCORE
//
// `'unsafe-inline'` reste nécessaire tant que les 368 onclick existent. La CSP
// n'arrête donc pas un script injecté dans un attribut — mais elle bloque déjà
// le plus courant : un script chargé depuis un domaine étranger.
//
// C'est une défense partielle, et c'est mieux qu'aucune.
app.use(helmet({
  contentSecurityPolicy: {
    reportOnly: true,
    directives: {
      defaultSrc: ["'self'"],
      // Stripe pour le paiement ; unpkg pour les icônes Lucide.
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://js.stripe.com', 'https://unpkg.com'],
      // Les 710 styles en ligne imposent unsafe-inline. Les polices Google
      // servent une feuille de style depuis googleapis.
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      // `data:` et `blob:` : les photos sont prévisualisées avant envoi.
      imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
      // L'API, l'adresse gouvernementale, Stripe.
      connectSrc: ["'self'", 'https://gleam-production-9b95.up.railway.app',
                   'https://gleam-app.fr', 'https://api-adresse.data.gouv.fr',
                   'https://data.geopf.fr', 'https://api.stripe.com'],
      // Le formulaire de carte Stripe s'affiche dans un cadre.
      frameSrc: ["'self'", 'https://js.stripe.com', 'https://hooks.stripe.com'],
      // Personne ne doit pouvoir encadrer Gleam dans son propre site.
      frameAncestors: ["'none'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  }
}));
// CORS restreint au(x) domaine(s) réel(s) de Gleam plutôt qu'ouvert à n'importe quelle origine.
//
// Deuxième correction, plus radicale que la première : la version précédente utilisait
// `process.env.CORS_ORIGIN || 'valeurs par défaut'` — si CORS_ORIGIN était déjà défini sur Railway
// (même avec une valeur ancienne, incomplète, ou erronée datant d'avant ce projet), il REMPLAÇAIT
// intégralement les domaines de secours, qui n'étaient alors jamais pris en compte. C'est très
// probablement ce qui a provoqué le blocage persistant, même après la première correction.
//
// Cette fois, les domaines connus de Gleam sont TOUJOURS inclus dans tous les cas, sans aucune
// condition — CORS_ORIGIN, s'il est défini, vient s'AJOUTER à cette liste plutôt que la remplacer.
// Il est donc impossible qu'une valeur oubliée ou incorrecte sur Railway bloque à nouveau la connexion.
const DOMAINES_GLEAM_CONNUS = ['gleam-app.fr', 'niakate1.github.io'];
const hotesAutorises = DOMAINES_GLEAM_CONNUS.concat(
  (process.env.CORS_ORIGIN || '').split(',')
).map(o => o.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/$/, '')).filter(Boolean);
console.log('CORS — hôtes autorisés au démarrage:', hotesAutorises);
const corsOptions = {
  origin: function (origin, callback) {
    // Autorise toujours les requêtes sans origine (apps mobiles Capacitor, curl, Postman, requêtes
    // serveur-à-serveur) — seules les requêtes d'un navigateur avec une origine non reconnue sont refusées.
    if (!origin) return callback(null, true);
    try {
      const hote = new URL(origin).hostname.toLowerCase().replace(/^www\./, '');
      if (hotesAutorises.includes(hote)) return callback(null, true);
    } catch (e) { /* origine malformée, refusée ci-dessous */ }
    console.error('CORS refusé pour origine:', origin, '— autorisées:', hotesAutorises);
    return callback(new Error('Origine non autorisée par CORS.'));
  },
  // ── LE COOKIE DOIT POUVOIR VOYAGER ──────────────────────────────────────
  // Sans `credentials`, le navigateur n'envoie aucun cookie vers une autre
  // origine — et le serveur (Railway) n'est pas sur le même domaine que
  // l'application (Netlify).
  //
  // C'est sans danger ici : la liste d'origines autorisées reste stricte, et
  // `credentials: true` avec `origin: '*'` est de toute façon refusé par les
  // navigateurs.
  credentials: true
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    return res.status(400).send('Webhook Error: ' + e.message);
  }
  if (event.type === 'payment_intent.succeeded') {
    // Filet de sécurité uniquement : si le navigateur du client s'est fermé avant que sa propre
    // confirmation n'ait eu le temps de s'exécuter, ce webhook la déclenche à sa place. La fonction
    // vérifie elle-même que le paiement n'a pas déjà été confirmé, pour ne jamais rien faire deux
    // fois (auparavant, ce webhook écrasait le statut avec une valeur "bloque" orpheline, jamais
    // utilisée ailleurs dans le code — un vrai risque d'écraser silencieusement une confirmation
    // déjà faite normalement par le client).
    try {
      await finaliserConfirmationPaiement(event.data.object.id);
    } catch (e) {
      console.error('Erreur webhook Stripe (finalisation paiement):', e);
    }
  }
  res.json({ received: true });
});

app.use(express.json({ limit: '10mb' }));

// Gestion propre des erreurs de parsing du body (JSON malformé, payload trop volumineux).
// Sans ce middleware, Express renvoie une page d'erreur HTML par défaut que le frontend
// ne peut pas parser en JSON, ce qui provoquait des messages "Erreur réseau" trompeurs
// (notamment sur mobile, où les photos prises directement au téléphone peuvent dépasser 10MB).
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Le fichier envoyé est trop volumineux (photos trop lourdes). Réessayez avec moins de photos.' });
  }
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Les informations envoyées sont incomplètes ou mal formées. Rechargez la page et réessayez.' });
  }
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Les informations envoyées sont incomplètes ou mal formées. Rechargez la page et réessayez.' });
  }
  next(err);
});

const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 900, standardHeaders: true, legacyHeaders: false });
// Les routes publiques n'exigent pas de compte — un visiteur doit pouvoir
// estimer un prix, et l'inscription doit pouvoir vérifier un SIRET. Sans
// limite, elles servent de relais gratuit : on interroge l'annuaire de l'État
// à votre place jusqu'à ce que VOTRE adresse soit bloquée, ou on extrait toute
// la grille tarifaire en quelques minutes.
// 30 par minute laisse largement de quoi remplir un formulaire.
const publicLimiter = rateLimit({
  windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Trop de requêtes. Patientez une minute.' }
});

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });
app.use('/api/', globalLimiter);

// ═══════════════════════════════════════════════════════════════════════════
// LIRE LE COOKIE SANS DÉPENDANCE SUPPLÉMENTAIRE
//
// `cookie-parser` ferait le travail, mais ajouter un paquet pour lire une
// chaîne de caractères n'en vaut pas la peine — et chaque dépendance est une
// surface d'attaque de plus.
// ═══════════════════════════════════════════════════════════════════════════
function lireCookie(req, nom) {
  const brut = req.headers.cookie;
  if (!brut) return null;
  for (const morceau of brut.split(';')) {
    const sep = morceau.indexOf('=');
    if (sep < 0) continue;
    if (morceau.slice(0, sep).trim() !== nom) continue;
    try { return decodeURIComponent(morceau.slice(sep + 1).trim()); }
    catch (e) { return null; }   // valeur mal encodée
  }
  return null;
}

// ── OÙ POSER LE COOKIE D'AUTHENTIFICATION ──────────────────────────────────
// `HttpOnly`  le JavaScript ne peut pas le lire : une faille XSS ne donne plus
//             accès au jeton, ce qui était le reproche de l'audit.
// `Secure`    transmis uniquement en HTTPS.
// `SameSite=None` obligatoire : l'application (Netlify) et l'API (Railway) ne
//             partagent pas le même domaine. « Lax » bloquerait tout.
//
// `SameSite=None` impose `Secure` — les navigateurs refusent l'un sans l'autre.
const COOKIE_JETON = 'gleam_session';
const OPTIONS_COOKIE = {
  httpOnly: true,
  secure: true,
  sameSite: 'none',
  maxAge: 7 * 24 * 3600 * 1000,
  path: '/'
};

// ═══════════════════════════════════════════════════════════════════════════
// EXIGER UNE ADRESSE VÉRIFIÉE — LÀ OÙ L'ARGENT CIRCULE
//
// L'audit relevait que `email_confirm: true` chez Supabase contredisait le
// système `email_verifie` de Gleam. En vérifiant, j'ai trouvé autre chose :
// les deux ne se contredisent pas. Le vrai défaut est que la vérification
// N'AVAIT AUCUN EFFET.
//
//     routes qui refusaient une adresse non vérifiée : 0
//
// L'application affichait « Confirmer mon email » dans le profil, et c'était
// tout. Corriger `email_confirm` sans donner un effet à `email_verifie`
// n'aurait rien changé.
//
// OÙ L'EXIGER, ET OÙ NE PAS L'EXIGER
//
//   payer                  OUI  l'argent engage, et un litige a besoin d'une
//                               adresse joignable
//   recevoir de l'argent   OUI  même raison, côté prestataire
//
//   créer une demande      non  freinerait le premier usage, sans rien protéger
//   envoyer un devis       non  le prestataire a déjà fourni ses documents
//   mot de passe oublié    non  c'est justement le recours de quelqu'un
//                               qui n'accède plus à son compte
//
// Exiger partout ferait fuir ; exiger nulle part ne protège rien.
// ═══════════════════════════════════════════════════════════════════════════
const exigerEmailVerifie = async (req, res, next) => {
  try {
    const { data: compte } = await supabase.from('users')
      .select('email_verifie').eq('id', req.user.id).maybeSingle();

    if (compte && compte.email_verifie === false) {
      return res.status(403).json({
        error: 'Confirmez votre adresse e-mail avant de continuer. '
             + 'Le code vous a été envoyé — retrouvez-le dans votre profil.',
        email_non_verifie: true
      });
    }
    next();
  } catch (e) {
    // Une lecture qui échoue ne doit pas bloquer un paiement : le client a
    // peut-être déjà saisi sa carte. On laisse passer et on note.
    console.warn('Vérification d\'email impossible :', e.message);
    next();
  }
};

const auth = async (req, res, next) => {
  // ── LE COOKIE D'ABORD, L'EN-TÊTE ENSUITE ────────────────────────────────
  // Les deux sont acceptés pendant la transition : les sessions déjà ouvertes
  // continuent de fonctionner avec leur jeton en localStorage, et les
  // nouvelles connexions reçoivent un cookie.
  //
  // Sans ce double chemin, tout le monde serait déconnecté au déploiement.
  const token = lireCookie(req, COOKIE_JETON)
    || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  if (!token) return res.status(401).json({ error: 'Votre session a expiré ou n\'est plus valide. Reconnectez-vous pour continuer.' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (e) {
    // Diagnostic précis, jamais le jeton ni la clé secrète eux-mêmes : seulement le type d'erreur
    // JWT réel (expiré, signature invalide, malformé) — pour savoir avec certitude la prochaine
    // fois, plutôt que de deviner entre un jeton simplement expiré (normal après 7 jours) et un
    // vrai problème de configuration (clé JWT_SECRET incohérente entre deux déploiements).
    console.warn('⚠️ Jeton rejeté — type d\'erreur JWT : ' + e.name + ' (' + e.message + ')');
    res.status(401).json({ error: 'Token invalide' });
  }
};

// Authentification admin totalement séparée du système client/pro — pas de rôle "admin" dans la
// table users (qui aurait demandé d'ouvrir à nouveau la contrainte de vérification sur le type),
// mais un token distinct, signé avec sa propre clé, vérifié par ce middleware dédié.
const adminAuth = async (req, res, next) => {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Votre session a expiré ou n\'est plus valide. Reconnectez-vous pour continuer.' });
  try {
    const decoded = jwt.verify(token, SECRET_ADMIN);
    if (!decoded.admin) return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });
    next();
  } catch (e) {
    res.status(401).json({ error: 'Session admin invalide, reconnectez-vous.' });
  }
};

const isProType = (t) => t === 'pro' || t === 'societe' || t === 'professionnel';

// Traduit les messages d'erreur techniques renvoyés par Supabase (souvent en anglais) en un
// message clair et en français pour l'utilisateur — sans jamais laisser passer un message brut
// non traduit, qui affichait par exemple "User already registered" au lieu d'un message compréhensible.
function traduireErreurSupabase(messageOriginal) {
  const m = (messageOriginal || '').toLowerCase();
  if (m.includes('already registered') || m.includes('already exists') || m.includes('duplicate'))
    return 'Un compte existe déjà avec cette adresse email.';
  if (m.includes('invalid email') || m.includes('unable to validate email'))
    return 'Adresse email invalide.';
  if (m.includes('password') && (m.includes('short') || m.includes('at least') || m.includes('weak')))
    return 'Mot de passe trop court ou trop simple (8 caractères minimum).';
  if (m.includes('rate limit') || m.includes('too many'))
    return 'Trop de tentatives, merci de réessayer dans quelques minutes.';
  if (m.includes('invalid login credentials') || m.includes('invalid credentials'))
    return 'Identifiants incorrects.';
  if (m.includes('network') || m.includes('timeout') || m.includes('fetch failed'))
    return 'Problème de connexion au serveur, merci de réessayer.';
  // Cas précis : une colonne attendue par le code n'existe pas encore dans la table (migration
  // SQL jamais exécutée sur cette base) — message explicite plutôt que le générique du dessous,
  // pour pouvoir corriger immédiatement en sachant exactement quoi faire.
  if (m.includes('column') && (m.includes('does not exist') || m.includes('not find')))
    return 'Erreur de configuration de la base de données (colonne manquante) — contactez le support technique en précisant "colonne manquante" et le message exact des journaux serveur.';
  // Message générique en dernier recours, jamais le message technique brut
  return 'Une erreur est survenue. Merci de réessayer ou de contacter le support si le problème persiste.';
}

// Vérifie qu'une date (et éventuellement une heure) de créneau n'est pas dans le passé.
// Retourne un message d'erreur (string) si invalide, ou null si tout va bien.
// Donne l'heure actuelle EN FRANCE (Europe/Paris), peu importe le fuseau horaire réel du serveur
// (Railway tourne en UTC) — indispensable ici : comparer une date/heure choisie par un client
// français à l'heure système du serveur (UTC) crée une fenêtre chaque jour (au moment où Paris a
// déjà changé de jour calendaire mais pas encore l'UTC) où une heure déjà passée en France pouvait
// être acceptée sans le moindre blocage. Bug confirmé et corrigé.
// ─────────────────────────────────────────────────────────────────────────
// Conversion d'un créneau en instant réel
//
// Les créneaux sont stockés en texte, dans l'heure du client français :
// "2026-09-15 à 14h30". Les interpréter avec new Date(a, m, j, h, min) les
// place dans le fuseau du SERVEUR — UTC sur Railway. Un rendez-vous à 9h00 à
// Reims devenait donc 9h00 UTC, soit 11h00 heure française, et expirait deux
// heures trop tard en été. La création, elle, validait déjà correctement en
// Europe/Paris : les deux moitiés du code ne parlaient pas de la même heure.
// ─────────────────────────────────────────────────────────────────────────
function decalageParisMinutes(instant) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: 'Europe/Paris', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'
  }).formatToParts(instant);
  const g = (t) => parseInt(parts.find(p => p.type === t).value, 10);
  const commeSiUTC = Date.UTC(g('year'), g('month') - 1, g('day'), g('hour'), g('minute'), g('second'));
  return Math.round((commeSiUTC - instant.getTime()) / 60000);
}

function creneauVersInstant(creneau) {
  const m = /(\d{4})-(\d{2})-(\d{2})\s*à\s*(\d{1,2})[h:](\d{2})/.exec(creneau || '');
  if (!m) return null;
  // On lit d'abord les composantes comme si elles étaient en UTC, puis on retire
  // le décalage réel de Paris à cette date (+1 h en hiver, +2 h en été).
  const provisoire = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]);
  const decalage = decalageParisMinutes(new Date(provisoire));
  return new Date(provisoire - decalage * 60000);
}

// ─────────────────────────────────────────────────────────────────────────
// Réservation atomique
//
// Le motif « je lis, je vérifie, puis j'écris » ne protège de rien : entre la
// lecture et l'écriture, une seconde requête peut passer le même contrôle. On
// écrit donc sous condition — le statut attendu fait partie du filtre — et on
// regarde si une ligne a réellement bougé. Une seule requête peut gagner.
// ─────────────────────────────────────────────────────────────────────────
async function reserverLigne(table, id, statutsAttendus, nouveauStatut) {
  const { data, error } = await supabase
    .from(table)
    .update({ statut: nouveauStatut })
    .eq('id', id)
    .in('statut', statutsAttendus)
    .select('id');
  if (error) throw error;
  return !!(data && data.length);
}

function maintenantEnFrance() {
  const parts = new Intl.DateTimeFormat('fr-FR', {
    timeZone: 'Europe/Paris', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'
  }).formatToParts(new Date());
  const get = (type) => parseInt(parts.find(p => p.type === type).value, 10);
  return { annee: get('year'), mois: get('month'), jour: get('day'), heure: get('hour'), minute: get('minute') };
}

function validerCreneauFutur(date, time) {
  if (!date) return null;
  const matchDate = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date);
  if (!matchDate) return 'Date invalide.';
  const anneeChoisie = parseInt(matchDate[1], 10);
  const moisChoisi = parseInt(matchDate[2], 10);
  const jourChoisi = parseInt(matchDate[3], 10);
  const maintenant = maintenantEnFrance();

  // Comparaison purement numérique (année, mois, jour) — jamais d'objet Date implicite dont le
  // fuseau horaire pourrait diverger de celui, français, dans lequel le client raisonne.
  const dateChoisieNum = anneeChoisie * 10000 + moisChoisi * 100 + jourChoisi;
  const aujourdhuiNum = maintenant.annee * 10000 + maintenant.mois * 100 + maintenant.jour;
  if (dateChoisieNum < aujourdhuiNum) return 'La date choisie ne peut pas être dans le passé.';

  if (dateChoisieNum === aujourdhuiNum && time) {
    const matchHeure = /(\d{1,2})h(\d{2})/.exec(time);
    if (matchHeure) {
      const heureChoisieNum = (+matchHeure[1]) * 60 + (+matchHeure[2]);
      const maintenantNum = maintenant.heure * 60 + maintenant.minute;
      if (heureChoisieNum < maintenantNum) return 'Cette heure est déjà passée aujourd\'hui. Choisissez un autre créneau.';
    }
  }
  return null;
}

// ══════════════ TARIFICATION (Vague 2/3) — calibrée sur des prix de marché réels ══════════════
// Coefficient d'état, universel à toutes les prestations
const ETAT_COEF = { propre: 1.0, moyen: 1.15, sale: 1.3, tres_sale: 1.5 };

// Tarif dégressif selon la surface — plus la surface est grande, plus le prix au m² baisse, comme
// c'est l'usage réel du marché (confirmé par la recherche : les vitreries appliquent ce même
// principe pour les grandes vitrines commerciales). Les coûts fixes d'une intervention
// (déplacement, installation du matériel, mise en route) s'amortissent sur davantage de mètres
// carrés quand le chantier est plus grand, justifiant un tarif unitaire réduit au-delà de certains
// seuils.
//
// Calculé de façon PROGRESSIVE, comme un barème d'impôt — chaque tranche de surface garde son
// propre tarif, plutôt qu'un simple palier appliqué à la surface entière. Sans ça, un mètre carré
// de plus pourrait faire BASCULER tout le calcul dans une tranche inférieure et donner un total
// final plus bas qu'une surface légèrement plus petite — un effet de seuil injuste, repéré et
// corrigé avant livraison.
// Barème revu à la hausse en agressivité, après une recherche de marché ciblée sur les grandes
// surfaces cumulées (proches d'une moquette professionnelle) : les tarifs réels chutent bien plus
// fort que les -22% initiaux au-delà de 50 m² — jusqu'à -50% à -65% pour une moquette de taille
// moyenne à grande, et même -70% à -80% pour les très grandes surfaces professionnelles. Un cas
// concret signalé (6 tapis + un tapis sur-mesure de 45 m², soit 76 m² au total) donnait un total de
// 1699€ avec l'ancien barème — bien au-dessus de ce que factureraient les professionnels réels à
// cette échelle, confirmé par plusieurs sources (Nova Hélios, WeCleaned, L'Atelier du Nettoyeur).
const PALIERS_DEGRESSIFS_SURFACE = [
  { jusqua: 10, coef: 1.0 },
  { jusqua: 25, coef: 0.85 },
  { jusqua: 50, coef: 0.60 },
  { jusqua: 100, coef: 0.40 },
  { jusqua: Infinity, coef: 0.28 }
];
// ─────────────────────────────────────────────────────────────────────────────
// PLANCHER D'INTERVENTION
//
// La dégressivité ci-dessus répond bien aux grandes surfaces. Elle laisse en
// revanche passer des estimations que personne ne peut honorer : 24 € pour
// 6 m² de vitres, 40 € pour 10 m² de terrasse. Un professionnel déclaré ne se
// déplace pas à ces prix — il faut compter le trajet, le matériel, l'installation
// et le rangement, indépendamment de la surface traitée.
//
// Le marché le confirme : les artisans appliquent un minimum de facturation de
// 60 à 90 €.
//
// 60 € plutôt que le milieu de la fourchette, pour une raison précise : à 70 €,
// le plancher écrasait des tarifs parfaitement légitimes que nous venons de
// calibrer — canapé 2 places 65 €, entretien de piscine 65 €, matelas 90×190
// 60 €. Un plancher n'est pas là pour corriger des prix justes, seulement pour
// écarter ceux qu'aucun professionnel ne peut honorer.
//
// Ce plancher ne s'applique qu'à l'ESTIMATION montrée au client. Le prestataire
// reste entièrement libre de son prix : ce n'est pas à la plateforme de le lui
// imposer, et une demande vraiment minuscule peut se justifier autrement — un
// client fidèle, un déplacement déjà prévu dans le quartier.
// ─────────────────────────────────────────────────────────────────────────────
const MINIMUM_INTERVENTION = 60;

// Renvoie le prix éventuellement relevé, et signale si le plancher a joué —
// pour que le client sache d'où vient le chiffre au lieu de le subir.
function appliquerPlancher(prixMoyen) {
  if (prixMoyen >= MINIMUM_INTERVENTION) {
    return { prix: prixMoyen, plancher: false };
  }
  return { prix: MINIMUM_INTERVENTION, plancher: true };
}

function surfaceEquivalentePonderee(quantite) {
  var restant = quantite, borneBasse = 0, total = 0;
  for (var i = 0; i < PALIERS_DEGRESSIFS_SURFACE.length && restant > 0; i++) {
    var palier = PALIERS_DEGRESSIFS_SURFACE[i];
    var largeurPalier = Math.min(restant, palier.jusqua - borneBasse);
    total += largeurPalier * palier.coef;
    restant -= largeurPalier;
    borneBasse = palier.jusqua;
  }
  return total; // une "surface équivalente" à multiplier par le prix/m² plein tarif
}

// ─────────────────────────────────────────────────────────────────────────────
// VÉRIFICATION DU SIRET AUPRÈS DU RÉPERTOIRE OFFICIEL
//
// API Recherche d'Entreprises, opérée par la DINUM. Gratuite, sans clé, elle
// agrège le répertoire Sirene (INSEE), le Registre National des Entreprises
// (INPI) et le BODACC. Limite annoncée : 7 appels par seconde.
//
// Cette fonction ne lève jamais d'exception et ne bloque jamais un appelant.
// Dans le pire des cas elle renvoie { statut: 'indisponible' } — jamais une
// erreur. Une inscription ne doit pas dépendre de la disponibilité d'un service
// tiers, si officiel soit-il.
//
// Codes NAF du nettoyage, à titre indicatif seulement : ils servent à signaler
// une incohérence à l'administrateur, jamais à refuser quoi que ce soit. Un
// artisan peut parfaitement nettoyer des canapés sous un code NAF de commerce.
// ─────────────────────────────────────────────────────────────────────────────
const NAF_NETTOYAGE = ['81.21Z', '81.22Z', '81.29A', '81.29B', '45.20A', '45.20B', '96.01B', '43.99C'];

function normaliserSiret(brut) {
  return String(brut || '').replace(/[^0-9]/g, '');
}

// ═══════════════════════════════════════════════════════════════════════════
// GÉOCODER UNE ADRESSE
//
// Les coordonnées d'une demande viennent de l'autocomplétion. Si le client
// tape son adresse sans choisir de suggestion, elles restent nulles — et sans
// coordonnées, aucune distance ne peut être calculée à l'arrivée du
// prestataire. Toute la vérification tombe.
//
// L'API Adresse du gouvernement comble ce trou : gratuite, sans clé, et
// alimentée par la Base Adresse Nationale.
//
// ELLE NE DOIT JAMAIS BLOQUER UNE DEMANDE
//
// Un service indisponible, une adresse mal orthographiée, un lieu-dit absent
// de la base : dans tous ces cas on renvoie null et la demande part quand
// même. Refuser une demande parce qu'un service tiers ne répond pas serait
// punir le client pour une panne qui ne le concerne pas.
// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════
// LE REPORT EST-IL ENCORE POSSIBLE ?
//
// Il était bloqué DÈS la déclaration d'arrivée, sans regarder si celle-ci
// était crédible. Un prestataire déclarant son arrivée depuis chez lui
// retirait au client son droit de reprogrammer — alors que rien ne prouvait
// qu'il fût là.
//
// Cela créait une contradiction avec ce qu'on avait posé la veille :
//
//   la clôture attendait 7 jours     parce qu'on doutait de l'arrivée
//   le report était bloqué           comme si on n'en doutait pas
//
// On protégeait l'argent du client, pas son créneau. Il ne pouvait ni
// reporter, ni annuler, et devait attendre une semaine pour être remboursé
// d'une prestation qui n'avait peut-être pas eu lieu.
//
// LA RÈGLE
//
//   arrivée sur place (< 2 km)         report fermé — quelqu'un est là
//   arrivée douteuse, client confirme  report fermé — il l'a dit lui-même
//   arrivée douteuse, sans réponse     report OUVERT
//
// L'ANNULATION, ELLE, RESTE BLOQUÉE DANS TOUS LES CAS. Annuler efface
// l'affaire : trop grave pour un doute. Reporter ne coûte rien à personne —
// le prestataire garde sa mission, à une autre date.
// ═══════════════════════════════════════════════════════════════════════════
function reportEncorePossible(demande) {
  if (!demande.prestation_demarree_le) return true;   // pas encore commencé

  // Le client a confirmé la venue : plus de doute, plus de report.
  if (demande.arrivee_confirmee_client === true) return false;

  // Arrivée non vérifiable : le client garde la main tant qu'il n'a pas
  // répondu. C'est lui qui sait si quelqu'un a sonné.
  return demande.arrivee_qualite === 'eloignee'
      || demande.arrivee_qualite === 'non_verifiee';
}

// ═══════════════════════════════════════════════════════════════════════════
// LE NOM D'UNE COMMUNE, À PARTIR DE COORDONNÉES
//
// « 10 km » ne veut rien dire sans son point de départ. La carte affichait ce
// chiffre seul, et le prestataire devait ouvrir le réglage pour se rappeler
// d'où partait son rayon.
//
// L'API Adresse fait aussi du géocodage inverse : des coordonnées donnent une
// commune. Gratuite, sans clé, comme le géocodage direct.
//
// Un échec renvoie null et l'application affiche « votre position » : moins
// précis, mais jamais faux.
// ═══════════════════════════════════════════════════════════════════════════
async function communeDepuisCoordonnees(latitude, longitude) {
  if (typeof latitude !== 'number' || typeof longitude !== 'number') return null;
  try {
    const reponse = await fetch(
      'https://api-adresse.data.gouv.fr/reverse/?lat=' + latitude + '&lon=' + longitude,
      { signal: AbortSignal.timeout(4000), headers: { 'Accept': 'application/json' } }
    );
    if (!reponse.ok) return null;
    const data = await reponse.json();
    const trouve = data && Array.isArray(data.features) ? data.features[0] : null;
    return (trouve && trouve.properties && trouve.properties.city) || null;
  } catch (e) {
    console.warn('Commune introuvable :', e.message);
    return null;
  }
}

async function geocoderAdresse(adresse) {
  const texte = String(adresse || '').trim();
  if (texte.length < 8) return null;   // trop court pour être une adresse

  try {
    const reponse = await fetch(
      'https://api-adresse.data.gouv.fr/search/?limit=1&q=' + encodeURIComponent(texte),
      { signal: AbortSignal.timeout(4000), headers: { 'Accept': 'application/json' } }
    );
    if (!reponse.ok) {
      console.warn('Géocodage — service indisponible (statut ' + reponse.status + ')');
      return null;
    }
    const data = await reponse.json();
    const trouve = data && Array.isArray(data.features) ? data.features[0] : null;
    if (!trouve || !trouve.geometry || !Array.isArray(trouve.geometry.coordinates)) return null;

    // Le score dit à quel point l'adresse trouvée ressemble à celle demandée.
    // En dessous de 0,4, la Base Adresse Nationale a renvoyé « la commune la
    // plus proche » plutôt que l'adresse — s'en servir placerait le point à
    // des kilomètres, et déclencherait une alerte sur un prestataire honnête.
    const score = typeof trouve.properties?.score === 'number' ? trouve.properties.score : 0;
    if (score < 0.4) {
      console.warn('Géocodage — correspondance trop faible (' + score.toFixed(2) + ') pour : ' + texte);
      return null;
    }

    const [lng, lat] = trouve.geometry.coordinates;   // la BAN renvoie lng, lat
    if (typeof lat !== 'number' || typeof lng !== 'number') return null;
    return { latitude: lat, longitude: lng, score };
  } catch (e) {
    // Délai dépassé, réseau coupé, réponse illisible : on continue sans.
    console.warn('Géocodage impossible :', e.message);
    return null;
  }
}

async function verifierSiretOfficiel(siretBrut) {
  const siret = normaliserSiret(siretBrut);
  if (siret.length !== 14) return { statut: 'introuvable', motif: 'format' };

  try {
    const reponse = await fetch(
      'https://recherche-entreprises.api.gouv.fr/search?q=' + siret + '&per_page=1',
      { signal: AbortSignal.timeout(4000), headers: { 'Accept': 'application/json' } }
    );
    if (!reponse.ok) {
      console.warn('SIRET — API répertoire indisponible (statut ' + reponse.status + ')');
      return { statut: 'indisponible' };
    }

    const data = await reponse.json();
    const resultats = Array.isArray(data && data.results) ? data.results : [];
    if (!resultats.length) return { statut: 'introuvable' };

    const r = resultats[0];
    // La réponse peut décrire l'établissement recherché soit dans
    // matching_etablissements, soit dans siege. On lit les deux, sans supposer
    // lequel est présent : cette API a déjà changé de forme par le passé.
    const correspondants = Array.isArray(r.matching_etablissements) ? r.matching_etablissements : [];
    const etab = correspondants.find(e => normaliserSiret(e && e.siret) === siret)
              || (r.siege && normaliserSiret(r.siege.siret) === siret ? r.siege : null)
              || correspondants[0] || r.siege || null;

    const etatEtab = etab && etab.etat_administratif;
    const etatUnite = r.etat_administratif;
    const naf = (etab && etab.activite_principale) || r.activite_principale || null;
    const nom = r.nom_complet || r.nom_raison_sociale
             || [r.prenom, r.nom].filter(Boolean).join(' ') || null;

    const infos = {
      siret,
      nom: nom,
      activite_code: naf,
      activite_libelle: (etab && etab.libelle_activite_principale) || r.libelle_activite_principale || null,
      commune: (etab && (etab.libelle_commune || etab.commune)) || null,
      code_postal: (etab && etab.code_postal) || null,
      date_creation: r.date_creation || null,
      nature_juridique: r.nature_juridique || null,
      etat_etablissement: etatEtab || null,
      etat_unite_legale: etatUnite || null,
      // Signalé, jamais bloquant : le code NAF ne dit pas ce qu'une personne
      // sait faire, seulement ce qu'elle a déclaré à la création.
      naf_coherent_nettoyage: naf ? NAF_NETTOYAGE.indexOf(String(naf).toUpperCase()) >= 0 : null,
      verifie_le: new Date().toISOString(),
      source: 'recherche-entreprises.api.gouv.fr'
    };

    // 'A' = actif, 'F' = fermé. En l'absence d'information, on ne conclut pas
    // à la fermeture : on considère l'établissement trouvé, c'est déjà l'essentiel.
    if (etatEtab === 'F') return { statut: 'ferme', infos };
    return { statut: 'verifie', infos };

  } catch (e) {
    // Délai dépassé, DNS, réseau, JSON malformé : aucune conséquence.
    console.warn('SIRET — vérification impossible : ' + (e && e.name ? e.name : 'erreur') + ' — ' + (e && e.message));
    return { statut: 'indisponible' };
  }
}

// Signale qu'un SIRET est partagé avec un autre compte. Aucune restriction
// n'est appliquée : le partage peut être parfaitement légitime — plusieurs
// intervenants d'une même société, plusieurs établissements — comme frauduleux.
// Seul un humain peut trancher, et il lui faut les deux dossiers sous les yeux.
//
// Surtout, bloquer serait contre-productif : un SIRET est public, et refuser le
// second inscrit reviendrait à laisser un imposteur verrouiller définitivement
// l'accès de la vraie entreprise.
async function signalerSiretPartage(userId, siret) {
  try {
    const propre = String(siret || '').replace(/\s/g, '');
    if (!/^\d{14}$/.test(propre)) return { partage: false };

    const { data: autres } = await supabase.from('users')
      .select('id, email, prenom, nom, created_at')
      .eq('siret', propre)
      .neq('id', userId)
      .eq('compte_supprime', false);

    if (!autres || !autres.length) return { partage: false };

    await supabase.from('users').update({ siret_doublon: true }).eq('id', userId);

    console.warn('⚠️ SIRET partagé — ' + propre + ' — compte ' + userId +
      ' partage ce numéro avec ' + autres.length + ' autre(s) : ' +
      autres.map(u => u.email).join(', ') + ' — à examiner.');

    return { partage: true, nombre: autres.length };
  } catch (e) {
    console.error('Détection SIRET partagé :', e.message);
    return { partage: false };
  }
}

// Enregistre le résultat sans jamais faire échouer l'appelant.
async function enregistrerVerificationSiret(userId, siret) {
  try {
    // Les deux contrôles vont de pair : l'un dit si le numéro existe, l'autre
    // s'il est déjà utilisé chez vous. Aucun des deux ne bloque.
    signalerSiretPartage(userId, siret).catch(() => {});

    const resultat = await verifierSiretOfficiel(siret);
    await supabase.from('users').update({
      siret_statut: resultat.statut,
      siret_verifie_le: new Date().toISOString(),
      siret_donnees: resultat.infos || null
    }).eq('id', userId);

    if (resultat.statut === 'verifie') {
      console.log('✅ SIRET vérifié — ' + (resultat.infos.nom || siret));
    } else {
      console.warn('⚠️ SIRET à examiner — compte ' + userId + ' — statut : ' + resultat.statut);
    }
  } catch (e) {
    console.error('Enregistrement vérification SIRET :', e.message);
  }
}

// Distance à vol d'oiseau entre deux points GPS (formule de Haversine), en kilomètres — reprise
// et factorisée depuis le calcul déjà utilisé pour vérifier la position d'un pro à l'arrivée,
// réutilisée ici pour filtrer les demandes par zone d'intervention.
function distanceKm(lat1, lon1, lat2, lon2) {
  const R = 6371; // rayon de la Terre en kilomètres
  const toRad = (deg) => deg * Math.PI / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

// Configuration complète par prestation. Chaque catégorie a une "dimension principale" (tierKey)
// pour laquelle le PRO SAISIT DIRECTEMENT UN PRIX PAR CAS CONCRET (ex: un prix pour "Citadine",
// un autre pour "SUV/4x4"...), plutôt qu'un coefficient invisible appliqué à un prix unique.
// Une dimension secondaire (matière, portée...) reste un coefficient multiplicatif simple.
// Chiffres calibrés à partir d'une recherche de prix pratiqués par des professionnels en France
// (voir tableau-reference-prix-marche.md pour le détail des sources et du raisonnement).
const PRESTATION_CONFIG = {
  voiture: {
    tierKey: 'taille', // le pro saisit un prix par type de véhicule
    // Le palier « berline » manquait alors que c'est le gabarit le plus répandu du
    // parc français. Une berline devait être classée en citadine ou en SUV, deux
    // réponses fausses. 105 € : la recherche de marché donne 85 à 110 € pour un
    // nettoyage complet de berline (2 h), c'est le seul chiffre précis disponible.
    tiers: ['citadine', 'berline', 'suv_4x4', 'monospace', 'utilitaire'],
    tierLabels: { citadine: 'Citadine', berline: 'Berline', suv_4x4: 'SUV / 4x4', monospace: 'Monospace', utilitaire: 'Utilitaire / Van' },
    tierDefaults: { citadine: 85, berline: 105, suv_4x4: 128, monospace: 132, utilitaire: 153 }, // intérieur+extérieur, propre
    coefPortee: { interieur: 0.70, exterieur: 0.55, complet: 1.0 },
    // Le nombre de places est un facteur secondaire : à type de véhicule identique, plus de places
    // signifie plus de surface à nettoyer (ex: un SUV 5 places vs un SUV 7 places).
    coefPlaces: { A: 0.90, B: 1.0, C: 1.15, D: 1.35 } // 2, 5, 7, 9+ places
  },
  canape: {
    tierKey: 'taille', // le pro saisit un prix par nombre de places
    tiers: ['A', 'B', 'C', 'D'],
    tierLabels: { A: '2 places', B: '3 places', C: '4 places', D: '5+ places / angle' },
    // Relevé sur le segment professionnel déclaré, seul comparable au modèle Gleam
    // (SIRET et RC Pro exigés) : C'Clean Lyon 70/90 €, AJC Lille 80/100 €, Fée du
    // propre Montpellier 100 € pour un 3 places. Les valeurs précédentes — 45 à
    // 85 € — venaient du segment entre particuliers, où le prestataire n'est ni
    // déclaré ni assuré. Un professionnel qui les appliquait travaillait à perte
    // sur une intervention d'une à deux heures, déplacement compris.
    tierDefaults: { A: 65, B: 80, C: 95, D: 115 }, // tissu, propre
    coefMatiere: { tissu: 1.0, cuir: 1.15, velours: 1.1, microfibre: 1.0 },
    // La forme influence le temps de travail à nombre de places égal (un angle est plus complexe qu'un droit).
    // Le "U" (panoramique, 2 retours) est nettement plus grand et complexe qu'un simple angle
    // (souvent 6 à 10 places contre 3-5 pour un angle classique) — coefficient recherché en conséquence.
    coefForme: { droit: 1.0, angle: 1.2, u_panoramique: 1.45, canape_lit: 1.15, chauffeuses: 0.85 }
  },
  matelas: {
    unite: true,
    tierKey: 'taille', // le pro saisit un prix unitaire par taille de matelas
    tiers: ['A', 'B', 'C', 'D', 'E'],
    // 200x200 ("Empereur" / King Size XL) manquait — une vraie taille standard en France, plus
    // grande que le 180x200 (King Size), confirmée par la recherche de marché (IKEA, Epéda,
    // La Maison Senso...). Prix extrapolé en suivant la progression déjà établie entre les paliers.
    tierLabels: { A: '90x190 cm', B: '140x190 cm', C: '160x200 cm', D: '180x200 cm', E: '200x200 cm (Empereur)' },
    // Corrigé après nouvelle recherche de marché : l'ensemble de la gamme était sous-évalué
    // d'environ 20 à 30% par rapport aux tarifs réels observés (BuildingDrive : 59€ à 99€ selon
    // taille ; L'Atelier du Nettoyeur : 72€ à 132€ selon taille) — progression resserrée sur les
    // nouveaux montants.
    tierDefaults: { A: 60, B: 78, C: 90, D: 105, E: 125 } // propre (marché observé 2026 : 59-72€ pour 90x190, jusqu'à 120-132€ pour 180x200/200x200)
  },
  terrasse: {
    unite: true,
    uniteLabel: 'm²', // le pro fixe un prix par m² réel, le client indique la surface exacte
    prixReferenceDefaut: 4, // €/m², carrelage, état propre (marché observé : 2 à 5€/m² carrelage)
    coefMatiere: { carrelage: 1.0, beton: 1.05, pierre_naturelle: 1.1, bois_composite: 2.75 } // bois/composite : 5 à 15€/m² observé
  },
  piscine: {
    tierKey: 'intervention', // le pro saisit un prix par type d'intervention (le vrai driver de prix du métier)
    tiers: ['entretien', 'complet', 'eau_verte'],
    tierLabels: { entretien: 'Entretien simple', complet: 'Nettoyage complet', eau_verte: 'Eau verte / remise en état' },
    // entretien 65 € : au centre exact du marché (50 à 70 € la visite de contrôle).
    // complet 190 € : le marché situe la remise en route entre 150 et 300 €.
    // eau_verte 600 € : borne basse de la fourchette 600 à 2 200 € relevée pour un
    // bassin laissé à l'abandon. On reste volontairement au plancher : le client
    // découvrant un devis supérieur à l'estimation est plus fréquent que l'inverse.
    tierDefaults: { entretien: 65, complet: 190, eau_verte: 600 }, // bassin moyen, propre
    // Coefficient revu à la baisse : l'ancien 1.9 pour les plus grands bassins, combiné au tarif
    // eau verte (585€), donnait un pire cas à 1111€ — bien au-delà des 300 à 800€ observés sur le
    // marché réel pour ce type d'intervention, même sur un grand bassin très encrassé.
    coefTaille: { A: 0.8, B: 1.0, C: 1.25, D: 1.5 },
    // Un spa/jacuzzi est nettement plus petit qu'un bassin classique ; le hors-sol est aussi souvent plus simple.
    coefTypeBassin: { enterree: 1.0, semi_enterree: 0.95, hors_sol: 0.8, spa_jacuzzi: 0.35 }
  },
  toiture: {
    unite: true,
    uniteLabel: 'm²', // le pro fixe un prix par m² réel, le client indique la surface exacte
    prixReferenceDefaut: 20, // €/m², tuiles, démoussage + hydrofuge, état propre (marché observé : 9 à 40€/m²)
    // Corrigé après nouvelle recherche de marché : ardoise et fibrociment étaient auparavant moins
    // chers que tuiles, alors que le marché montre l'inverse — l'ardoise naturelle demande plus de
    // minutie (fixations à préserver), et le fibrociment implique un risque amiante à gérer,
    // justifiant un tarif au moins équivalent, voire légèrement supérieur, à celui des tuiles.
    coefMatiere: { tuiles: 1.0, ardoises: 1.05, fibrociment: 1.05, zinc_metal: 1.1 }
  },
  vitres: {
    unite: true,
    uniteLabel: 'm²', // le pro fixe un prix par m² de surface vitrée réelle
    tierKey: 'type_bien', // le type de bien reste pertinent : accès et vitrages souvent plus complexes en commerce/bureaux
    tiers: ['maison', 'appartement', 'commerce', 'bureaux'],
    tierLabels: { maison: 'Maison', appartement: 'Appartement', commerce: 'Commerce', bureaux: 'Bureaux' },
    // Bureaux corrigé après nouvelle recherche : le marché pro/copropriété/hauteur observe plutôt
    // 7 à 12€/m², contre 5,2€ auparavant — trop proche du tarif particulier alors que ce segment
    // implique souvent un accès plus complexe (immeubles, façades vitrées en hauteur).
    tierDefaults: { maison: 4, appartement: 4, commerce: 5, bureaux: 6.5 } // €/m², propre (marché observé 2026 : 4-8€/m² particulier, 7-12€/m² pro/copropriété/hauteur)
  },
  tapis: {
    unite: true,
    uniteLabel: 'm²', // le pro fixe un prix par m² réel, le client indique la surface exacte
    // 16 €/m² et non 20 : la base doit être le BAS de la fourchette de marché,
    // pas son milieu. Les fourchettes relevées — 15 à 25 €/m² pour du synthétique,
    // 25 à 35 pour de la laine — contiennent déjà la variation de matière et
    // d'état. Partir du milieu puis remultiplier par 1,6 (matière) et 1,6 (état)
    // comptait deux fois la même chose : un tapis de laine très sale ressortait à
    // 51 €/m², soit 45 % au-dessus du plafond du marché.
    //
    // Avec 16 €/m² et des coefficients resserrés, les extrêmes retombent dans les
    // clous : synthétique 16 à 25,6 · laine 23,2 à 37,1 · soie 48 à 76,8 €/m².
    prixReferenceDefaut: 16, // €/m², synthétique, état propre (marché : 15 à 25 €/m²)
    // Le rapport soie/synthétique reste d'environ 3, conforme au marché relevé
    // (synthétique dès 18 €/m², soie dès 45 à 75 €/m²).
    coefMatiere: { synthetique: 1.0, coton: 1.15, jute_sisal: 1.25, berbere: 1.3, laine: 1.45, soie: 3.0 }
  },
  autre: {
    tierKey: null, // pas de dimension structurée, un seul prix indicatif
    prixReferenceDefaut: 60
  }
};

const UNIT_CATEGORIES = Object.keys(PRESTATION_CONFIG).filter(k => PRESTATION_CONFIG[k].unite);

// Calcule le prix pour un palier donné d'une prestation, en utilisant la moyenne des prix
// déclarés par les pros disponibles pour CE palier précis, ou le prix par défaut sinon.
// Fonctionne aussi pour les catégories sans palier (prix unique par pro, ex: prix au m²).
function prixPourPalier(config, prestation, tierValue, prosTarifs) {
  if (!config.tiers) {
    const declares = (prosTarifs || []).filter(v => typeof v === 'number' && v > 0);
    const prix = declares.length ? declares.reduce((a, b) => a + b, 0) / declares.length : config.prixReferenceDefaut;
    return { prix, reel: declares.length > 0, nbPros: declares.length };
  }
  const key = tierValue && config.tiers.includes(tierValue) ? tierValue : config.tiers[0];
  const declares = (prosTarifs || [])
    .map(t => t && t[key])
    .filter(v => typeof v === 'number' && v > 0);
  const prix = declares.length ? declares.reduce((a, b) => a + b, 0) / declares.length : config.tierDefaults[key];
  return { prix, reel: declares.length > 0, nbPros: declares.length };
}

// Extrait la liste des types de prestation demandés (ex: ['voiture','canape'] pour une demande groupée)
// à partir du champ notes (JSON) d'une demande, avec repli sur le champ prestation si besoin.
function extractPrestationTypes(demande) {
  try {
    const n = JSON.parse(demande.notes);
    if (n && Array.isArray(n.prestations) && n.prestations.length) {
      return n.prestations.map(p => p.type).filter(Boolean);
    }
  } catch (e) { /* notes non-JSON ou absent, on utilise le repli ci-dessous */ }
  return (demande.prestation || '').split(' + ').map(s => s.trim()).filter(Boolean);
}
// ═══════════════════════════════════════════════════════════════════════════
// LES COORDONNÉES DÉGUISÉES
//
// Le filtre bloquait « 06 12 34 56 78 » mais laissait passer :
//
//   « Zéro six cinquante un vingt quatre vingt douze quatre vingt cinq »
//   « O6 I2 34 56 78 »        (lettre O, lettre I)
//   « 06​12​34​56​78 »            (espaces de largeur nulle entre les chiffres)
//
// Plutôt que d'allonger une expression déjà illisible, on NORMALISE le texte
// avant de le tester. Chaque nouvelle ruse se traite alors en ajoutant une
// ligne de conversion, pas une alternative de plus dans le motif.
//
// Ce que ce filtre ne fera jamais : arrêter quelqu'un de déterminé. « mon
// numéro finit par 85, le début c'est mon année de naissance » passera
// toujours. L'objectif est de rendre le contournement plus pénible que la voie
// normale, et de garder une trace quand quelqu'un essaie.
// ═══════════════════════════════════════════════════════════════════════════

// Les nombres écrits en lettres, du plus long au plus court : « quatre-vingt »
// doit être converti avant « quatre », sinon il reste « 4-vingt ».
const MOTS_NOMBRES = [
  ['quatre[\s-]*vingt[s]?[\s-]*dix[\s-]*neuf', '99'], ['quatre[\s-]*vingt[s]?[\s-]*dix[\s-]*huit', '98'],
  ['quatre[\s-]*vingt[s]?[\s-]*dix[\s-]*sept', '97'], ['quatre[\s-]*vingt[s]?[\s-]*seize', '96'],
  ['quatre[\s-]*vingt[s]?[\s-]*quinze', '95'], ['quatre[\s-]*vingt[s]?[\s-]*quatorze', '94'],
  ['quatre[\s-]*vingt[s]?[\s-]*treize', '93'], ['quatre[\s-]*vingt[s]?[\s-]*douze', '92'],
  ['quatre[\s-]*vingt[s]?[\s-]*onze', '91'], ['quatre[\s-]*vingt[s]?[\s-]*dix', '90'],
  ['quatre[\s-]*vingt[s]?', '80'],
  ['soixante[\s-]*dix[\s-]*neuf', '79'], ['soixante[\s-]*dix[\s-]*huit', '78'],
  ['soixante[\s-]*dix[\s-]*sept', '77'], ['soixante[\s-]*seize', '76'],
  ['soixante[\s-]*quinze', '75'], ['soixante[\s-]*quatorze', '74'],
  ['soixante[\s-]*treize', '73'], ['soixante[\s-]*douze', '72'],
  ['soixante[\s-]*et[\s-]*onze', '71'], ['soixante[\s-]*dix', '70'],
  ['cinquante[\s-]*et[\s-]*un', '51'], ['quarante[\s-]*et[\s-]*un', '41'],
  ['trente[\s-]*et[\s-]*un', '31'], ['vingt[\s-]*et[\s-]*un', '21'],
  ['soixante', '60'], ['cinquante', '50'], ['quarante', '40'], ['trente', '30'],
  ['dix[\s-]*neuf', '19'], ['dix[\s-]*huit', '18'], ['dix[\s-]*sept', '17'],
  ['seize', '16'], ['quinze', '15'], ['quatorze', '14'], ['treize', '13'],
  ['douze', '12'], ['onze', '11'], ['vingt', '20'], ['dix', '10'],
  ['neuf', '9'], ['huit', '8'], ['sept', '7'], ['six', '6'], ['cinq', '5'],
  ['quatre', '4'], ['trois', '3'], ['deux', '2'], ['une?', '1'],
  ['z[ée]ro', '0'], ['o', '0']
];

function normaliserPourDetection(texte) {
  if (!texte) return '';
  let t = String(texte);

  // 1. Les caractères invisibles, insérés entre les chiffres pour casser le
  //    motif sans que rien ne se voie à l'écran.
  t = t.replace(/[\u200B-\u200D\uFEFF\u00AD\u2060]/g, '');

  // 2. Les accents, pour que « zéro » et « zero » se traitent pareil.
  t = t.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();

  // 3. Les mots-nombres, du plus long au plus court.
  //    La dernière règle — « o » seul → « 0 » — ne s'applique qu'entre des
  //    chiffres, sinon elle détruirait tous les mots du message.
  for (const [motif, chiffre] of MOTS_NOMBRES) {
    if (motif === 'o') continue;
    t = t.replace(new RegExp('\\b' + motif + '\\b', 'g'), chiffre);
  }

  // 4. Les lettres qui imitent des chiffres, uniquement dans un contexte
  //    numérique : « O6 12 » devient « 06 12 », mais « Bonjour » reste intact.
  t = t.replace(/(?<=\d[\s.-]*)[oO](?=[\s.-]*\d)/g, '0')
       .replace(/(?<=\d[\s.-]*)[iIlL](?=[\s.-]*\d)/g, '1')
       .replace(/^[oO](?=\s*\d)/g, '0');

  // 5. Les espaces multiples issus des remplacements.
  return t.replace(/\s{2,}/g, ' ');
}

// Un numéro peut aussi apparaître une fois les mots convertis mais sans le
// préfixe attendu : « 6 51 24 92 85 » sans le zéro initial. On cherche donc
// aussi une suite de huit à dix chiffres séparés par n'importe quoi.
// Une suite de neuf chiffres ou plus, quels que soient les séparateurs — les
// virgules comprises : « zéro six, douze, trente-quatre » donne « 0 6, 12, 34 »
// une fois normalisé, et sans la virgule dans la classe, le motif s'arrête au
// premier groupe.
const SUITE_LONGUE_REGEX = /(?:\d[\s.,;:\-]*){9,}/;

// Détecte un numéro de téléphone français (mobile ou fixe), même écrit avec espaces/points/tirets
// entre les groupes de chiffres (ex: "06 12 34 56 78", "06.12.34.56.78"), pas seulement collé.
// Détecte une tentative de partage de coordonnées avant paiement : numéro français (fixe/mobile,
// collé ou avec séparateurs), numéro au format international (+33/0033), email (y compris légèrement
// déguisé avec "at"/"point"), ou mention d'une messagerie externe couramment utilisée pour contourner
// la plateforme. Reste volontairement prudent sur les mots ambigus (ex: "signal", "snap") pour éviter
// de bloquer des messages innocents.
const BLOCK_REGEX = /(\b0[1-9](?:[\s.-]?\d{2}){4}\b|(?:\+33|0033)[\s.-]?[1-9](?:[\s.-]?\d{2}){4}\b|[\w.+-]+\s?(?:@|\(at\)|arobase)\s?[\w-]+\s?(?:\.|\(dot\)|\bpoint\b)\s?[a-z]{2,}|whatsapp|telegram|instagram|messenger|snapchat|tiktok|facebook|viber|\bsms\b)/i;

// Teste le message brut ET sa version normalisée. Le brut attrape ce qui est
// écrit directement ; le normalisé attrape les déguisements.
function contientCoordonnees(texte) {
  if (!texte) return false;
  if (BLOCK_REGEX.test(texte)) return true;
  const normalise = normaliserPourDetection(texte);
  return BLOCK_REGEX.test(normalise) || SUITE_LONGUE_REGEX.test(normalise);
}


app.get('/health', (req, res) => {
  res.json({ status: 'ok', app: 'Gleam API', version: '2.2.0', timestamp: new Date().toISOString() });
});

// ══════════════ AUTH ══════════════

// ═══════════════════════════════════════════════════════════════════════════
// CE QU'UN COMPTE NE DOIT JAMAIS RÉVÉLER
//
// `res.json({ ...data })` renvoyait TOUTES les colonnes de la table users.
// Parmi elles :
//
//   reset_code           le code qui permet de changer un mot de passe
//   email_verif_code     le code de vérification d'adresse
//   siret_donnees        la réponse brute de l'annuaire des entreprises
//
// Le compte est bien celui de l'utilisateur — ce n'est donc pas une fuite
// vers un tiers. Mais ces codes n'ont aucune raison de quitter le serveur :
// ils transitent par le réseau, s'inscrivent dans les journaux du navigateur,
// et restent en mémoire de l'application.
//
// Le risque grandit avec le temps : le jour où la table gagne une colonne
// sensible — un jeton, une note interne, un indicateur d'administration —
// elle partirait au client sans que personne s'en aperçoive.
//
// On liste donc ce qu'on RETIRE, jamais ce qu'on garde : une nouvelle colonne
// anodine reste visible, une nouvelle colonne sensible s'ajoute ici.
// ═══════════════════════════════════════════════════════════════════════════
const CHAMPS_INTERNES = [
  'reset_code', 'reset_code_expire',
  'email_verif_code', 'email_verif_expire',
  'siret_donnees'
];

// ═══════════════════════════════════════════════════════════════════════════
// UN CODE SECRET NE SE TIRE PAS AU HASARD ORDINAIRE
//
// `Math.random()` n'est pas conçu pour la sécurité : sa suite est prévisible
// pour qui observe assez de valeurs. Quatre codes en dépendaient — vérification
// d'adresse, réinitialisation de mot de passe, validation de prestation.
//
// Le dernier est le plus sensible : c'est lui qui libère le paiement.
//
// `crypto.randomInt` puise dans la source d'entropie du système. Même coût,
// même forme, aucune prévisibilité.
// ═══════════════════════════════════════════════════════════════════════════
// UN CODE DE RÉINITIALISATION NE SE STOCKE PAS EN CLAIR
//
// Il l'était. Quiconque lisait la table `users` — une fuite, un accès
// administrateur, une sauvegarde égarée — pouvait prendre la main sur
// n'importe quel compte pendant trente minutes.
//
// On enregistre l'EMPREINTE. Le serveur compare l'empreinte du code saisi à
// celle stockée : il n'a jamais besoin de connaître le code.
//
// POURQUOI SHA-256 SUFFIT ICI, ALORS QU'UN MOT DE PASSE DEMANDE SCRYPT
//
// Un mot de passe est réutilisé, choisi par un humain, et vit des années :
// il faut une fonction lente pour décourager l'essai en masse.
//
// Ce code vit trente minutes, ne vaut que pour un compte, et compte un million
// de possibilités — protégées par un compteur de cinq tentatives. La lenteur
// n'apporterait rien, et ralentirait chaque vérification légitime.
function empreinteCode(code) {
  return crypto.createHash('sha256').update(String(code).trim()).digest('hex');
}

function codeSecret6() {
  return String(crypto.randomInt(100000, 1000000));
}

function compteVisible(compte) {
  if (!compte) return compte;
  const propre = { ...compte };
  for (const champ of CHAMPS_INTERNES) delete propre[champ];
  return propre;
}

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const email = req.body.email;
    const password = req.body.password;
    const prenom = req.body.firstName || req.body.prenom;
    const nom = req.body.lastName || req.body.nom;
    const telephone = req.body.phone || req.body.telephone;
    const type = req.body.role || req.body.type || 'client';
    const assuranceRcPro = Boolean(req.body.assurance_rc_pro);
    const assuranceCompagnie = req.body.assurance_compagnie || null;
    const assurancePolice = req.body.assurance_police || null;
    const siret = (req.body.siret || '').replace(/\s/g, '').trim();
    const raisonSociale = req.body.raison_sociale || null;
    const tvaIntracom = req.body.tva_intracom || null;
    const adresseFacturation = req.body.adresse_facturation || null;
    const cguAcceptees = Boolean(req.body.cgu_accepte);
    const codeParrainageSaisi = (req.body.code_parrainage || '').trim().toUpperCase();

    if (!email || !password || !prenom || !nom)
      return res.status(400).json({ error: 'Tous les champs sont requis.' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Mot de passe : 8 caractères minimum.' });
    if (!cguAcceptees)
      return res.status(400).json({ error: 'Merci d\'accepter les CGU et la politique de confidentialité pour continuer.' });
    // Ni le SIRET ni l'attestation d'assurance ne sont exigés pour créer un
    // compte. Ils le sont avant le premier devis — voir justificatifsManquants().
    //
    // Un artisan convaincu par la plateforme mais qui n'a pas ses papiers sous
    // les yeux doit pouvoir s'inscrire, regarder les demandes de son secteur et
    // revenir. L'exiger ici revenait à le perdre définitivement.
    //
    // En revanche, un SIRET fourni doit être correctement formé : mieux vaut le
    // dire tout de suite que de le laisser passer et le refuser au premier devis.
    if (isProType(type) && siret && !/^\d{14}$/.test(siret))
      return res.status(400).json({ error: 'Numéro SIRET invalide (14 chiffres attendus). Vous pouvez aussi laisser le champ vide et le renseigner plus tard.' });
    // Rien n'est exigé d'une entreprise pour créer son compte, pas plus que d'un
    // prestataire ou d'un particulier. Les informations de facturation sont
    // demandées avant le premier paiement — voir facturationManquante().
    //
    // Un gérant qui découvre Gleam ne connaît pas encore son besoin. Lui demander
    // trois champs administratifs avant qu'il ait vu un seul prix, c'est le perdre
    // pour une information dont on n'aura peut-être jamais besoin.
    //
    // Le format du SIRET reste contrôlé s'il est saisi : mieux vaut signaler une
    // faute de frappe tout de suite que la découvrir au moment de payer.
    if (type === 'entreprise' && siret && !/^\d{14}$/.test(siret))
      return res.status(400).json({ error: 'Numéro SIRET invalide (14 chiffres attendus). Vous pouvez aussi laisser le champ vide et le renseigner plus tard.' });

    // Vérifie le code de parrainage éventuellement saisi (silencieusement ignoré s'il est invalide,
    // pour ne jamais bloquer une inscription à cause d'une faute de frappe sur ce champ optionnel)
    let parrainId = null;
    if (codeParrainageSaisi) {
      const { data: parrain } = await supabase.from('users').select('id').eq('code_parrainage', codeParrainageSaisi).maybeSingle();
      if (parrain) parrainId = parrain.id;
    }

    const { data: authData, error: authError } = await supabase.auth.admin.createUser({
      email: email.toLowerCase().trim(),
      password: password,
      email_confirm: true
    });
    if (authError) { console.error('Erreur inscription (Supabase Auth), message technique complet:', authError); return res.status(400).json({ error: traduireErreurSupabase(authError.message) }); }

    // Génère un code de parrainage unique pour ce nouveau compte (quelques essais suffisent presque
    // toujours vu le grand nombre de combinaisons possibles)
    let codeParrainage = null;
    for (let essai = 0; essai < 5 && !codeParrainage; essai++) {
      const candidat = (prenom.trim().slice(0, 4) + Math.floor(1000 + Math.random() * 9000)).toUpperCase().replace(/[^A-Z0-9]/g, '');
      const { data: dejaUtilise } = await supabase.from('users').select('id').eq('code_parrainage', candidat).maybeSingle();
      if (!dejaUtilise) codeParrainage = candidat;
    }

    // Code de vérification email à 6 chiffres, envoyé après l'inscription — sur le modèle des
    // meilleures pratiques actuelles (recherche à l'appui) : vérifier l'email par un code plutôt
    // qu'un lien, mais SANS bloquer l'accès à l'application en attendant (l'utilisateur peut
    // utiliser Gleam normalement dès l'inscription, la confirmation se fait en tâche de fond,
    // avec un simple rappel non-bloquant dans l'app tant qu'elle n'est pas faite).
    const codeVerifEmail = codeSecret6();
    const codeVerifExpire = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // valable 24h

    const { data, error } = await supabase.from('users').insert({
      id: authData.user.id,
      email: email.toLowerCase().trim(),
      prenom: prenom.trim(),
      nom: nom.trim(),
      telephone: telephone || null,
      type: type,
      disponible: true,
      assurance_rc_pro: isProType(type) ? assuranceRcPro : null,
      assurance_compagnie: isProType(type) ? assuranceCompagnie : null,
      assurance_police: isProType(type) ? assurancePolice : null,
      siret: (isProType(type) || type === 'entreprise') ? siret : null,
      raison_sociale: type === 'entreprise' ? raisonSociale : null,
      tva_intracom: type === 'entreprise' ? tvaIntracom : null,
      adresse_facturation: type === 'entreprise' ? adresseFacturation : null,
      cgu_acceptees_le: new Date().toISOString(),
      code_parrainage: codeParrainage,
      parraine_par: parrainId,
      email_verifie: false,
      email_verif_code: codeVerifEmail,
      email_verif_expire: codeVerifExpire
    }).select().single();

    if (error) {
      // Le compte de connexion a été créé mais le profil a échoué : on annule tout plutôt que
      // de laisser un compte "orphelin" (connexion possible, mais aucune donnée de profil).
      console.error('Erreur inscription (insertion profil), message technique complet:', error);
      await supabase.auth.admin.deleteUser(authData.user.id).catch(e => console.error('Rollback inscription:', e));
      return res.status(400).json({ error: traduireErreurSupabase(error.message) });
    }

    // Envoie le code de vérification par email — protégé dans son propre bloc : un souci d'envoi
    // (SendGrid indisponible, etc.) ne doit jamais empêcher la création du compte de réussir,
    // l'utilisateur pourra toujours redemander un nouveau code plus tard depuis son profil.
    try {
      sendEmail('verification_email', data.email, { compteId: data.id, prenom: data.prenom, code: codeVerifEmail });
    } catch (e) {
      console.error('Envoi email de vérification échoué (compte créé normalement):', e.message);
    }

    // Vérification du SIRET, volontairement SANS await : l'inscription se termine
    // à la même vitesse qu'avant, et un répertoire momentanément injoignable ne
    // peut en aucun cas empêcher quelqu'un de créer son compte.
    if (siret && (isProType(type) || type === 'entreprise')) {
      enregistrerVerificationSiret(data.id, siret).catch(() => {});
    }

    const token = jwt.sign({ id: data.id, email: data.email, type: data.type }, process.env.JWT_SECRET, { expiresIn: '7d' });
    // ── LE CODE DE VÉRIFICATION NE DOIT PAS PARTIR AVEC LA RÉPONSE ────────
    // `...data` renvoyait la ligne ENTIÈRE telle qu'insérée — y compris
    // `email_verif_code` et `email_verif_expire`, créés quelques lignes plus
    // haut.
    //
    // La personne qui s'inscrivait recevait donc le code censé prouver qu'elle
    // contrôle l'adresse. La vérification par courriel ne prouvait plus rien.
    //
    // `compteVisible` existe et filtre déjà ces champs sur /login et /me.
    // Cette route l'avait oublié.
    res.cookie(COOKIE_JETON, token, OPTIONS_COOKIE);
    res.status(201).json({ message: 'Compte Gleam créé !', token, user: { ...compteVisible(data), firstName: data.prenom, lastName: data.nom } });
  } catch (e) {
    console.error(e);
    erreurServeur(res, 'POST /api/auth/register', e);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// LA DÉCONNEXION DOIT EFFACER LE COOKIE
//
// Il n'existait aucune route de déconnexion : le client se contentait de vider
// son localStorage. Avec un cookie HttpOnly, il ne PEUT PAS l'effacer
// lui-même — c'est précisément ce qui le protège.
//
// Sans cette route, se déconnecter laisserait la session ouverte côté serveur.
// Sur un ordinateur partagé, la personne suivante reprendrait le compte.
//
// Aucune authentification requise : effacer un cookie qu'on possède déjà ne
// demande pas de prouver qui l'on est, et exiger un jeton valide empêcherait
// de se déconnecter d'une session expirée.
// ═══════════════════════════════════════════════════════════════════════════
app.post('/api/auth/logout', (req, res) => {
  // Les options doivent correspondre à celles de la pose, sinon le navigateur
  // considère qu'il s'agit d'un autre cookie et garde le premier.
  res.clearCookie(COOKIE_JETON, {
    httpOnly: true, secure: true, sameSite: 'none', path: '/'
  });
  res.json({ message: 'Déconnecté.' });
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email et mot de passe requis.' });

    const { data, error } = await supabaseAuth.auth.signInWithPassword({
      email: email.toLowerCase().trim(),
      password: password
    });
    // La session est refermée aussitôt : on n'a besoin que de la vérification du
    // mot de passe, jamais de rester connecté au nom de cette personne. Le champ
    // scope reste local — un signOut global révoquerait les jetons de rafraîchissement
    // de l'utilisateur sur tous ses appareils.
    await supabaseAuth.auth.signOut({ scope: 'local' }).catch(() => {});
    if (error) return res.status(401).json({ error: 'Identifiants incorrects.' });

    let { data: user } = await supabase.from('users').select('*').eq('id', data.user.id).single();
    if (!user) {
      const { data: newUser } = await supabase.from('users').insert({
        id: data.user.id, email: data.user.email, prenom: data.user.email.split('@')[0], nom: '', type: 'client', disponible: true
      }).select().single();
      user = newUser;
    }
    if (!user) return res.status(500).json({ error: 'Ce compte n\'existe plus. S\'il s\'agit du vôtre, reconnectez-vous ; sinon, la personne a supprimé son compte.' });

    const token = jwt.sign({ id: user.id, email: user.email, type: user.type }, process.env.JWT_SECRET, { expiresIn: '7d' });
    // Le jeton part AUSSI en cookie HttpOnly : le JavaScript ne peut pas le lire,
    // donc une faille XSS ne le vole plus. Il reste dans la réponse le temps que
    // les sessions déjà ouvertes migrent.
    res.cookie(COOKIE_JETON, token, OPTIONS_COOKIE);
    res.json({ token, user: { ...compteVisible(user),
                              firstName: user.prenom, lastName: user.nom } });
  } catch (e) {
    console.error(e);
    erreurServeur(res, 'POST /api/auth/login', e);
  }
});

// Notre propre système de réinitialisation de mot de passe, plutôt que de dépendre du lien
// automatique de Supabase (dont le format exact — jeton dans le fragment d'URL, ou code dans les
// paramètres — s'est révélé peu fiable à détecter côté navigateur). Un code à 6 chiffres, envoyé
// par notre propre système d'email, saisi directement dans l'app : plus simple, plus prévisible,
// et cohérent avec le code de validation de fin de prestation déjà utilisé ailleurs dans Gleam.
app.post('/api/auth/forgot-password', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email requis.' });

    const { data: user } = await supabase.from('users').select('id, prenom, email').eq('email', email.toLowerCase().trim()).maybeSingle();
    // Réponse identique que le compte existe ou non, pour ne jamais révéler si un email est
    // inscrit chez Gleam (bonne pratique de sécurité classique).
    if (!user) return res.json({ message: 'Si ce compte existe, un email a été envoyé.' });

    const code = codeSecret6();
    const expiration = new Date(Date.now() + 30 * 60 * 1000).toISOString(); // valable 30 minutes
    // On stocke l'EMPREINTE, jamais le code. Le compteur repart à zéro : une
    // nouvelle demande annule les tentatives de la précédente.
    await supabase.from('users').update({
      reset_code: empreinteCode(code),
      reset_code_expire: expiration,
      reset_tentatives: 0
    }).eq('id', user.id);

    sendEmail('reinitialisation_mot_de_passe', user.email, { compteId: user.id, prenom: user.prenom || '', code }).catch(e => console.error('Email réinitialisation:', e));

    res.json({ message: 'Si ce compte existe, un email a été envoyé.' });
  } catch (e) {
    console.error('Erreur mot de passe oublié:', e);
    erreurServeur(res, 'POST /api/auth/forgot-password', e);
  }
});

app.post('/api/auth/reset-password', authLimiter, async (req, res) => {
  try {
    const { email, code, new_password } = req.body;
    if (!email || !code || !new_password) return res.status(400).json({ error: 'Informations manquantes.' });
    if (new_password.length < 8) return res.status(400).json({ error: 'Mot de passe : 8 caractères minimum.' });

    const { data: user } = await supabase.from('users')
      .select('id, reset_code, reset_code_expire, reset_tentatives')
      .eq('email', email.toLowerCase().trim()).maybeSingle();

    // ── CINQ TENTATIVES, PAS PLUS ───────────────────────────────────────
    // Un code à six chiffres, c'est un million de possibilités. La limitation
    // de débit ralentit ; un compteur par compte arrête net.
    //
    // Au cinquième échec le code est détruit : il faut en redemander un. Le
    // message reste volontairement identique à celui d'un code faux, pour ne
    // pas indiquer à un attaquant qu'il approchait du but.
    if (user && user.reset_code && (user.reset_tentatives || 0) >= 5) {
      await supabase.from('users')
        .update({ reset_code: null, reset_code_expire: null, reset_tentatives: 0 })
        .eq('id', user.id);
      return res.status(400).json({
        error: 'Ce code ne correspond pas. Refaites une demande de « mot de passe oublié ».'
      });
    }

    // On compare des EMPREINTES : le code en clair ne se trouve nulle part en
    // base, et le serveur n'a jamais besoin de le connaître.
    const codeCorrect = user && user.reset_code
      && user.reset_code === empreinteCode(code);

    if (user && user.reset_code && !codeCorrect) {
      // Chaque échec compte. Sans await : un compteur qui échoue ne doit pas
      // transformer un code faux en erreur serveur.
      supabase.from('users')
        .update({ reset_tentatives: (user.reset_tentatives || 0) + 1 })
        .eq('id', user.id).then(() => {}, () => {});
    }

    if (!codeCorrect)
      return res.status(400).json({ error: 'Ce code ne correspond pas. Vérifiez les six chiffres auprès du client — ils figurent dans son application.' });
    if (!user.reset_code_expire || new Date(user.reset_code_expire) < new Date())
      return res.status(400).json({ error: 'Ce code a expiré. Refaites une demande de "mot de passe oublié".' });

    const { error: erreurMaj } = await supabase.auth.admin.updateUserById(user.id, { password: new_password });
    if (erreurMaj) return res.status(400).json({ error: erreurMaj.message });

    await supabase.from('users').update({ reset_code: null, reset_code_expire: null, reset_tentatives: 0 }).eq('id', user.id);

    res.json({ message: 'Mot de passe mis à jour avec succès !' });
  } catch (e) {
    console.error('Erreur réinitialisation mot de passe:', e);
    erreurServeur(res, 'POST /api/auth/reset-password', e);
  }
});


app.get('/api/auth/me', auth, async (req, res) => {
  const { data } = await supabase.from('users').select('*').eq('id', req.user.id).single();
  if (!data) return res.status(404).json({ error: 'Ce compte n\'existe plus. S\'il s\'agit du vôtre, reconnectez-vous ; sinon, la personne a supprimé son compte.' });
  // La colonne contient un chemin depuis la migration : on le signe pour que
  // l'application puisse afficher l'image. Une ancienne valeur en base64 passe
  // telle quelle, sans conversion.
  const photoAffichable = data.photo ? await lienPhotoProfil(data.photo) : null;
  res.json({ ...compteVisible(data), photo: photoAffichable,
             firstName: data.prenom, lastName: data.nom });
});

// Fournit la clé publique VAPID au frontend, nécessaire pour s'abonner aux notifications push —
// cette clé est publique par nature (contrairement à la clé privée), aucun risque à la partager.
app.get('/api/push/vapid-public-key', (req, res) => {
  res.json({ publicKey: process.env.VAPID_PUBLIC_KEY || null });
});

// Enregistre un nouvel abonnement aux notifications (un par appareil/navigateur) — remplace
// silencieusement un abonnement existant avec le même endpoint plutôt que d'en créer un doublon.
app.post('/api/push/subscribe', auth, async (req, res) => {
  try {
    const { endpoint, keys, plateforme, jeton_natif } = req.body;

    // Deux formes d'abonnement arrivent sur cette route. Le navigateur envoie un
    // endpoint et deux clés de chiffrement ; une application iOS ou Android
    // envoie un simple jeton d'appareil, sans clés. Les distinguer ici évite une
    // seconde route et une seconde table à tenir synchronisées.
    if (plateforme === 'ios' || plateforme === 'android') {
      if (!jeton_natif) return res.status(400).json({ error: 'Jeton d\'appareil manquant.' });
      await supabase.from('push_subscriptions').upsert({
        user_id: req.user.id, plateforme, jeton_natif,
        endpoint: null, keys_p256dh: null, keys_auth: null
      }, { onConflict: 'jeton_natif' });
      console.log('🔔 Appareil ' + plateforme + ' enregistré pour ' + req.user.id);
      return res.json({ message: 'Notifications activées.' });
    }

    if (!endpoint || !keys || !keys.p256dh || !keys.auth) return res.status(400).json({ error: 'Abonnement invalide.' });
    await supabase.from('push_subscriptions').upsert({
      user_id: req.user.id, plateforme: 'web', endpoint, keys_p256dh: keys.p256dh, keys_auth: keys.auth
    }, { onConflict: 'endpoint' });
    res.json({ message: 'Notifications activées.' });
  } catch (e) {
    erreurServeur(res, 'POST /api/push/subscribe', e);
  }
});

// Retire un abonnement (désactivation depuis le profil, ou déconnexion)
app.post('/api/push/unsubscribe', auth, async (req, res) => {
  try {
    const { endpoint } = req.body;
    if (endpoint) await supabase.from('push_subscriptions').delete().eq('endpoint', endpoint).eq('user_id', req.user.id);
    res.json({ message: 'Notifications désactivées.' });
  } catch (e) {
    erreurServeur(res, 'POST /api/push/unsubscribe', e);
  }
});

// Permet de renseigner un code de parrainage après l'inscription (par exemple si on a reçu le
// code d'un ami après coup) — uniquement possible tant qu'aucun parrain n'est déjà renseigné, et
// tant qu'aucun paiement n'a encore été effectué (la récompense se déclenche au premier paiement,
// ce serait donc déjà trop tard si un paiement a déjà eu lieu sans code de parrainage).
app.post('/api/parrainage/renseigner-code', auth, async (req, res) => {
  try {
    const code = (req.body.code || '').trim().toUpperCase();
    if (!code) return res.status(400).json({ error: 'Saisissez le code de validation que le client vous a communiqué à la fin de la prestation.' });

    const { data: moi } = await supabase.from('users').select('parraine_par, code_parrainage').eq('id', req.user.id).single();
    if (!moi) return res.status(404).json({ error: 'Ce compte n\'existe plus. S\'il s\'agit du vôtre, reconnectez-vous ; sinon, la personne a supprimé son compte.' });
    if (moi.parraine_par) return res.status(400).json({ error: 'Un parrain est déjà associé à votre compte.' });
    if (moi.code_parrainage === code) return res.status(400).json({ error: 'Vous ne pouvez pas utiliser votre propre code.' });

    const { count: nbPaiements } = await supabase.from('paiements').select('id', { count: 'exact', head: true })
      .eq('client_id', req.user.id).in('statut', ['paye', 'libere', 'rembourse_partiel']);
    if (nbPaiements && nbPaiements > 0)
      return res.status(400).json({ error: 'Un code de parrainage doit être renseigné avant votre premier paiement.' });

    const { data: parrain } = await supabase.from('users').select('id').eq('code_parrainage', code).maybeSingle();
    if (!parrain) return res.status(404).json({ error: 'Code de parrainage introuvable.' });

    await supabase.from('users').update({ parraine_par: parrain.id }).eq('id', req.user.id);
    res.json({ message: 'Code de parrainage enregistré ! La réduction s\'appliquera dès votre première prestation payée.' });
  } catch (e) {
    erreurServeur(res, 'POST /api/parrainage/renseigner-code', e);
  }
});

// Mémorise l'adresse d'intervention préférée d'un client, pour pré-remplir ses prochaines
// demandes — une seule adresse mémorisée à la fois, volontairement simple. Le client garde
// toujours la possibilité de saisir une adresse différente à tout moment, jamais verrouillée.
app.post('/api/client/adresse-memorisee', auth, async (req, res) => {
  try {
    const { adresse, ville, latitude, longitude } = req.body;
    if (!adresse || !ville) return res.status(400).json({ error: 'Adresse et ville requises.' });
    await supabase.from('users').update({
      adresse_memorisee: adresse,
      ville_memorisee: ville,
      latitude_memorisee: (typeof latitude === 'number' && !isNaN(latitude)) ? latitude : null,
      longitude_memorisee: (typeof longitude === 'number' && !isNaN(longitude)) ? longitude : null
    }).eq('id', req.user.id);
    res.json({ message: 'Adresse mémorisée.' });
  } catch (e) {
    erreurServeur(res, 'POST /api/client/adresse-memorisee', e);
  }
});

// Vérifie le code de confirmation d'email — n'importe qui de connecté peut confirmer son propre
// compte, à tout moment (pas de blocage d'accès en attendant, conformément aux bonnes pratiques
// actuelles : la vérification email se fait en tâche de fond, jamais en barrage à l'entrée).
app.post('/api/auth/verifier-email', auth, async (req, res) => {
  try {
    const code = (req.body.code || '').trim();
    if (!code) return res.status(400).json({ error: 'Saisissez le code de validation que le client vous a communiqué à la fin de la prestation.' });

    const { data: moi } = await supabase.from('users').select('email_verifie, email_verif_code, email_verif_expire').eq('id', req.user.id).single();
    if (!moi) return res.status(404).json({ error: 'Ce compte n\'existe plus. S\'il s\'agit du vôtre, reconnectez-vous ; sinon, la personne a supprimé son compte.' });
    if (moi.email_verifie) return res.json({ message: 'Votre email est déjà confirmé.' });
    if (!moi.email_verif_code || moi.email_verif_code !== code)
      return res.status(400).json({ error: 'Ce code ne correspond pas. Vérifiez les six chiffres auprès du client — ils figurent dans son application.' });
    if (moi.email_verif_expire && new Date(moi.email_verif_expire) < new Date())
      return res.status(400).json({ error: 'Ce code a expiré, demandez-en un nouveau.' });

    await supabase.from('users').update({ email_verifie: true, email_verif_code: null }).eq('id', req.user.id);
    res.json({ message: 'Email confirmé, merci !' });
  } catch (e) {
    erreurServeur(res, 'POST /api/auth/verifier-email', e);
  }
});

// Renvoie un nouveau code si l'ancien a expiré ou n'a jamais été reçu
app.post('/api/auth/renvoyer-code-verification', auth, async (req, res) => {
  try {
    const { data: moi } = await supabase.from('users').select('email, prenom, email_verifie').eq('id', req.user.id).single();
    if (!moi) return res.status(404).json({ error: 'Ce compte n\'existe plus. S\'il s\'agit du vôtre, reconnectez-vous ; sinon, la personne a supprimé son compte.' });
    if (moi.email_verifie) return res.json({ message: 'Votre email est déjà confirmé.' });

    const nouveauCode = codeSecret6();
    const nouvelleExpiration = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    await supabase.from('users').update({ email_verif_code: nouveauCode, email_verif_expire: nouvelleExpiration }).eq('id', req.user.id);
    sendEmail('verification_email', moi.email, { compteId: moi.id, prenom: moi.prenom, code: nouveauCode });
    res.json({ message: 'Un nouveau code vous a été envoyé par email.' });
  } catch (e) {
    erreurServeur(res, 'POST /api/auth/renvoyer-code-verification', e);
  }
});
// ═══════════════════════════════════════════════════════════════════════════
// LES PHOTOS DE PROFIL VONT DANS LE STOCKAGE, PLUS DANS LA BASE
//
// Une photo en base64 dans users.photo pesait jusqu'à 48 Ko. Chaque lecture de
// la table les emportait — et les listes sont sondées toutes les 15 secondes.
// Relevé : 787 062 lignes lues, environ 8,6 Go sur un quota de 5,5.
//
// La colonne ne contient plus qu'un chemin : "uuid/avatar-1786261371.jpg".
// Soixante caractères au lieu de dix mille.
// ═══════════════════════════════════════════════════════════════════════════

const COMPARTIMENT_PHOTOS = 'photos-profil';

// Signe les photos d'un lot de personnes, en parallèle.
//
// C'est ce qui rend possible de RENDRE la photo aux listes : depuis qu'elles
// sont dans le stockage, la colonne ne contient qu'un chemin, et un lien signé
// pèse environ 200 octets. Avant la migration, chaque photo pesait 10 Ko en
// base64 — c'est ce qui avait épuisé le quota.
//
// Les signatures partent ensemble : les faire une par une ajouterait autant
// d'allers-retours que de prestataires.
async function signerPhotosDeLot(personnes) {
  if (!personnes || !personnes.length) return personnes;
  await Promise.all(personnes.map(async (p) => {
    if (p && p.photo) {
      try { p.photo = await lienPhotoProfil(p.photo); }
      catch (e) { p.photo = null; }   // une photo absente vaut mieux qu'une liste absente
    }
  }));
  return personnes;
}

// Reconnaît une ancienne valeur base64, pour continuer à la servir telle quelle.
function estPhotoBase64(v) {
  return typeof v === 'string' && v.startsWith('data:image/');
}

// Transforme ce que contient la colonne en quelque chose que l'application peut
// afficher : un lien signé pour un chemin, la valeur elle-même pour une base64.
async function lienPhotoProfil(valeur) {
  if (!valeur) return null;
  if (estPhotoBase64(valeur)) return valeur;   // ancienne photo, pas encore migrée
  try {
    const { data, error } = await supabase.storage
      .from(COMPARTIMENT_PHOTOS)
      .createSignedUrl(valeur, 3600);   // une heure : la photo change rarement
    if (error) return null;
    return data && data.signedUrl ? data.signedUrl : null;
  } catch (e) {
    // Une photo qu'on ne peut pas signer ne doit jamais empêcher de charger un
    // profil : l'application affiche l'initiale, ce qu'elle sait déjà faire.
    console.error('Signature photo profil:', e.message);
    return null;
  }
}

app.patch('/api/users/photo', auth, async (req, res) => {
  try {
    const { photo } = req.body;
    const format = /^data:image\/(jpeg|jpg|png|webp);base64,/.exec(photo || '');
    if (!photo || typeof photo !== 'string' || !format) {
      return res.status(400).json({ error: 'Format d\'image non supporté (JPEG, PNG ou WEBP uniquement).' });
    }
    if (photo.length > 600 * 1024) {
      return res.status(413).json({ error: 'Photo trop volumineuse. Réessayez avec une image plus légère.' });
    }

    const extension = format[1] === 'jpg' ? 'jpeg' : format[1];
    const binaire = Buffer.from(photo.split(',')[1] || '', 'base64');
    if (!binaire.length) return res.status(400).json({ error: 'Image illisible.' });

    // Le nom porte un horodatage : sans lui, le navigateur garderait l'ancienne
    // image en cache et le changement de photo paraîtrait sans effet.
    const chemin = req.user.id + '/avatar-' + Date.now() + '.' + extension;

    const { error: erreurEnvoi } = await supabase.storage
      .from(COMPARTIMENT_PHOTOS)
      .upload(chemin, binaire, { contentType: 'image/' + extension, upsert: true });
    if (erreurEnvoi) {
      console.error('Envoi photo profil:', erreurEnvoi);
      return res.status(400).json({ error: 'La photo n\'a pas pu être enregistrée.' });
    }

    // L'ancienne photo est retirée APRÈS que la nouvelle est en place : si
    // l'envoi échoue, l'utilisateur garde celle qu'il avait.
    const { data: avant } = await supabase.from('users').select('photo').eq('id', req.user.id).maybeSingle();

    const { error } = await supabase.from('users').update({ photo: chemin }).eq('id', req.user.id);
    if (error) {
      console.error('Erreur Supabase, message technique complet:', error);
      return res.status(400).json({ error: traduireErreurSupabase(error.message) });
    }

    if (avant && avant.photo && !estPhotoBase64(avant.photo) && avant.photo !== chemin) {
      supabase.storage.from(COMPARTIMENT_PHOTOS).remove([avant.photo])
        .catch(e => console.error('Nettoyage ancienne photo:', e.message));
    }

    res.json({ message: 'Photo mise à jour.', photo: await lienPhotoProfil(chemin) });
  } catch (e) {
    erreurServeur(res, 'PATCH /api/users/photo', e);
  }
});

// Suppression de compte (droit à l'effacement RGPD) : anonymise les données personnelles
// identifiantes plutôt qu'une suppression brute, pour préserver l'historique des transactions
// (nécessaire pour la comptabilité, le suivi de fiabilité, et les litiges éventuels), tout en
// révoquant définitivement l'accès de connexion — cohérent avec l'approche "archiver plutôt
// que supprimer" déjà retenue ailleurs dans l'app.
// ══════════════════════════════════════════════════════════════════════════
// EXPORT RGPD — ARTICLE 20, DROIT À LA PORTABILITÉ
//
// Chaque utilisateur peut récupérer ses données dans un format lisible par
// machine. Le délai légal de réponse est d'un mois ; cette route répond en
// quelques secondes.
//
// Limitée à 3 exports par heure : une demande de portabilité est un acte
// rare, et la route lit neuf tables d'un coup.
// ══════════════════════════════════════════════════════════════════════════
const exportLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 3, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Vous avez déjà demandé vos données récemment. Réessayez dans une heure.' }
});

app.get('/api/users/me/donnees', auth, exportLimiter, async (req, res) => {
  try {
    const moi = req.user.id;
    const lire = async (table, filtre) => {
      try {
        let q = supabase.from(table).select('*');
        q = filtre(q);
        const { data } = await q;
        return data || [];
      } catch (e) {
        console.error('Export RGPD, table ' + table + ' :', e.message);
        return [];
      }
    };

    const [profil, demandes, devis, messages, paiementsClient, paiementsPro,
           evalDonnees, evalRecues, favoris, documents, notifications] = await Promise.all([
      lire('users',        q => q.eq('id', moi)),
      lire('demandes',     q => q.eq('client_id', moi)),
      lire('devis',        q => q.eq('societe_id', moi)),
      // Uniquement les messages ÉCRITS par l'utilisateur. Exporter les
      // réponses de l'autre partie divulguerait les données d'un tiers :
      // ce serait une violation du RGPD, pas une conformité.
      lire('messages',     q => q.eq('expediteur_id', moi)),
      lire('paiements',    q => q.eq('client_id', moi)),
      lire('paiements',    q => q.eq('societe_id', moi)),
      lire('evaluations',  q => q.eq('evaluateur_id', moi)),
      lire('evaluations',  q => q.eq('evalue_id', moi)),
      lire('favoris',      q => q.or('client_id.eq.' + moi + ',pro_id.eq.' + moi)),
      lire('documents_pro',q => q.eq('pro_id', moi)),
      lire('push_subscriptions', q => q.eq('user_id', moi))
    ]);

    // Les champs internes n'ont aucun sens hors du système et exposeraient sa
    // structure. On les retire de l'export.
    const nettoyer = (lignes, aRetirer) => (lignes || []).map(l => {
      const copie = Object.assign({}, l);
      (aRetirer || []).forEach(c => { delete copie[c]; });
      return copie;
    });

    const p = (profil || [])[0] || {};

    res.setHeader('Content-Disposition',
      'attachment; filename="mes-donnees-gleam-' + new Date().toISOString().slice(0, 10) + '.json"');
    res.json({
      _a_propos: {
        genere_le: new Date().toISOString(),
        fondement: 'Article 20 du RGPD — droit à la portabilité des données',
        format: 'JSON, structuré et lisible par machine',
        remarque: "Cet export contient les données que vous avez fournies ou générées. " +
                  "Les messages reçus d'autres utilisateurs ne sont pas inclus : ils " +
                  "contiennent les données personnelles de tiers."
      },
      profil: {
        prenom: p.prenom, nom: p.nom, email: p.email, telephone: p.telephone,
        type: p.type, adresse: p.adresse, siret: p.siret,
        raison_sociale: p.raison_sociale, note_moyenne: p.note_moyenne,
        inscrit_le: p.created_at
      },
      demandes:            nettoyer(demandes, ['client_id']),
      devis_envoyes:       nettoyer(devis, ['societe_id']),
      messages_envoyes:    nettoyer(messages, ['expediteur_id']),
      paiements_effectues: nettoyer(paiementsClient, ['client_id', 'societe_id', 'stripe_payment_intent_id']),
      paiements_recus:     nettoyer(paiementsPro, ['client_id', 'societe_id', 'stripe_payment_intent_id']),
      evaluations_donnees: nettoyer(evalDonnees, ['evaluateur_id', 'evalue_id']),
      evaluations_recues:  nettoyer(evalRecues, ['evaluateur_id', 'evalue_id']),
      favoris:             nettoyer(favoris, ['client_id', 'pro_id']),
      // Les documents sont des fichiers : on liste ce qu'ils sont et quand ils
      // ont été déposés, pas leur contenu binaire.
      documents_deposes: (documents || []).map(d => ({
        type: d.type, statut: d.statut, depose_le: d.created_at,
        expire_le: d.date_expiration
      })),
      appareils_notifies: (notifications || []).length
    });
  } catch (e) {
    console.error('Erreur export RGPD:', e);
    res.status(500).json({ error: 'Impossible de générer vos données pour le moment.' });
  }
});

app.post('/api/users/me/supprimer', auth, async (req, res) => {
  try {
    // Bloque la suppression tant qu'une prestation active (payée, en cours, ou en attente de
    // paiement) existe pour ce compte — que ce soit en tant que client ou en tant que prestataire.
    // Sans ce garde-fou, un pro pourrait disparaître en plein milieu d'une prestation payée.
    const { data: demandesActivesClient } = await supabase.from('demandes').select('id').eq('client_id', req.user.id).in('statut', ['acceptee', 'en_cours']);
    if (demandesActivesClient && demandesActivesClient.length) {
      return res.status(400).json({ error: 'Vous avez une prestation en cours ou en attente de paiement. Terminez-la ou annulez-la avant de supprimer votre compte.' });
    }
    const { data: devisActifsProResult } = await supabase.from('devis').select('demande_id').eq('societe_id', req.user.id).eq('statut', 'accepte');
    if (devisActifsProResult && devisActifsProResult.length) {
      const demandeIdsActifs = devisActifsProResult.map(d => d.demande_id);
      const { data: demandesActivesPro } = await supabase.from('demandes').select('id').in('id', demandeIdsActifs).in('statut', ['acceptee', 'en_cours']);
      if (demandesActivesPro && demandesActivesPro.length) {
        return res.status(400).json({ error: 'Vous avez une prestation en cours chez un client. Terminez-la ou annulez-la avant de supprimer votre compte.' });
      }
    }

    const anonEmail = `compte-supprime-${req.user.id}@gleam-deleted.local`;
    const { error } = await supabase.from('users').update({
      email: anonEmail,
      prenom: 'Compte',
      nom: 'supprimé',
      telephone: null,
      photo: null,
      disponible: false,
      compte_supprime: true
    }).eq('id', req.user.id);
    if (error) { console.error('Erreur Supabase, message technique complet:', error); return res.status(400).json({ error: traduireErreurSupabase(error.message) }); }

    // Révoque l'accès de connexion (best-effort : n'empêche pas la suppression si ça échoue)
    try { await supabase.auth.admin.deleteUser(req.user.id); } catch (e) { console.error('Suppression auth:', e); }

    res.json({ message: 'Compte supprimé.' });
  } catch (e) {
    erreurServeur(res, 'POST /api/users/me/supprimer', e);
  }
});

// ══════════════ DEMANDES ══════════════

// ═══════════════════════════════════════════════════════════════════════════
// JUSQU'À QUAND LE FAVORI GARDE-T-IL LA DEMANDE POUR LUI ?
//
// Une durée FIXE serait fausse la moitié du temps :
//
//   demande pour dans trois jours   six heures, c'est confortable
//   demande pour demain matin       six heures, c'est déjà trop tard
//
// On prend donc un QUART du temps restant avant le créneau, plafonné à douze
// heures et planché à trente minutes.
//
//   créneau dans 4 h    →  1 h d'exclusivité
//   créneau dans 3 j    →  12 h (le plafond)
//   créneau dans 1 h    →  30 min (le plancher)
//
// Le plancher compte : sans lui, une demande pour dans dix minutes s'ouvrirait
// à tous instantanément, et le choix du client n'aurait servi à rien.
// ═══════════════════════════════════════════════════════════════════════════
function finExclusivite(creneauTexte) {
  const maintenant = Date.now();
  const creneau = instantDuCreneau(creneauTexte);

  // Créneau illisible ou déjà passé : on retombe sur le plafond, plutôt que
  // de calculer sur une valeur qu'on ne comprend pas.
  if (!creneau || creneau <= maintenant) {
    return new Date(maintenant + 12 * 3600 * 1000).toISOString();
  }
  const restant = creneau - maintenant;
  const quart = Math.floor(restant / 4);
  const duree = Math.min(Math.max(quart, 30 * 60 * 1000), 12 * 3600 * 1000);
  return new Date(maintenant + duree).toISOString();
}

// Le créneau est stocké en texte lisible — « 2026-08-25 à 9h00 ». On en tire
// un instant, ou null si la forme est inattendue.
function instantDuCreneau(texte) {
  if (!texte) return null;
  const m = String(texte).match(/(\d{4})-(\d{2})-(\d{2})\D+(\d{1,2})h(\d{2})/);
  if (!m) return null;
  const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]),
                     Number(m[4]), Number(m[5]));
  return isNaN(d.getTime()) ? null : d.getTime();
}

app.post('/api/demandes', auth, async (req, res) => {
  try {
    const { type, prestations, address, date, time, flexibility, description, details, photos, pro_prefere_id, latitude, longitude, recurrence } = req.body;
    if (!address) return res.status(400).json({ error: 'Indiquez l\'adresse où doit avoir lieu la prestation.' });
    const erreurCreneau = validerCreneauFutur(date, time);
    if (erreurCreneau) return res.status(400).json({ error: erreurCreneau });
    // La récurrence ne nécessite plus un favori précis : sans favori choisi, la prochaine
    // Le délai entre deux occurrences est maintenant un nombre de jours librement choisi par le
    // client (7, 14, 30, 90...), plutôt que 3 fréquences fixes qui ne convenaient pas à toutes
    // les prestations (on ne nettoie pas une voiture aussi souvent qu'un ménage classique). Borné
    // entre 3 jours et 1 an pour rester raisonnable, sans imposer de valeurs prédéfinies.
    const recurrenceValide = (Number.isInteger(recurrence) && recurrence >= 3 && recurrence <= 365) ? recurrence : null;
    if (photos && Array.isArray(photos)) {
      if (photos.length > 5) return res.status(400).json({ error: 'Maximum 5 photos par demande.' });
      for (const p of photos) {
        if (typeof p !== 'string' || !/^data:image\/(jpeg|jpg|png|webp);base64,/.test(p)) {
          return res.status(400).json({ error: 'Format de photo non supporté (JPEG, PNG ou WEBP uniquement).' });
        }
        if (p.length > 800 * 1024) {  // 800 ko : une demande reste sous 4 Mo au total
          return res.status(400).json({ error: 'Une photo est trop volumineuse. Réessayez avec une photo plus légère.' });
        }
      }
    }

    // Si le client cible un prestataire favori, on vérifie que c'est bien un pro existant —
    // la demande ne sera alors visible que pour lui (voir /api/demandes/all).
    let proPrefereValide = null;
    if (pro_prefere_id) {
      const { data: proCible } = await supabase.from('users').select('id, type').eq('id', pro_prefere_id).single();
      if (proCible && isProType(proCible.type)) proPrefereValide = proCible.id;
    }

    const numero = 'Client #' + Math.floor(1000 + Math.random() * 9000);
    const creneau = date && time ? date + ' à ' + time : null;

    // Supporte soit une liste de prestations (nouveau format groupé), soit une seule (ancien format)
    const listePrestations = prestations && Array.isArray(prestations) && prestations.length
      ? prestations
      : [{ type: type || 'autre', description: description || '', details: details || {} }];

    const prestationLabel = listePrestations.map(p => p.type).join(' + ');

    // Les photos partent dans le dépôt de fichiers ; seuls leurs chemins sont
    // conservés en base. Le dossier est tiré au hasard : l'identifiant de la
    // demande n'existe pas encore à cet instant, et un chemin devinable serait
    // de toute façon inutile puisque le dépôt est privé.
    // ── DIX DEMANDES ACTIVES AU MAXIMUM ─────────────────────────────────
    // Un doigt qui reste appuyé, une connexion instable qui fait renvoyer le
    // formulaire — et cinquante demandes partent. Vos prestataires reçoivent
    // cinquante notifications et chiffrent cinquante devis dont quarante-neuf
    // ne serviront à rien.
    //
    // Ce n'est pas la malveillance qu'on arrête, c'est l'accident.
    const { count: actives } = await supabase.from('demandes')
      .select('id', { count: 'exact', head: true })
      .eq('client_id', req.user.id)
      .in('statut', ['en_attente', 'devis_recus', 'acceptee', 'en_cours']);

    if ((actives || 0) >= 10) {
      return res.status(409).json({
        error: 'Vous avez déjà dix demandes en cours. Terminez-en ou annulez-en '
             + 'une avant d\'en créer une nouvelle.'
      });
    }

    // ── LA MÊME DEMANDE, DEUX FOIS ──────────────────────────────────────
    // Le client ne voit pas la confirmation sur un réseau instable, alors il
    // recommence. Les prestataires voient deux fois la même demande, et le
    // client se retrouve avec deux devis pour un seul besoin.
    //
    // Deux minutes : au-delà, une demande identique est probablement voulue —
    // deux voitures à nettoyer au même endroit, par exemple.
    const ilYaDeuxMinutes = new Date(Date.now() - 2 * 60 * 1000).toISOString();
    const { data: doublon } = await supabase.from('demandes')
      .select('id')
      .eq('client_id', req.user.id)
      .eq('adresse', address)
      .eq('creneau', creneau)
      .gte('created_at', ilYaDeuxMinutes)
      .maybeSingle();

    if (doublon) {
      // On renvoie la demande EXISTANTE plutôt qu'une erreur : du point de vue
      // du client, sa demande est bien passée. Lui afficher un échec le ferait
      // recommencer une troisième fois.
      return res.json({ id: doublon.id, doublon_evite: true });
    }

    const dossierPhotos = 'demandes/' + crypto.randomUUID();
    const cheminsPhotos = await televerserPhotos(photos || [], dossierPhotos);

    const notes = JSON.stringify({ flexibility: flexibility || '', prestations: listePrestations, photos: cheminsPhotos });

    // ── LES COORDONNÉES, MÊME SANS AUTOCOMPLÉTION ────────────────────────
    // Elles viennent normalement du choix d'une suggestion d'adresse. Si le
    // client a tapé son adresse à la main, elles sont absentes — et sans
    // elles, la distance du prestataire à l'arrivée ne peut pas être vérifiée.
    //
    // On géocode donc au serveur. Si cela échoue, la demande part quand même
    // sans coordonnées : une panne de service tiers ne doit pas empêcher
    // quelqu'un de commander.
    let coordonnees = {
      latitude: (typeof latitude === 'number' && !isNaN(latitude)) ? latitude : null,
      longitude: (typeof longitude === 'number' && !isNaN(longitude)) ? longitude : null
    };
    if (coordonnees.latitude === null || coordonnees.longitude === null) {
      const trouve = await geocoderAdresse(address);
      if (trouve) {
        coordonnees = { latitude: trouve.latitude, longitude: trouve.longitude };
      }
    }

    const { data, error } = await supabase.from('demandes').insert({
      client_id: req.user.id,
      prestation: prestationLabel,
      adresse: address,
      creneau: creneau,
      notes: notes,
      numero_anonyme: numero,
      pro_prefere_id: proPrefereValide,
      // L'exclusivité n'a de sens que s'il y a un favori désigné.
      exclusivite_jusqu_a: proPrefereValide ? finExclusivite(creneau) : null,
      latitude: coordonnees.latitude,
      longitude: coordonnees.longitude,
      statut: 'en_attente',
      recurrence: recurrenceValide,
      recurrence_active: recurrenceValide ? true : null,
      recurrence_prochaine_creee: false
    }).select().single();

    if (error) { console.error('Erreur Supabase, message technique complet:', error); return res.status(400).json({ error: traduireErreurSupabase(error.message) }); }

    // 📧 Notification aux prestataires — réactivée, mais CIBLÉE.
    // Le bloc d'origine écrivait à tous les pros disponibles sans distinction de
    // zone ni de prestation, d'où sa mise en sommeil. prosConcernesParDemande()
    // applique désormais les mêmes règles que /api/demandes/all : un pro ne reçoit
    // un email que pour une demande qu'il verrait dans son application.
    //
    // Attendu, cette fois. Les envois d'emails restent asynchrones à l'intérieur :
    // seule la sélection des prestataires est attendue, soit deux requêtes.
    // Ce court délai achète une information que le client n'avait pas — savoir
    // si quelqu'un a seulement vu sa demande, au lieu de l'apprendre deux jours
    // plus tard, ou jamais.
    let envoi = { nb: 0, elargi: false };
    try {
      envoi = await notifierProsPourDemande(data, 'nouvelle_demande');
      if (envoi.nb > 0) {
        await supabase.from('demandes')
          .update({ notifiee_pros_le: new Date().toISOString() }).eq('id', data.id);
      }
    } catch (e) {
      console.error('Notification création:', e.message);
    }

    res.status(201).json({ ...data, prestataires_prevenus: envoi.nb, zone_elargie: envoi.elargi });
  } catch (e) {
    erreurServeur(res, 'POST /api/demandes', e);
  }
});

// Marque automatiquement comme "expirée" toute demande dont le créneau prévu est dépassé depuis
// plus de 3h, sans qu'aucun devis n'ait été accepté (ni payé) entre-temps — plutôt que de laisser
// une demande "en attente" ou "devis reçus" indéfiniment pour une date déjà passée, ce qui n'a plus
// aucun sens. Une marge de 3h est laissée pour ne pas être trop agressif (retard, confirmation
// tardive...). Fonctionne par lecture (pas de tâche planifiée à gérer) : vérifiée à chaque fois que
// les demandes sont consultées, sur le lot concerné uniquement — reste donc très léger.
//
// Couvre aussi le cas d'une demande "acceptée" (devis choisi par le client) mais jamais payée
// (carte bancaire jamais saisie) dont le créneau est également dépassé — sans quoi elle restait
// bloquée indéfiniment en "Accepté — Paiement requis", invisible à la fois pour le pro (qui ne
// peut plus rien en faire) et pour le client (qui ne pouvait pas la relancer, "acceptee" étant
// bloquée à la modification). Le devis correspondant est alors annulé pour rester cohérent.
// Quand une prestation récurrente est marquée terminée, recrée automatiquement la demande
// suivante à la bonne date, adressée au même prestataire favori — pas un abonnement prélevé à
// l'avance, juste un créneau qui se répète, payé prestation par prestation (même principe que
// le "ménage régulier" chez Wecasa, en plus simple : rien à gérer côté paiement à l'avance).
async function creerProchaineOccurrenceRecurrente(demandeId) {
  try {
    const { data: demande } = await supabase.from('demandes').select('*').eq('id', demandeId).single();
    if (!demande || !demande.recurrence || !demande.recurrence_active || demande.recurrence_prochaine_creee) return;

    const match = /(\d{4})-(\d{2})-(\d{2})\s*à\s*(\d{1,2})[h:](\d{2})/.exec(demande.creneau || '');
    if (!match) return;
    const joursAAjouter = parseInt(demande.recurrence, 10) || 7;
    // Les jours sont ajoutés au calendrier, pas en millisecondes : un rendez-vous de
    // 14h30 reste à 14h30 même quand la série traverse un changement d'heure. En
    // ajoutant des millisecondes, il devenait 13h30 ou 15h30 fin mars et fin octobre.
    const pad = n => String(n).padStart(2, '0');
    const base = new Date(Date.UTC(+match[1], +match[2] - 1, +match[3]));
    base.setUTCDate(base.getUTCDate() + joursAAjouter);
    const dateStr = base.getUTCFullYear() + '-' + pad(base.getUTCMonth() + 1) + '-' + pad(base.getUTCDate());
    const heureStr = pad(+match[4]) + 'h' + pad(+match[5]);

    await supabase.from('demandes').insert({
      client_id: demande.client_id,
      prestation: demande.prestation,
      adresse: demande.adresse,
      creneau: dateStr + ' à ' + heureStr,
      notes: demande.notes,
      numero_anonyme: 'Client #' + Math.floor(1000 + Math.random() * 9000),
      pro_prefere_id: demande.pro_prefere_id,
      latitude: demande.latitude,
      longitude: demande.longitude,
      statut: 'en_attente',
      recurrence: demande.recurrence,
      recurrence_active: true,
      recurrence_prochaine_creee: false
    });

    await supabase.from('demandes').update({ recurrence_prochaine_creee: true }).eq('id', demandeId);

    const { data: client } = await supabase.from('users').select('email, prenom').eq('id', demande.client_id).single();
    if (client) {
      sendEmail('prochaine_prestation_recurrente', client.email, {
        compteId: client.id,
        prenom: client.prenom, prestation: demande.prestation, date: dateStr, heure: heureStr
      }).catch(e => console.error('Email récurrence:', e));
    }
  } catch (e) {
    console.error('Erreur création occurrence récurrente:', e.message);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// CIBLAGE DES PRESTATAIRES
//
// Applique exactement les mêmes règles que /api/demandes/all, pour une raison
// simple : un pro ne doit jamais recevoir un email à propos d'une demande qu'il
// ne verrait pas en ouvrant l'application. L'inverse serait pire que le silence.
//
//   · disponible, et compte non supprimé
//   · prestations déclarées correspondant à la demande (si le pro en a déclaré)
//   · zone d'intervention couvrant l'adresse (si le pro l'a configurée)
//   · demande adressée à un favori : ce pro-là uniquement
//
// C'est ce ciblage qui rend la notification réactivable. Le bloc d'origine
// écrivait à tous les pros disponibles sans distinction — d'où sa mise en
// sommeil, justifiée à l'époque.
// ─────────────────────────────────────────────────────────────────────────────
const PLAFOND_PROS_NOTIFIES = 25;

// Plafond réduit lorsqu'on sort des zones déclarées. Prévenir vingt-cinq
// prestataires d'une demande hors de leur secteur reviendrait à leur envoyer du
// courrier indésirable ; dix, triés par proximité, reste une proposition.
const PLAFOND_PROS_ELARGI = 10;

// Plafond d'envois par passage du balayage. SendGrid facture au crédit et
// l'offre gratuite s'arrête à 100 emails par jour : sans borne, un seul
// balayage traitant 50 demandes × 25 prestataires pouvait tenter 1250 envois
// et épuiser le quota — ce qui s'est produit le 3 août, faisant ensuite échouer
// des emails vitaux comme la réinitialisation de mot de passe.
// Ce plafond protège les envois critiques, qui ne passent jamais par ici.
const PLAFOND_ENVOIS_PAR_PASSAGE = 40;
let envoisCePassage = 0;

// options.elargir : lève le filtre de zone. Les prestations déclarées, elles,
// restent respectées — proposer une toiture à quelqu'un qui ne fait que des
// canapés n'aiderait personne, quelle que soit la distance.
async function prosConcernesParDemande(demande, options) {
  const elargir = !!(options && options.elargir);
  // ⚠️ Le filtre sur le type est INDISPENSABLE ici. La colonne `disponible` vaut
  // true par défaut pour TOUS les comptes, clients compris : sans ce filtre, la
  // requête remonte l'intégralité des utilisateurs, et des clients reçoivent des
  // emails leur demandant d'envoyer un devis. C'est exactement ce qui s'est
  // produit le 3 août — 10 destinataires notifiés alors que la base ne compte
  // que 2 prestataires. Le bloc d'origine, lui, filtrait bien sur type='pro'.
  const { data: pros } = await supabase
    .from('users')
    .select('id, email, prenom, type, prestations_proposees, latitude, longitude, rayon_intervention_km, compte_supprime')
    .in('type', ['pro', 'societe', 'professionnel'])
    .eq('disponible', true);
  if (!pros || !pros.length) return [];

  const typesDemandes = extractPrestationTypes(demande);

  let retenus = pros.filter((pro) => {
    if (pro.compte_supprime) return false;
    if (!pro.email) return false;
    // Second garde-fou, volontairement redondant avec le filtre SQL ci-dessus :
    // ce sont des emails envoyés à des personnes réelles, une erreur ne se
    // rattrape pas.
    if (!isProType(pro.type)) return false;

    // Demande réservée à un prestataire favori : lui seul est concerné.
    if (demande.pro_prefere_id) return pro.id === demande.pro_prefere_id;

    // Prestations déclarées. Un pro qui n'a rien configuré continue de tout
    // recevoir, exactement comme il voit tout dans l'application.
    if (Array.isArray(pro.prestations_proposees) && pro.prestations_proposees.length) {
      const proposees = new Set(pro.prestations_proposees);
      // Même règle que pour la liste : « autre » n'est plus cochable dans les
      // tarifs, donc personne ne l'a déclarée. Sans cette ligne, une demande
      // « autre » ne déclencherait aucun courriel — elle arriverait dans
      // l'application sans que personne ne soit prévenu.
      proposees.add('autre');
      if (!typesDemandes.some((t) => proposees.has(t))) return false;
    }
    return true;
  });

  // Zone d'intervention, et tri par proximité : quand le plafond s'applique,
  // ce sont les plus proches qui sont prévenus.
  // Un prestataire explicitement désigné par le client échappe au filtre de zone :
  // c'est LUI que le client demande, la distance ne le regarde que lui. Sans cette
  // exception, une demande adressée à un favori situé hors de son rayon n'était
  // visible de personne — ni de lui (filtre de zone), ni des autres (filtre de
  // favori) — et expirait sans avoir jamais été vue.
  const estFavoriDesigne = !!demande.pro_prefere_id;

  retenus = retenus.map((pro) => {
    // En mode élargi, la zone n'est plus prise en compte : la distance reste
    // calculée et affichée, mais elle ne sert plus qu'à trier.
    const zoneReglee = !estFavoriDesigne && !elargir
      && typeof pro.latitude === 'number' && typeof pro.longitude === 'number'
      && typeof pro.rayon_intervention_km === 'number';
    if (!zoneReglee || typeof demande.latitude !== 'number' || typeof demande.longitude !== 'number') {
      return { ...pro, distance_km: null, zoneReglee };
    }
    const d = Math.round(distanceKm(pro.latitude, pro.longitude, demande.latitude, demande.longitude) * 10) / 10;
    return { ...pro, distance_km: d, zoneReglee };
  }).filter((pro) => !pro.zoneReglee || pro.distance_km === null || pro.distance_km <= pro.rayon_intervention_km);

  retenus.sort((a, b) => (a.distance_km ?? 9999) - (b.distance_km ?? 9999));
  return retenus.slice(0, elargir ? PLAFOND_PROS_ELARGI : PLAFOND_PROS_NOTIFIES);
}

// Envoie la notification correspondante. `gabarit` vaut 'nouvelle_demande' à la
// création, ou 'demande_sans_devis_pro' pour la relance à 24 h.
async function notifierProsPourDemande(demande, gabarit, options) {
  try {
    const elargir = !!(options && options.elargir);
    let pros = await prosConcernesParDemande(demande, { elargir });
    let aElargi = elargir;

    // Personne dans les zones déclarées : plutôt que de laisser la demande
    // mourir sans qu'aucun prestataire ne l'ait vue, on relance une fois sans
    // le filtre de zone. C'est le seul moyen qu'elle atteigne quelqu'un.
    if (!pros.length && !elargir) {
      pros = await prosConcernesParDemande(demande, { elargir: true });
      aElargi = pros.length > 0;
      if (aElargi) console.log('🔎 Aucun prestataire dans la zone — recherche élargie pour ' + demande.id);
    }

    if (!pros.length) {
      // Ni dans la zone, ni au-delà : aucun prestataire ne propose cette
      // prestation, ou aucun n'est disponible. C'est un manque d'offre, pas
      // un problème de rayon.
      console.warn('📭 AUCUN prestataire pour la demande ' + demande.id +
        ' (' + demande.prestation + ', ' + (demande.adresse || 'adresse inconnue') + ') — offre insuffisante.');
      return { nb: 0, elargi: false };
    }

    const relance = gabarit === 'demande_sans_devis_pro';
    const ville = (demande.adresse || '').split(',').pop().trim() || demande.adresse;

    for (const pro of pros) {
      if (envoisCePassage >= PLAFOND_ENVOIS_PAR_PASSAGE) {
        console.warn('⏸️  Plafond d\'envois atteint pour ce passage — le reste attendra le prochain.');
        break;
      }
      envoisCePassage++;
      sendEmail(gabarit, pro.email, {
        prenom: pro.prenom,
        prestation: demande.prestation,
        ville,
        distance: pro.distance_km,
        creneau: demande.creneau
      }).catch((e) => console.error('Email ' + gabarit + ':', e.message));

      envoyerNotificationPush(pro.id, {
        // Le titre annonce l'élargissement : recevoir une demande hors de sa
        // zone sans explication ressemblerait à un défaut de filtrage.
        titre: aElargi ? 'Demande hors de votre zone habituelle'
                       : (relance ? 'Demande toujours sans devis' : 'Nouvelle demande disponible'),
        corps: demande.prestation + ' à ' + ville + (pro.distance_km !== null ? ' — ' + pro.distance_km + ' km' : ''),
        url: '/'
      }).catch(() => {});
    }

    console.log('📨 ' + pros.length + ' prestataire(s) notifié(s)' + (aElargi ? ' [zone élargie]' : '') +
      ' — ' + gabarit + ' — demande ' + demande.id);
    // Un objet plutôt qu'un nombre : l'appelant a besoin de savoir non seulement
    // combien de prestataires ont été prévenus, mais s'il a fallu sortir de leur
    // zone pour y parvenir. Les deux informations se disent différemment au client.
    return { nb: pros.length, elargi: aElargi };
  } catch (e) {
    // Une notification qui échoue ne doit jamais faire échouer la création
    // d'une demande ni interrompre le balayage.
    console.error('Notification prestataires:', e.message);
    return { nb: 0, elargi: false };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// RELANCES
//
// Une demande sans devis mourait jusqu'ici en silence : ni le pro, ni le client
// n'apprenait quoi que ce soit avant l'expiration. Sur vos données, 19 demandes
// sur 52 ont connu ce sort.
//
// Les marqueurs en base garantissent qu'une relance part une fois : sans eux,
// ce balayage qui tourne toutes les 15 minutes la renverrait indéfiniment.
// ─────────────────────────────────────────────────────────────────────────────
async function relancerDemandesSansDevis() {
  try {
    envoisCePassage = 0;
    const ilYA = (h) => new Date(Date.now() - h * 3600 * 1000).toISOString();

    // — Relance aux prestataires, 24 h après publication —
    const { data: pourPros } = await supabase
      .from('demandes')
      .select('*')
      .eq('statut', 'en_attente')
      .is('relance_pro_le', null)
      .lt('created_at', ilYA(24))
      .limit(10);   // petits lots : le balayage repasse tous les quarts d'heure

    for (const demande of (pourPros || [])) {
      const { count } = await supabase.from('devis')
        .select('id', { count: 'exact', head: true }).eq('demande_id', demande.id);
      if (count && count > 0) continue;   // un devis est arrivé entre-temps

      // Élargissement d'office : si personne dans la zone n'a répondu en
      // vingt-quatre heures, réinterroger exactement les mêmes n'apporterait
      // rien. On sort du rayon, en restant plafonné à dix destinataires.
      await notifierProsPourDemande(demande, 'demande_sans_devis_pro', { elargir: true });
      await supabase.from('demandes')
        .update({ relance_pro_le: new Date().toISOString() }).eq('id', demande.id);
    }

    // — Message au client, 48 h après publication —
    const { data: pourClients } = await supabase
      .from('demandes')
      .select('*')
      .eq('statut', 'en_attente')
      .is('relance_client_le', null)
      .lt('created_at', ilYA(48))
      .limit(10);   // petits lots : le balayage repasse tous les quarts d'heure

    for (const demande of (pourClients || [])) {
      const { count } = await supabase.from('devis')
        .select('id', { count: 'exact', head: true }).eq('demande_id', demande.id);
      if (count && count > 0) continue;

      const { data: client } = await supabase.from('users')
        .select('email, prenom, compte_supprime').eq('id', demande.client_id).maybeSingle();

      if (client && client.email && !client.compte_supprime) {
        sendEmail('demande_sans_devis_client', client.email, {
          compteId: client.id,
          prenom: client.prenom,
          prestation: demande.prestation,
          demandeId: demande.id,
          creneau: demande.creneau
        }).catch((e) => console.error('Email relance client:', e.message));

        envoyerNotificationPush(demande.client_id, {
          titre: 'Votre demande attend toujours',
          corps: 'Élargir votre créneau augmenterait vos chances de recevoir un devis.',
          url: '/#devis'
        }).catch(() => {});
      }

      await supabase.from('demandes')
        .update({ relance_client_le: new Date().toISOString() }).eq('id', demande.id);
    }

    const total = (pourPros || []).length + (pourClients || []).length;
    if (total) console.log('🔔 Relances traitées : ' + total + ' demande(s).');
  } catch (e) {
    console.error('Relances:', e.message);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHOTOS — STOCKAGE DE FICHIERS
//
// Les photos étaient encodées en base64 dans des colonnes `text`. Sur cette
// base, une seule demande atteignait 282 ko : chaque lecture de la ligne
// transportait l'image entière, même pour afficher une simple liste.
//
// Le navigateur n'est pas modifié. Il envoie toujours du base64, et reçoit
// désormais des adresses https — <img src> accepte les deux sans distinction.
// Toute la bascule tient donc au serveur.
// ─────────────────────────────────────────────────────────────────────────────
const DEPOT_PHOTOS = 'photos-demandes';
const DUREE_LIEN_SIGNE = 3600;   // une heure, largement au-delà d'une session

function estBase64(v) { return typeof v === 'string' && v.startsWith('data:'); }
function estCheminDepot(v) {
  return typeof v === 'string' && !v.startsWith('data:') && !v.startsWith('http') && v.includes('/');
}

// Téléverse une image base64 et renvoie son chemin dans le dépôt.
// En cas d'échec, renvoie le base64 d'origine : une photo mal rangée vaut
// toujours mieux qu'une photo perdue.
// ─────────────────────────────────────────────────────────────────────────────
// DOCUMENTS DES PRESTATAIRES
// ─────────────────────────────────────────────────────────────────────────────
const DEPOT_DOCUMENTS = 'documents-pro';

// Chaque type porte son libellé, sa durée de validité et le fait qu'il soit
// exigé ou non. Une seule source de vérité, partagée par toutes les routes.
// `faces` liste ce qu'il faut photographier. Une carte d'identité recto seul ne
// prouve rien : la date d'expiration, l'adresse et la bande MRZ sont au verso.
// Les attestations, elles, tiennent sur une page.
const TYPES_DOCUMENTS = {
  identite:         { libelle: "Pièce d'identité",             requis: true,  mois_validite: null,
                      faces: ['recto', 'verso'] },
  immatriculation:  { libelle: "Justificatif d'immatriculation", requis: true,  mois_validite: 6,
                      faces: ['unique'] },
  rc_pro:           { libelle: "Attestation d'assurance RC Pro", requis: true,  mois_validite: null,
                      faces: ['unique'] },
  // Exigée par le Code du travail (L.8222-1) au-delà de 5 000 € HT cumulés sur
  // une année civile. Sa validité de 6 mois est fixée par l'URSSAF.
  vigilance_urssaf: { libelle: "Attestation de vigilance URSSAF", requis: false, mois_validite: 6,
                      faces: ['unique'] },
  sap:              { libelle: "Agrément services à la personne", requis: false, mois_validite: 12,
                      faces: ['unique'] }
  // « Autre document » a été retiré : un prestataire n'a aucune raison de
  // déposer un justificatif que personne ne lui demande, et l'administrateur
  // n'aurait aucun critère pour le valider. La valeur reste admise par la
  // contrainte en base — inutile de la modifier pour une entrée jamais utilisée.
};

const LIBELLES_FACE = { unique: '', recto: 'Recto', verso: 'Verso' };

const MOTIFS_REFUS = {
  illisible:       'Le document est illisible',
  expire:          'Le document est expiré',
  incomplet:       'Le document est incomplet',
  ne_correspond_pas: 'Le document ne correspond pas au prestataire',
  mauvais_type:    "Ce n'est pas le document demandé",
  autre:           'Autre motif'
};

// Accepte les images et les PDF. Le HEIC est indispensable : c'est le format
// natif des photos d'iPhone, et refuser une photo prise à l'instant serait le
// meilleur moyen de faire abandonner le prestataire.
async function televerserDocument(base64, proId, type) {
  const m = /^data:(image\/(?:jpeg|jpg|png|webp|heic|heif)|application\/pdf);base64,(.+)$/.exec(base64 || '');
  if (!m) return { erreur: 'Format non accepté. Envoyez une photo ou un PDF.' };

  let typeMime = m[1] === 'image/jpg' ? 'image/jpeg' : m[1];
  const extensions = {
    'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp',
    'image/heic': 'heic', 'image/heif': 'heif', 'application/pdf': 'pdf'
  };
  const contenu = Buffer.from(m[2], 'base64');

  if (contenu.length > 8 * 1024 * 1024)
    return { erreur: 'Fichier trop lourd (8 Mo maximum).' };

  // Un dossier par prestataire, un sous-dossier par type : le dépôt reste
  // navigable à la main depuis Supabase si vous devez chercher quelque chose.
  const chemin = proId + '/' + type + '/' + crypto.randomUUID() + '.' + extensions[typeMime];

  const { error } = await supabase.storage.from(DEPOT_DOCUMENTS)
    .upload(chemin, contenu, { contentType: typeMime, upsert: false });
  if (error) {
    console.error('Téléversement document échoué :', error.message);
    return { erreur: "Le dépôt a échoué. Réessayez dans un instant." };
  }
  return { chemin, typeMime, taille: contenu.length };
}

// URL signée de courte durée. Jamais stockée, jamais publique : régénérée à
// chaque consultation, elle expire en cinq minutes.
async function signerDocument(chemin) {
  try {
    const { data } = await supabase.storage.from(DEPOT_DOCUMENTS).createSignedUrl(chemin, 300);
    return data ? data.signedUrl : null;
  } catch (e) {
    return null;
  }
}

async function televerserPhoto(base64, dossier) {
  try {
    const m = /^data:(image\/(?:jpeg|jpg|png|webp));base64,(.+)$/.exec(base64 || '');
    if (!m) return base64;

    const typeMime = m[1] === 'image/jpg' ? 'image/jpeg' : m[1];
    const extension = typeMime === 'image/png' ? 'png' : typeMime === 'image/webp' ? 'webp' : 'jpg';
    const contenu = Buffer.from(m[2], 'base64');
    const chemin = dossier + '/' + crypto.randomUUID() + '.' + extension;

    const { error } = await supabase.storage.from(DEPOT_PHOTOS)
      .upload(chemin, contenu, { contentType: typeMime, upsert: false });
    if (error) {
      console.error('Téléversement photo échoué, conservation en base64:', error.message);
      return base64;
    }
    return chemin;
  } catch (e) {
    console.error('Téléversement photo:', e.message);
    return base64;
  }
}

async function televerserPhotos(liste, dossier) {
  if (!Array.isArray(liste) || !liste.length) return [];
  const resultats = [];
  for (const photo of liste) {
    resultats.push(estBase64(photo) ? await televerserPhoto(photo, dossier) : photo);
  }
  return resultats;
}

// Transforme les chemins du dépôt en liens temporaires. Une seule requête pour
// l'ensemble des chemins, quel qu'en soit le nombre.
// Les valeurs qui ne sont pas des chemins — base64 des demandes historiques,
// liens déjà signés — traversent la fonction sans être touchées.
async function signerChemins(valeurs) {
  const chemins = [...new Set(valeurs.filter(estCheminDepot))];
  if (!chemins.length) return {};
  try {
    const { data, error } = await supabase.storage.from(DEPOT_PHOTOS)
      .createSignedUrls(chemins, DUREE_LIEN_SIGNE);
    if (error) { console.error('Signature des photos:', error.message); return {}; }
    const table = {};
    (data || []).forEach((r) => { if (r.signedUrl && !r.error) table[r.path] = r.signedUrl; });
    return table;
  } catch (e) {
    console.error('Signature des photos:', e.message);
    return {};
  }
}

// Récupère toutes les valeurs de photos portées par un lot de demandes.
function photosDUneDemande(d) {
  const trouvees = [];
  if (d && d.notes) {
    try {
      const n = JSON.parse(d.notes);
      if (Array.isArray(n.photos)) trouvees.push(...n.photos);
    } catch (e) { /* notes en texte libre : rien à extraire */ }
  }
  ['photos_avant', 'photos_apres'].forEach((champ) => {
    const v = d && d[champ];
    if (!v) return;
    if (Array.isArray(v)) trouvees.push(...v);
    else { try { const t = JSON.parse(v); if (Array.isArray(t)) trouvees.push(...t); } catch (e) {} }
  });
  return trouvees;
}

// Prépare un lot de demandes pour l'envoi au navigateur : une seule requête de
// signature pour tout le lot, quel que soit le nombre de demandes.
async function signerPhotosDesDemandes(demandes) {
  const lot = Array.isArray(demandes) ? demandes : [demandes];
  const toutes = [];
  lot.forEach((d) => toutes.push(...photosDUneDemande(d)));
  const table = await signerChemins(toutes);
  if (!Object.keys(table).length) return demandes;

  const convertir = (v) => (table[v] || v);

  lot.forEach((d) => {
    if (!d) return;
    if (d.notes) {
      try {
        const n = JSON.parse(d.notes);
        if (Array.isArray(n.photos)) {
          n.photos = n.photos.map(convertir);
          d.notes = JSON.stringify(n);
        }
      } catch (e) {}
    }
    ['photos_avant', 'photos_apres'].forEach((champ) => {
      const v = d[champ];
      if (!v) return;
      if (Array.isArray(v)) { d[champ] = v.map(convertir); return; }
      try {
        const t = JSON.parse(v);
        if (Array.isArray(t)) d[champ] = JSON.stringify(t.map(convertir));
      } catch (e) {}
    });
  });
  return demandes;
}

// ── LA PRESTATION QUE PERSONNE NE CLÔT ──────────────────────────────────────
// Le client donne un code au prestataire à la fin. S'il l'oublie, rentre chez
// lui ou ne répond plus, la prestation reste « en cours » indéfiniment : le
// prestataire n'est jamais payé, l'argent dort chez Stripe, et la demande
// encombre les deux listes.
//
// Ce n'est pas un cas rare. C'est le cas NORMAL d'un client pressé qui a vu sa
// voiture propre et qui est reparti.
//
// 48 heures après le début de la prestation, la validation se fait seule. Le
// client est prévenu à 24 heures : sans avertissement, il découvrirait un
// débit qu'il n'a rien validé ; avec, son silence vaut accord.
//
// La validation automatique solde le PAIEMENT, pas le litige : le signalement
// reste ouvert, et vous gardez la main pour rembourser.
const HEURES_AVANT_CLOTURE_AUTO = 48;
const HEURES_AVANT_AVERTISSEMENT = 24;

async function cloturerPrestationsOubliees() {
  try {
    const limite = new Date(Date.now() - HEURES_AVANT_CLOTURE_AUTO * 3600000).toISOString();
    // ═══════════════════════════════════════════════════════════════════
    // LA COLONNE QUI N'EXISTE PAS
    //
    // Cette requête demandait « type_prestation ». La colonne n'existe pas :
    // la table n'a que « prestation ». PostgREST renvoyait donc une erreur,
    // le code ne lisait que `data` sans regarder `error`, et `aClore` valait
    // null — traité comme « rien à faire ».
    //
    // La clôture n'a JAMAIS fonctionné, depuis le premier jour. Elle échouait
    // en silence, à chaque appel, en annonçant zéro prestation à traiter.
    //
    // On lit désormais l'erreur, et on la fait remonter. Une requête qui
    // échoue doit se voir : sinon on cherche pendant des jours pourquoi rien
    // ne se passe.
    // ═══════════════════════════════════════════════════════════════════
    // ── DEUX DÉLAIS, SELON LA QUALITÉ DE L'ARRIVÉE ─────────────────────
    // Une arrivée vérifiée à moins d'un kilomètre se clôture à 48 h, comme
    // avant. Une arrivée éloignée ou non vérifiée attend SEPT JOURS.
    //
    // POURQUOI ALLONGER, ET NON SUSPENDRE
    //
    // Suspendre indéfiniment punirait le prestataire honnête dont la position
    // a échoué — parking souterrain, immeuble ancien, permission refusée. Sa
    // prestation est faite, son temps est passé, et il attendrait un client
    // satisfait qui ne rouvre jamais l'application.
    //
    // Une suspension sans fin, c'est un impayé. Sept jours laissent au client
    // tout le temps de contester, et le prestataire finit par être payé si
    // personne ne dit rien.
    //
    // Le silence ne doit jamais valoir accusation.
    const limiteDouteuse = new Date(Date.now() - 7 * 24 * 3600000).toISOString();

    const { data: aClore, error: erreurLecture } = await supabase.from('demandes')
      .select('id, client_id, prestation, prestation_demarree_le, arrivee_qualite, arrivee_confirmee_client')
      .eq('statut', 'en_cours')
      .not('prestation_demarree_le', 'is', null)
      // On lit large — toutes celles qui dépassent 48 h — puis on écarte
      // ensuite celles dont l'arrivée est douteuse et qui n'ont pas encore
      // atteint sept jours. Filtrer les deux délais en SQL demanderait une
      // condition OR imbriquée, plus difficile à relire qu'un filtre en clair.
      .lt('prestation_demarree_le', limite)
      .limit(200);

    if (erreurLecture) {
      console.error('Clôture automatique — lecture impossible :', erreurLecture.message);
      throw new Error('lecture des prestations à clôturer : ' + erreurLecture.message);
    }
    if (!aClore || !aClore.length) return 0;

    // ── LE SECOND DÉLAI S'APPLIQUE ICI ─────────────────────────────────
    // Une arrivée éloignée ou non vérifiée attend sept jours — sauf si le
    // client a explicitement confirmé que quelqu'un était bien venu. Dans ce
    // cas, il n'y a plus de doute, et faire attendre le prestataire cinq
    // jours de plus n'aurait aucun sens.
    const douteuse = (d) =>
      (d.arrivee_qualite === 'eloignee' || d.arrivee_qualite === 'non_verifiee')
      && d.arrivee_confirmee_client !== true;

    const pretes = aClore.filter(d =>
      !douteuse(d) || d.prestation_demarree_le < limiteDouteuse
    );
    if (!pretes.length) return 0;

    // ── UN LITIGE OUVERT SUSPEND LA CLÔTURE ─────────────────────────────
    // Payer automatiquement une prestation contestée reviendrait à trancher
    // le litige en faveur du prestataire, sans l'avoir instruit. L'argent
    // attend votre décision.
    //
    // « Ouvert » : tout signalement qui n'est ni résolu ni rejeté. Une fois
    // que vous avez tranché depuis l'administration, la clôture reprend son
    // cours au passage suivant.
    const { data: litiges } = await supabase.from('signalements')
      .select('demande_id')
      .in('demande_id', pretes.map(d => d.id))
      // « traite » est le mot qu'écrit l'administration. « resolu » et « rejete »
      // sont prévus pour un arbitrage plus fin, s'il vient un jour.
      // Les trois libèrent le paiement ; tout le reste le suspend.
      .not('statut', 'in', '(traite,resolu,rejete)');
    const demandesEnLitige = new Set((litiges || []).map(l => l.demande_id));
    let cloturees = 0;

    for (const d of pretes) {
      if (demandesEnLitige.has(d.id)) {
        console.log('Clôture suspendue pour ' + d.id + ' : signalement ouvert.');
        continue;
      }
      try {
        // Écriture conditionnelle : si le client valide au même instant, c'est
        // SA validation qui gagne, et la clôture automatique ne s'applique pas.
        const gagnee = await reserverLigne('demandes', d.id, ['en_cours'], 'terminee');
        if (!gagnee) continue;

        await supabase.from('demandes')
          .update({ validation_automatique: true }).eq('id', d.id);

        // ── LE VERSEMENT, QUI MANQUAIT ────────────────────────────────────
        // La clôture passait la demande en « terminée » et écrivait au client
        // que « le prestataire a été réglé » — sans jamais libérer l'argent.
        // Le paiement restait au statut « paye », et le virement n'existait
        // que dans le courriel.
        //
        // On réutilise exactement la brique de la validation par code :
        // réservation de la ligne, puis finalisation. La réservation évite
        // qu'un client validant au même instant ne déclenche un second
        // virement pour la même prestation.
        const { data: paiement } = await supabase.from('paiements')
          .select('*').eq('demande_id', d.id).eq('statut', 'paye').maybeSingle();

        if (paiement) {
          const reserve = await reserverLigne(
            'paiements', paiement.id, ['paye'], 'liberation_en_cours');
          if (reserve) {
            try {
              const resultat = await finaliserPrestation(paiement);
              if (resultat && resultat.erreur) {
                // On rend la réservation : sans cela le paiement resterait
                // dans un état intermédiaire que plus rien ne reprendrait.
                await supabase.from('paiements').update({ statut: 'paye' })
                  .eq('id', paiement.id).eq('statut', 'liberation_en_cours');
                console.error('Clôture auto ' + d.id + ' — versement refusé : ' + resultat.erreur);
              }
            } catch (errPaiement) {
              await supabase.from('paiements').update({ statut: 'paye' })
                .eq('id', paiement.id).eq('statut', 'liberation_en_cours');
              console.error('Clôture auto ' + d.id + ' — versement : ' + errPaiement.message);
            }
          }
        }

        cloturees += 1;
        console.log('Prestation ' + d.id + ' validée automatiquement apres ' +
                    HEURES_AVANT_CLOTURE_AUTO + ' h sans code.');

        const { data: client } = await supabase.from('users')
          .select('prenom, email').eq('id', d.client_id).maybeSingle();
        if (client) {
          sendEmail('prestation_validee_automatiquement', client.email, {
            compteId: client.id,
            prenom: client.prenom || '',
            prestation: d.prestation || 'nettoyage'
          }).catch(err => console.error('Email clôture auto:', err.message));
        }
        envoyerNotificationPush(d.client_id, {
          titre: 'Prestation validée',
          corps: 'Sans retour de votre part, la prestation a été validée et le prestataire réglé.',
          url: '/#mes-demandes'
        }).catch(() => {});
      } catch (err) {
        console.error('Clôture automatique ' + d.id + ' :', err.message);
      }
    }
    return cloturees;
  } catch (err) {
    // Une clôture qui échoue ne doit jamais empêcher la lecture des demandes.
    console.error('Clôture automatique ignorée:', err.message);
    return 0;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// RAPPELER AU PRESTATAIRE DE DÉCLARER SON ARRIVÉE
//
// Beaucoup d'oublis viennent de là : le prestataire EST sur place, mais n'a
// pas pensé à le déclarer. Et cette déclaration décide de tout — le report,
// l'annulation, le compte à rebours du versement.
//
// Trente minutes avant, il est encore en route ou vient d'arriver : c'est le
// moment où le rappel sert. Une heure avant, il l'aurait oublié ; à l'heure
// dite, il est déjà en train de travailler.
//
// LE CLIENT EST PRÉVENU AUSSI
//
// Il attend quelqu'un. Savoir que le prestataire a été rappelé le rassure —
// et s'il ne voit rien venir, il saura que ce n'est pas un oubli du système.
// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════
// REPRENDRE LES VIREMENTS QUI ONT ÉCHOUÉ
//
// Un virement échoue pour des raisons temporaires : solde de plateforme
// insuffisant, compte Connect pas encore actif, incident Stripe. Sans reprise,
// le prestataire attendrait indéfiniment un argent que le client a déjà payé.
//
// POURQUOI UN DÉLAI D'UNE HEURE ENTRE DEUX TENTATIVES
//
// Réessayer toutes les quinze minutes sur un compte Connect inachevé produit
// quatre échecs par heure et autant de lignes de journal — sans plus de chance
// d'aboutir. Une heure laisse le temps qu'une situation change.
//
// POURQUOI ON S'ARRÊTE À CINQ TENTATIVES
//
// Au-delà, la cause n'est pas temporaire : le compte du prestataire n'est pas
// en règle, ou le montant dépasse le solde disponible. Continuer masquerait le
// problème au lieu de le signaler. Le paiement reste visible dans
// l'administration, avec le motif du dernier échec.
// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════
// LES DEVIS ACCEPTÉS MAIS NON PAYÉS
//
// Deux traitements, dans le même balayage :
//
//   à 10 minutes de l'échéance   un rappel au client
//   après l'échéance             le devis redevient disponible
//
// POURQUOI LE RAPPEL
//
// Trente minutes suffisent pour un paiement ordinaire, pas pour une carte
// refusée ou un plafond bancaire à relever. Le rappel prévient celui qui a un
// problème ; il n'importune pas celui qui a déjà payé, puisque son échéance
// est effacée.
//
// POURQUOI LIBÉRER PLUTÔT QU'ANNULER
//
// Le devis redevient « envoye » : le client retrouve ses options, y compris
// celle-ci. Annuler l'obligerait à tout recommencer alors qu'il n'a fait que
// tarder.
// ═══════════════════════════════════════════════════════════════════════════
async function traiterEcheancesPaiement() {
  try {
    const maintenant = new Date();

    // ── 1. LE RAPPEL, DANS LES QUINZE DERNIÈRES MINUTES ─────────────────
    // J'avais choisi dix minutes. Or le balayage passe toutes les QUINZE :
    // une fenêtre de dix minutes est plus courte que le battement, et un
    // rappel sur trois tombait entre deux passages.
    //
    // Quinze minutes garantissent qu'aucune échéance n'est manquée — vérifié
    // sur les quinze décalages de départ possibles.
    const fenetreRappel = new Date(maintenant.getTime() + 15 * 60 * 1000).toISOString();

    const { data: aRappeler } = await supabase.from('devis')
      .select('id, demande_id, prix_ttc')
      .eq('statut', 'accepte')
      .not('paiement_avant', 'is', null)
      .is('rappel_paiement_envoye_le', null)
      .lt('paiement_avant', fenetreRappel)
      .gt('paiement_avant', maintenant.toISOString())
      .limit(50);

    for (const d of (aRappeler || [])) {
      const { data: demande } = await supabase.from('demandes')
        .select('client_id, prestation').eq('id', d.demande_id).maybeSingle();
      if (!demande) continue;

      envoyerNotificationPush(demande.client_id, {
        titre: 'Votre réservation expire bientôt',
        corps: 'Réglez ' + Number(d.prix_ttc).toFixed(2).replace('.', ',')
             + ' € pour confirmer votre prestation, sinon le devis sera libéré.',
        url: '/#devis'
      }).catch(() => {});

      await supabase.from('devis')
        .update({ rappel_paiement_envoye_le: maintenant.toISOString() })
        .eq('id', d.id);
    }

    // ── 2. L'ÉCHÉANCE DÉPASSÉE ──────────────────────────────────────────
    const { data: expires, error } = await supabase.from('devis')
      .select('id, demande_id')
      .eq('statut', 'accepte')
      .not('paiement_avant', 'is', null)
      .lt('paiement_avant', maintenant.toISOString())
      .limit(50);

    if (error) {
      console.error('Échéances de paiement — lecture impossible :', error.message);
      return 0;
    }
    if (!expires || !expires.length) return 0;

    let liberes = 0;
    for (const d of expires) {
      // Un paiement a-t-il été enregistré entre-temps ? Le webhook Stripe peut
      // arriver après notre lecture — libérer un devis payé serait le pire des
      // défauts possibles ici.
      const { data: paye } = await supabase.from('paiements')
        .select('id').eq('devis_id', d.id)
        .in('statut', ['paye', 'libere', 'liberation_en_cours']).maybeSingle();

      if (paye) {
        await supabase.from('devis')
          .update({ paiement_avant: null }).eq('id', d.id);
        continue;
      }

      await supabase.from('devis')
        .update({ statut: 'envoye', paiement_avant: null,
                  rappel_paiement_envoye_le: null })
        .eq('id', d.id).eq('statut', 'accepte');

      // La demande redevient ouverte : elle avait basculé en « acceptee ».
      await supabase.from('demandes')
        .update({ statut: 'devis_recus' })
        .eq('id', d.demande_id).eq('statut', 'acceptee');

      const { data: demande } = await supabase.from('demandes')
        .select('client_id').eq('id', d.demande_id).maybeSingle();
      if (demande) {
        envoyerNotificationPush(demande.client_id, {
          titre: 'Votre réservation a expiré',
          corps: 'Faute de paiement, le devis a été libéré. Vous pouvez le '
               + 'reprendre ou en choisir un autre.',
          url: '/#devis'
        }).catch(() => {});
      }
      liberes++;
    }
    return liberes;
  } catch (e) {
    console.error('Échéances de paiement :', e.message);
    return 0;
  }
}

async function reprendreVirementsEchoues() {
  try {
    const ilYaUneHeure = new Date(Date.now() - 3600 * 1000).toISOString();

    const { data: aReprendre, error } = await supabase.from('paiements')
      .select('id, demande_id, transfert_tentatives')
      .eq('statut', 'paye')
      .not('transfert_erreur', 'is', null)
      .lt('transfert_tentative_le', ilYaUneHeure)
      .lt('transfert_tentatives', 5)
      .limit(20);

    if (error) {
      console.error('Reprise des virements — lecture impossible :', error.message);
      return 0;
    }
    if (!aReprendre || !aReprendre.length) return 0;

    let repris = 0;
    for (const p of aReprendre) {
      // La prestation doit être terminée : un paiement encore en cours n'a
      // rien à verser, et sa présence ici serait un autre défaut.
      const { data: demande } = await supabase.from('demandes')
        .select('statut').eq('id', p.demande_id).maybeSingle();
      if (!demande || demande.statut !== 'terminee') continue;

      const resultat = await finaliserPrestation(p.demande_id);
      if (resultat && !resultat.erreur) {
        // Le virement a abouti : on efface la trace de l'échec, sinon le
        // paiement reviendrait à chaque passage.
        await supabase.from('paiements')
          .update({ transfert_erreur: null }).eq('id', p.id);
        repris++;
      }
    }
    return repris;
  } catch (e) {
    console.error('Reprise des virements :', e.message);
    return 0;
  }
}

async function rappelerDeclarationArrivee() {
  try {
    // On regarde large — les prestations des trois prochaines heures — puis on
    // filtre sur la fenêtre exacte. Le créneau est un texte en heure
    // française : PostgreSQL ne peut pas le comparer à un instant.
    const { data: proches, error } = await supabase.from('demandes')
      .select('id, client_id, prestation, creneau, prestation_demarree_le')
      .eq('statut', 'en_cours')
      .is('prestation_demarree_le', null)
      .is('rappel_arrivee_envoye_le', null)
      .limit(100);

    if (error) {
      console.error('Rappel d\'arrivée — lecture impossible :', error.message);
      return 0;
    }
    if (!proches || !proches.length) return 0;

    const maintenant = Date.now();
    let envoyes = 0;

    for (const d of proches) {
      const instant = instantDuCreneau(d.creneau);
      if (!instant) continue;

      const minutesAvant = (instant - maintenant) / 60000;
      // La fenêtre est large de 30 minutes pour couvrir l'intervalle entre
      // deux passages du balayage — sinon un créneau tomberait entre deux
      // et ne recevrait jamais son rappel.
      if (minutesAvant > 30 || minutesAvant < 0) continue;

      // Le prestataire qui doit venir : celui dont le devis a été accepté.
      const { data: devis } = await supabase.from('devis')
        .select('societe_id').eq('demande_id', d.id).eq('statut', 'accepte').maybeSingle();
      if (!devis) continue;

      const quand = Math.max(0, Math.round(minutesAvant));

      envoyerNotificationPush(devis.societe_id, {
        titre: 'Prestation dans ' + quand + ' minutes',
        corps: 'Pensez à déclarer votre arrivée une fois sur place — c\'est ce qui '
             + 'déclenche votre paiement.',
        url: '/#pro-devis'
      }).catch(() => {});

      envoyerNotificationPush(d.client_id, {
        titre: 'Votre prestation approche',
        corps: 'Le prestataire a été prévenu. Il déclarera son arrivée en arrivant.',
        url: '/#accueil'
      }).catch(() => {});

      // On marque AVANT de compter : si le marquage échoue, mieux vaut un
      // rappel manquant qu'une notification toutes les quinze minutes.
      await supabase.from('demandes')
        .update({ rappel_arrivee_envoye_le: new Date().toISOString() })
        .eq('id', d.id);

      envoyes++;
    }
    return envoyes;
  } catch (e) {
    console.error('Rappel d\'arrivée :', e.message);
    return 0;
  }
}

async function avertirValidationProche() {
  try {
    const debut = new Date(Date.now() - HEURES_AVANT_CLOTURE_AUTO * 3600000).toISOString();
    const fin = new Date(Date.now() - HEURES_AVANT_AVERTISSEMENT * 3600000).toISOString();
    // Même colonne inexistante que dans la clôture, et même conséquence :
    // l'avertissement 24 h avant la validation automatique n'a jamais été
    // envoyé. Les deux fonctions ont été écrites le même jour, avec la même
    // erreur — et aucune ne lisait son `error`.
    const { data: aPrevenir, error: erreurPrevenir } = await supabase.from('demandes')
      .select('id, client_id, prestation')
      .eq('statut', 'en_cours')
      .not('prestation_demarree_le', 'is', null)
      .gte('prestation_demarree_le', debut)
      .lt('prestation_demarree_le', fin)
      .is('avertissement_validation_envoye', null)
      .limit(100);

    if (erreurPrevenir) {
      console.error('Avertissement validation — lecture impossible :', erreurPrevenir.message);
      return;
    }
    if (!aPrevenir || !aPrevenir.length) return;

    // Même règle pour l'avertissement : annoncer une validation automatique à
    // quelqu'un qui vient de signaler un problème serait incompréhensible.
    const { data: litigesAvert } = await supabase.from('signalements')
      .select('demande_id')
      .in('demande_id', aPrevenir.map(d => d.id))
      // « traite » est le mot qu'écrit l'administration. « resolu » et « rejete »
      // sont prévus pour un arbitrage plus fin, s'il vient un jour.
      // Les trois libèrent le paiement ; tout le reste le suspend.
      .not('statut', 'in', '(traite,resolu,rejete)');
    const enLitige = new Set((litigesAvert || []).map(l => l.demande_id));

    for (const d of aPrevenir) {
      if (enLitige.has(d.id)) continue;
      // Marqué AVANT l'envoi : un doublon d'e-mail est moins grave qu'un envoi
      // répété à chaque lecture de la liste des demandes.
      await supabase.from('demandes')
        .update({ avertissement_validation_envoye: new Date().toISOString() })
        .eq('id', d.id);
      envoyerNotificationPush(d.client_id, {
        titre: 'Validez votre prestation',
        corps: 'Sans code de votre part sous 24 h, elle sera validée automatiquement.',
        url: '/#mes-demandes'
      }).catch(() => {});
    }
  } catch (err) {
    console.error('Avertissement de validation ignoré:', err.message);
  }
}

async function expirerDemandesEnRetard(demandes) {
  const maintenant = new Date();
  const aExpirer = [];
  const aExpirerAcceptees = [];
  for (const d of (demandes || [])) {
    if ((d.statut === 'en_attente' || d.statut === 'devis_recus' || d.statut === 'acceptee') && d.creneau) {
      // Le créneau est exprimé en heure française : il est converti en instant réel
      // plutôt qu'interprété dans le fuseau du serveur, qui est UTC sur Railway.
      const dateCreneau = creneauVersInstant(d.creneau);
      if (dateCreneau) {
        const heuresDepassement = (maintenant - dateCreneau) / (1000 * 60 * 60);
        // Une heure, pas trois. Le délai couvre un retard réel du prestataire
        // ou un paiement de dernière minute — au-delà, la prestation n'aura
        // pas lieu, et laisser la demande visible fait perdre du temps au
        // prestataire comme au client.
        if (heuresDepassement > 1) {
          aExpirer.push(d.id);
          if (d.statut === 'acceptee') aExpirerAcceptees.push(d.id);
        }
      }
    }
  }
  // Les prestations oubliées se traitent au même moment que les demandes
  // expirées : à chaque lecture de liste. Sans tâche planifiée, c'est le seul
  // battement de cœur dont dispose ce serveur — et il suffit, puisque la
  // clôture n'a rien d'urgent à la minute près.
  cloturerPrestationsOubliees().catch(() => {});
  avertirValidationProche().catch(() => {});

  if (aExpirer.length) {
    await supabase.from('demandes').update({ statut: 'expiree' }).in('id', aExpirer);
    demandes.forEach(d => { if (aExpirer.includes(d.id)) d.statut = 'expiree'; });

    // ── PRÉVENIR LE CLIENT ──────────────────────────────────────────────
    // Sans ce message, la demande disparaît en silence : le client attend des
    // devis qui ne viendront jamais et n'a aucune raison d'en refaire une.
    // C'est la façon la plus sûre de perdre quelqu'un qui était prêt à payer.
    //
    // L'envoi ne bloque jamais l'expiration elle-même : si l'e-mail échoue, la
    // demande reste close. L'inverse — garder une demande morte parce qu'un
    // courriel n'est pas parti — serait bien pire.
    try {
      const expirees = demandes.filter(d => aExpirer.includes(d.id));
      const clientIds = [...new Set(expirees.map(d => d.client_id).filter(Boolean))];
      if (clientIds.length) {
        const { data: clients } = await supabase.from('users')
          .select('id, prenom, email').in('id', clientIds);
        const parId = {};
        (clients || []).forEach(c => { parId[c.id] = c; });

        // Un devis reçu mais non réglé n'est pas la même histoire qu'un secteur
        // sans prestataire disponible. Le message le dit.
        const { data: devisExistants } = await supabase.from('devis')
          .select('demande_id').in('demande_id', aExpirer);
        const avecDevis = new Set((devisExistants || []).map(v => v.demande_id));

        for (const d of expirees) {
          const client = parId[d.client_id];
          if (!client) continue;
          const donnees = {
            prenom: client.prenom || '',
            prestation: d.prestation || 'nettoyage',
            creneau: d.creneau || 'la date prévue',
            demandeId: d.id,
            avaitDevis: avecDevis.has(d.id)
          };
          sendEmail('demande_expiree', client.email, donnees)
            .catch(err => console.error('Email expiration demande:', err.message));
          envoyerNotificationPush(d.client_id, {
            titre: 'Votre demande a expiré',
            corps: 'Le créneau du ' + donnees.creneau + ' est passé. Vous pouvez refaire une demande à une autre date.',
            url: '/#nouvelle-demande'
          }).catch(() => {});
        }
      }
    } catch (err) {
      console.error('Notification d\'expiration ignorée:', err.message);
    }
  }
  if (aExpirerAcceptees.length) {
    // Annule le(s) devis "accepté" resté(s) sans paiement, pour ne pas laisser un devis "accepté"
    // pointer vers une demande désormais expirée — incohérence qui perturberait l'affichage côté pro.
    // 'expire_sans_paiement' et non 'annule_client' : le client n'a rien annulé, il a
    // accepté un devis puis n'a jamais réglé, et le créneau est passé. Confondre les
    // deux affichait « Annulé par le client » à un prestataire à qui personne n'avait
    // rien annulé, et rendait indistinguables deux problèmes produit opposés — un
    // désistement d'une part, un tunnel de paiement qui décroche de l'autre.
    await supabase.from('devis').update({ statut: 'expire_sans_paiement' }).in('demande_id', aExpirerAcceptees).eq('statut', 'accepte');
  }
  return demandes;
}

app.get('/api/demandes', auth, async (req, res) => {
  const { data } = await supabase.from('demandes').select('*').eq('client_id', req.user.id).order('created_at', { ascending: false });
  const dataAJour = await expirerDemandesEnRetard(data || []);

  // ── QUI A RÉALISÉ LA PRESTATION ────────────────────────────────────────
  // La liste ne portait aucune trace du prestataire retenu. Le bandeau
  // « Votre avis compte » ne pouvait donc que renvoyer vers l'onglet Devis,
  // à charge pour le client de retrouver la bonne prestation dans sa liste.
  //
  // On joint le devis accepté aux prestations terminées : c'est ce qui permet
  // d'ouvrir la notation directement, sur la bonne personne.
  // ── LE NOM DU FAVORI RÉSERVATAIRE ──────────────────────────────────────
  // Rien n'indiquait au client que sa demande était réservée à quelqu'un. Il
  // voyait « Devis reçus » comme pour n'importe quelle demande, et un lien
  // « Ouvrir à tous » qui semblait sorti de nulle part.
  //
  // Dire QUI la garde change tout : « Réservée à Arnaud » explique à la fois
  // l'état et la raison du lien.
  const reservees = dataAJour.filter(d => d.pro_prefere_id).map(d => d.pro_prefere_id);
  if (reservees.length) {
    const { data: favoris } = await supabase.from('users')
      .select('id, prenom, nom').in('id', [...new Set(reservees)]);
    const parId = {};
    (favoris || []).forEach(p => { parId[p.id] = ((p.prenom || '') + ' ' + (p.nom || '')).trim(); });
    dataAJour.forEach(d => {
      if (d.pro_prefere_id) d.pro_prefere_nom = parId[d.pro_prefere_id] || null;
    });
  }

  const terminees = dataAJour.filter(d => d.statut === 'terminee').map(d => d.id);
  if (terminees.length) {
    const { data: devisAcceptes } = await supabase.from('devis')
      .select('demande_id, societe_id')
      .in('demande_id', terminees)
      .eq('statut', 'accepte');

    const parDemande = {};
    (devisAcceptes || []).forEach(v => { parDemande[v.demande_id] = v.societe_id; });

    const proIds = [...new Set(Object.values(parDemande))];
    const { data: pros } = proIds.length
      ? await supabase.from('users').select('id, prenom, nom').in('id', proIds)
      : { data: [] };
    const parPro = {};
    (pros || []).forEach(p => { parPro[p.id] = p; });

    dataAJour.forEach(d => {
      const proId = parDemande[d.id];
      if (!proId) return;
      const p = parPro[proId];
      d.societe_id = proId;
      d.pro_nom = p ? ((p.prenom || '') + ' ' + (p.nom || '')).trim() : 'votre prestataire';
    });
  }

  res.json(await signerPhotosDesDemandes(dataAJour));
});

// Demandes disponibles pour les pros (en attente, pas encore acceptées) — DOIT être déclarée avant /api/demandes/:id
// L'état du dossier prestataire, pour l'écran d'accueil.
//
// Route SÉPARÉE, et c'est délibéré : la liste des demandes doit rester une
// liste de demandes. Mélanger les deux a produit une carte fantôme en
// production, avec un bouton « Proposer un prix » sur une demande inexistante.
app.get('/api/pro/acces', auth, async (req, res) => {
  try {
    const regle = await prestataireEnRegle(req.user.id);
    res.json({
      en_regle: regle.enRegle,
      manques: regle.manques,
      message: regle.manques.join(' ')
    });
  } catch (e) {
    // En cas d'échec on répond « en règle » : mieux vaut un message générique
    // qu'un prestataire accusé à tort d'avoir un dossier incomplet.
    res.json({ en_regle: true, manques: [], message: '' });
  }
});

app.get('/api/demandes/all', auth, async (req, res) => {
  try {
    const { data: user, error: userErr } = await supabase.from('users').select('type, prestations_proposees, latitude, longitude, rayon_intervention_km').eq('id', req.user.id).single();
    if (userErr) return res.status(500).json({ error: 'Erreur utilisateur: ' + userErr.message });
    if (!user || !isProType(user.type))
      return res.status(403).json({ error: 'Cet écran est réservé aux comptes prestataires. Votre compte est un compte client.' });

    // Colonnes explicites plutôt que select('*') : la colonne `notes` contient les
    // photos encodées en base64 (jusqu'à 282 ko pour une seule demande dans la base
    // actuelle). Elle partait intégralement, pour toutes les demandes ouvertes, à
    // chaque sondage de chaque pro — pour n'en afficher que quelques-unes après
    // filtrage. `notes` reste servie par /api/demandes/:id, à l'ouverture d'une
    // demande précise, qui est le seul moment où le détail est réellement lu.
    const { data: demandes, error: demErr } = await supabase
      .from('demandes')
      .select('id, client_id, prestation, adresse, creneau, notes, statut, numero_anonyme, created_at, pro_prefere_id, exclusivite_jusqu_a, latitude, longitude, recurrence')
      .or('statut.eq.en_attente,statut.eq.devis_recus')
      .order('created_at', { ascending: false })
      .limit(500);

    if (demErr) return res.status(500).json({ error: 'Erreur demandes: ' + demErr.message });

    // Marque les demandes en retard comme expirées, puis les exclut immédiatement de la liste —
    // un pro ne doit jamais voir une demande dont le créneau est déjà largement dépassé.
    const demandesAJour = await expirerDemandesEnRetard(demandes || []);
    const demandesEncoreValides = demandesAJour.filter(d => d.statut !== 'expiree');

    const { data: mesDevis } = await supabase.from('devis').select('demande_id, statut').eq('societe_id', req.user.id);
    const idsRepondues = new Set((mesDevis || []).filter(d => d.statut === 'envoye' || d.statut === 'accepte').map(d => d.demande_id));
    let filtered = demandesEncoreValides.filter(d => !idsRepondues.has(d.id));

    // Les demandes que ce prestataire a lui-même écartées. Strictement
    // personnel : elles restent visibles de tous les autres.
    const { data: masquees } = await supabase.from('demandes_masquees')
      .select('demande_id').eq('pro_id', req.user.id);
    const idsMasquees = new Set((masquees || []).map(m => m.demande_id));
    filtered = filtered.filter(d => !idsMasquees.has(d.id));

    // ── UN DOSSIER INCOMPLET NE REÇOIT PAS DE DEMANDES ──────────────────
    // Montrer des demandes à un prestataire qui ne peut pas y répondre est
    // doublement mauvais : il perd son temps à lire des annonces, et il se
    // heurte au refus au moment d'envoyer son prix — c'est-à-dire après avoir
    // réfléchi à son tarif.
    //
    // La liste devient vide, et l'écran explique ce qui manque. Le parcours de
    // démarrage est déjà là pour l'y conduire.
    //
    // On vérifie avant tout autre filtre : inutile de trier des demandes qu'on
    // ne montrera pas.
    const regleListe = await prestataireEnRegle(req.user.id);
    if (!regleListe.enRegle) {
      // ── UNE LISTE VIDE, ET RIEN D'AUTRE ──────────────────────────────
      //
      // Deux mauvaises idées essayées avant celle-ci :
      //
      // 1. Un objet { demandes: [], acces_restreint: true } — l'application
      //    fait `data.length` puis `data.map` et serait restée sur son
      //    squelette de chargement, sans erreur.
      //
      // 2. Un en-tête HTTP — invisible au JavaScript d'origine croisée sans
      //    configuration CORS, donc silencieusement perdu le jour d'un
      //    changement d'hébergeur.
      //
      // 3. Un élément porteur d'un drapeau glissé dans le tableau — et une
      //    application pas encore mise à jour l'a affiché comme une DEMANDE
      //    VIDE, avec un bouton « Proposer un prix » sur du néant. C'est
      //    arrivé en production.
      //
      // La leçon : la réponse d'une route ne doit jamais dépendre de la
      // version de l'application qui la lit. On renvoie donc une liste vide,
      // point. L'application demande la cause à une route dédiée, quand elle
      // en a besoin — et une application qui l'ignore affiche simplement son
      // message générique, ce qui reste juste.
      return res.json([]);
    }

    // Ne montrer que les demandes correspondant aux prestations que le pro a déclaré savoir faire
    // (si le pro n'a configuré aucune préférence dans "Mes tarifs", on continue à tout lui montrer
    // pour ne pas casser l'expérience des pros n'ayant pas encore configuré cet écran).
    const prestationsPro = user.prestations_proposees;
    if (Array.isArray(prestationsPro) && prestationsPro.length > 0) {
      const prestationsProSet = new Set(prestationsPro);
      // « autre » ne figure plus dans l'écran des tarifs prestataire : une
      // prestation décrite en texte libre n'a pas de prix de base possible.
      //
      // Il ne peut donc plus la cocher — et sans cette ligne, il ne verrait
      // plus jamais ces demandes. Elles resteraient sans réponse, alors que ce
      // sont précisément celles qui méritent un devis sur mesure.
      //
      // Le prestataire les reçoit s'il est dans la zone, et décide en lisant.
      prestationsProSet.add('autre');
      filtered = filtered.filter(d => {
        const typesDemande = extractPrestationTypes(d);
        return typesDemande.some(t => prestationsProSet.has(t));
      });
    }

    // ── L'EXCLUSIVITÉ DU FAVORI A UNE FIN ───────────────────────────────
    // Elle n'en avait aucune : si le favori ne répondait pas, la demande
    // restait invisible pour tous jusqu'à son expiration, une heure après le
    // créneau. Le client perdait son créneau sans jamais savoir pourquoi.
    //
    // Passé `exclusivite_jusqu_a`, la demande redevient visible par tous les
    // prestataires de la zone. Le favori la garde toujours — il n'est pas
    // écarté, il cesse simplement d'être seul.
    const maintenant = Date.now();
    filtered = filtered.filter(d => {
      if (!d.pro_prefere_id) return true;                    // ouverte à tous
      if (d.pro_prefere_id === req.user.id) return true;     // c'est son favori
      // Un autre prestataire : il la voit si l'exclusivité est échue.
      if (!d.exclusivite_jusqu_a) return false;
      return new Date(d.exclusivite_jusqu_a).getTime() <= maintenant;
    });

    // Filtre par zone d'intervention — uniquement si le pro a configuré sa position ET un rayon.
    // Sans configuration, aucun filtrage n'est appliqué : un pro qui n'a pas encore réglé sa zone
    // continue de tout voir, exactement comme avant l'ajout de cette fonctionnalité.
    // ── PLUSIEURS ZONES, PAS UNE SEULE ──────────────────────────────────
    // Un prestataire habitant Cergy et travaillant souvent à Poissy devait
    // choisir : un rayon énorme depuis Cergy — et des demandes hors de portée
    // — ou rater tout ce qui se passe autour de Poissy.
    const { data: zonesPro } = await supabase.from('zones_intervention')
      .select('libelle, latitude, longitude, rayon_km')
      .eq('pro_id', req.user.id);

    // Repli sur l'ancien champ tant qu'un prestataire n'a pas de zone en
    // table. Sans lui, il ne verrait plus une seule demande sans comprendre.
    const zones = (zonesPro && zonesPro.length)
      ? zonesPro
      : ((typeof user.latitude === 'number' && typeof user.longitude === 'number'
          && typeof user.rayon_intervention_km === 'number')
          ? [{ libelle: 'Ma zone', latitude: user.latitude, longitude: user.longitude,
               rayon_km: user.rayon_intervention_km }]
          : []);

    const proAConfigureZone = zones.length > 0;
    filtered = filtered.map(d => {
      if (typeof d.latitude !== 'number' || typeof d.longitude !== 'number' || !proAConfigureZone) {
        return { ...d, distance_km: null, zone_libelle: null, dans_zone: false };
      }
      // La distance affichée est celle de la zone la PLUS PROCHE — c'est elle
      // qui décide s'il peut y aller. Mais l'appartenance se juge sur TOUTES :
      // une zone plus lointaine peut avoir un rayon plus large.
      let meilleure = null;
      let dansZone = false;
      for (const z of zones) {
        const dist = Math.round(distanceKm(z.latitude, z.longitude, d.latitude, d.longitude) * 10) / 10;
        if (dist <= z.rayon_km) dansZone = true;
        if (!meilleure || dist < meilleure.dist) meilleure = { dist, libelle: z.libelle };
      }
      return { ...d, distance_km: meilleure.dist, zone_libelle: meilleure.libelle, dans_zone: dansZone };
    });
    if (proAConfigureZone) {
      // Une demande adressée en priorité à CE prestataire reste visible quelle que
      // soit la distance : le client l'a choisi délibérément. Sans cette exception,
      // elle était écartée ici après l'avoir été pour tous les autres par le filtre
      // de favori juste au-dessus — donc invisible de tout le monde, jusqu'à
      // expiration silencieuse.
      filtered = filtered.filter(d =>
        d.pro_prefere_id === req.user.id
        || d.distance_km === null
        || d.dans_zone);
    }

    res.json(await signerPhotosDesDemandes(filtered));
  } catch (e) {
    console.error('Erreur /api/demandes/all:', e);
    res.status(500).json({ error: 'Erreur serveur: ' + e.message });
  }
});

// Enregistre la position de référence et le rayon d'intervention souhaité d'un pro — utilisé pour
// filtrer les demandes qu'il voit (voir /api/demandes/all). Réservé aux comptes pro.
// ═══════════════════════════════════════════════════════════════════════════
// LES ZONES D'INTERVENTION — JUSQU'À TROIS
//
// Un prestataire habitant Cergy et travaillant souvent à Poissy devait
// choisir : un rayon énorme depuis Cergy — et des demandes qu'il ne peut pas
// honorer — ou rater tout ce qui se passe autour de Poissy.
//
// Trois zones suffisent, et la limite protège la lecture : chaque zone ajoute
// un calcul de distance par demande affichée.
// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════
// LA COMMUNE À PARTIR D'UNE POSITION
//
// Le bouton « me localiser » écrivait littéralement « Position actuelle » dans
// le champ d'adresse. Le prestataire ne savait donc pas où il venait de se
// placer — et sa zone s'appelait ensuite « Ma zone » faute de nom.
//
// L'API Adresse ne peut pas être appelée depuis le navigateur sans exposer
// l'application au partage d'origine ; le serveur relaie donc.
// ═══════════════════════════════════════════════════════════════════════════
app.get('/api/geo/commune', auth, async (req, res) => {
  try {
    const lat = parseFloat(req.query.lat);
    const lng = parseFloat(req.query.lng);
    if (!isFinite(lat) || !isFinite(lng)) {
      return res.status(400).json({ error: 'Position invalide.' });
    }
    const commune = await communeDepuisCoordonnees(lat, lng);
    res.json({ commune: commune || null });
  } catch (e) {
    // Un échec n'est pas une erreur : l'application affichera « Position
    // actuelle », comme avant. On ne casse rien.
    res.json({ commune: null });
  }
});

app.get('/api/pro/zones', auth, async (req, res) => {
  try {
    const { data } = await supabase.from('zones_intervention')
      .select('id, libelle, latitude, longitude, rayon_km')
      .eq('pro_id', req.user.id)
      .order('created_at', { ascending: true });

    // ── LES ZONES REPRISES N'ONT PAS DE NOM ─────────────────────────────
    // La migration a converti les zones existantes en « Ma zone » : elle ne
    // pouvait pas appeler l'API Adresse depuis PostgreSQL.
    //
    // On les nomme à la première lecture, une seule fois. Le prestataire n'a
    // rien à faire, et sa tuile passe de « Ma zone · 10 km » à
    // « Cergy · 10 km » tout seul.
    const aNommer = (data || []).filter(z => z.libelle === 'Ma zone');
    for (const z of aNommer) {
      const commune = await communeDepuisCoordonnees(z.latitude, z.longitude);
      if (!commune) continue;   // le service n'a pas répondu : on réessaiera
      await supabase.from('zones_intervention')
        .update({ libelle: commune }).eq('id', z.id);
      z.libelle = commune;
    }

    res.json(data || []);
  } catch (e) {
    erreurServeur(res, 'GET /api/pro/zones', e);
  }
});

app.post('/api/pro/zones', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('type').eq('id', req.user.id).single();
    if (!user || !isProType(user.type)) {
      return res.status(403).json({ error: 'Cette action est réservée aux comptes prestataires.' });
    }

    const { latitude, longitude, rayon_km, libelle } = req.body;
    if (typeof latitude !== 'number' || typeof longitude !== 'number'
        || isNaN(latitude) || isNaN(longitude)) {
      return res.status(400).json({ error: 'Position invalide.' });
    }
    const rayon = Number.isInteger(rayon_km) ? rayon_km : parseInt(rayon_km, 10);
    if (!Number.isInteger(rayon) || rayon < 1 || rayon > 200) {
      return res.status(400).json({ error: 'Le rayon doit être compris entre 1 et 200 km.' });
    }

    // Le nom vient du géocodage inverse si le client n'en a pas fourni : c'est
    // lui qui rendra « 10 km autour de Cergy » lisible sur la carte.
    const nom = String(libelle || '').trim()
      || await communeDepuisCoordonnees(latitude, longitude)
      || 'Ma zone';

    const { data, error } = await supabase.from('zones_intervention')
      .insert({ pro_id: req.user.id, libelle: nom, latitude, longitude, rayon_km: rayon })
      .select('id, libelle, latitude, longitude, rayon_km').single();

    if (error) {
      // Le déclencheur en base refuse au-delà de trois. Son message est clair,
      // on le transmet plutôt que d'en inventer un autre.
      if (/trois zones/i.test(error.message)) {
        return res.status(409).json({ error: 'Trois zones d\'intervention au maximum.' });
      }
      return erreurServeur(res, 'POST /api/pro/zones', error);
    }

    // On garde `users.latitude` à jour sur la PREMIÈRE zone : d'autres écrans
    // s'en servent encore, et deux sources qui divergent finissent toujours
    // par produire un écart inexplicable.
    const { data: toutes } = await supabase.from('zones_intervention')
      .select('id').eq('pro_id', req.user.id);
    if ((toutes || []).length === 1) {
      await supabase.from('users')
        .update({ latitude, longitude, rayon_intervention_km: rayon })
        .eq('id', req.user.id);
    }

    res.json(data);
  } catch (e) {
    erreurServeur(res, 'POST /api/pro/zones', e);
  }
});

// ── MODIFIER UNE ZONE EXISTANTE ────────────────────────────────────────────
// Sans cette route, l'écran de réglage n'avait que la création : un
// prestataire qui ajuste son rayon trois fois se retrouvait avec trois zones,
// puis bloqué par la limite — sans comprendre pourquoi.
app.patch('/api/pro/zones/:id', auth, async (req, res) => {
  try {
    const { data: zone } = await supabase.from('zones_intervention')
      .select('id, pro_id').eq('id', req.params.id).maybeSingle();
    if (!zone) return res.status(404).json({ error: 'Cette zone n\'existe plus.' });
    if (zone.pro_id !== req.user.id) {
      return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément.' });
    }

    const { latitude, longitude, rayon_km, libelle } = req.body;
    const maj = {};

    if (typeof latitude === 'number' && typeof longitude === 'number'
        && !isNaN(latitude) && !isNaN(longitude)) {
      maj.latitude = latitude;
      maj.longitude = longitude;
      // La position change : le nom aussi, sauf si le client en fournit un.
      maj.libelle = String(libelle || '').trim()
        || await communeDepuisCoordonnees(latitude, longitude)
        || 'Ma zone';
    } else if (String(libelle || '').trim()) {
      maj.libelle = String(libelle).trim();
    }

    if (rayon_km !== undefined) {
      const rayon = Number.isInteger(rayon_km) ? rayon_km : parseInt(rayon_km, 10);
      if (!Number.isInteger(rayon) || rayon < 1 || rayon > 200) {
        return res.status(400).json({ error: 'Le rayon doit être compris entre 1 et 200 km.' });
      }
      maj.rayon_km = rayon;
    }

    if (!Object.keys(maj).length) {
      return res.status(400).json({ error: 'Rien à modifier.' });
    }

    const { data, error } = await supabase.from('zones_intervention')
      .update(maj).eq('id', zone.id)
      .select('id, libelle, latitude, longitude, rayon_km').single();
    if (error) return erreurServeur(res, 'PATCH /api/pro/zones/:id', error);

    // On garde `users.latitude` aligné sur la PREMIÈRE zone : d'autres écrans
    // s'en servent, et deux sources qui divergent produisent des écarts
    // inexplicables.
    const { data: toutes } = await supabase.from('zones_intervention')
      .select('id').eq('pro_id', req.user.id).order('created_at', { ascending: true });
    if (toutes && toutes.length && toutes[0].id === zone.id && maj.latitude) {
      await supabase.from('users')
        .update({ latitude: maj.latitude, longitude: maj.longitude,
                  rayon_intervention_km: maj.rayon_km || undefined })
        .eq('id', req.user.id);
    }

    res.json(data);
  } catch (e) {
    erreurServeur(res, 'PATCH /api/pro/zones/:id', e);
  }
});

app.delete('/api/pro/zones/:id', auth, async (req, res) => {
  try {
    const { data: zone } = await supabase.from('zones_intervention')
      .select('id, pro_id').eq('id', req.params.id).maybeSingle();
    if (!zone) return res.status(404).json({ error: 'Cette zone n\'existe plus.' });
    if (zone.pro_id !== req.user.id) {
      return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément.' });
    }

    // Supprimer la dernière zone reviendrait à ne plus recevoir aucune
    // demande, sans que rien ne l'explique. On refuse, en le disant.
    const { data: toutes } = await supabase.from('zones_intervention')
      .select('id').eq('pro_id', req.user.id);
    if ((toutes || []).length <= 1) {
      return res.status(409).json({
        error: 'Gardez au moins une zone : sans elle, vous ne recevriez plus aucune demande.'
      });
    }

    await supabase.from('zones_intervention').delete().eq('id', zone.id);
    res.json({ message: 'Zone supprimée.' });
  } catch (e) {
    erreurServeur(res, 'DELETE /api/pro/zones/:id', e);
  }
});

app.post('/api/pro/zone-intervention', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('type').eq('id', req.user.id).single();
    if (!user || !isProType(user.type)) return res.status(403).json({ error: 'Cette action est réservée aux comptes prestataires. Votre compte est un compte client.' });

    const { latitude, longitude, rayon_km } = req.body;
    if (typeof latitude !== 'number' || typeof longitude !== 'number' || isNaN(latitude) || isNaN(longitude))
      return res.status(400).json({ error: 'Position invalide.' });
    const rayon = Number.isInteger(rayon_km) ? rayon_km : parseInt(rayon_km, 10);
    if (!Number.isInteger(rayon) || rayon < 1 || rayon > 200)
      return res.status(400).json({ error: 'Le rayon doit être compris entre 1 et 200 km.' });

    await supabase.from('users').update({ latitude, longitude, rayon_intervention_km: rayon }).eq('id', req.user.id);
    res.json({ message: 'Zone d\'intervention enregistrée.' });
  } catch (e) {
    erreurServeur(res, 'POST /api/pro/zone-intervention', e);
  }
});

app.get('/api/demandes/:id', auth, async (req, res) => {
  const { data } = await supabase.from('demandes').select('*').eq('id', req.params.id).single();
  if (!data) return res.status(404).json({ error: 'Cette demande n\'existe plus. Elle a sans doute été supprimée ou annulée par le client.' });
  if (data.client_id === req.user.id) return res.json((await signerPhotosDesDemandes([data]))[0]);
  const { data: monDevis } = await supabase.from('devis').select('id').eq('demande_id', req.params.id).eq('societe_id', req.user.id).maybeSingle();
  if (monDevis) return res.json((await signerPhotosDesDemandes([data]))[0]);
  return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });
});

// Modifier une demande (uniquement si aucun devis n'a été accepté)
app.patch('/api/demandes/:id', auth, async (req, res) => {
  try {
    const { data: demande } = await supabase.from('demandes').select('*').eq('id', req.params.id).single();
    if (!demande) return res.status(404).json({ error: 'Cette demande n\'existe plus. Elle a sans doute été supprimée ou annulée par le client.' });
    if (demande.client_id !== req.user.id) return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });
    if (demande.statut === 'acceptee' || demande.statut === 'en_cours' || demande.statut === 'terminee' || demande.statut === 'annulee_client')
      return res.status(400).json({ error: 'Impossible de modifier : un devis a déjà été accepté pour cette demande.' });

    const { prestations, address, date, time, flexibility } = req.body;
    if (!address) return res.status(400).json({ error: 'Indiquez l\'adresse où doit avoir lieu la prestation.' });
    const erreurCreneau = validerCreneauFutur(date, time);
    if (erreurCreneau) return res.status(400).json({ error: erreurCreneau });

    const creneau = date && time ? date + ' à ' + time : demande.creneau;
    const listePrestations = prestations && Array.isArray(prestations) && prestations.length ? prestations : null;

    const updateData = { adresse: address, creneau: creneau };
    if (listePrestations) {
      updateData.prestation = listePrestations.map(p => p.type).join(' + ');
      updateData.notes = JSON.stringify({ flexibility: flexibility || '', prestations: listePrestations, modifiee: true });
    }
    // Si la demande était expirée, la relancer avec un nouveau créneau doit bien la remettre "en
    // attente" — sinon elle reste invisible pour les pros (leur liste n'affiche jamais les
    // demandes expirées), même une fois modifiée. On ne le fait que si une vraie nouvelle date a
    // été fournie (pas si l'ancien créneau, déjà passé, est resté inchangé — elle expirerait à
    // nouveau immédiatement au prochain contrôle).
    if (demande.statut === 'expiree' && date && time) updateData.statut = 'en_attente';

    const { data, error } = await supabase.from('demandes').update(updateData).eq('id', req.params.id).select().single();
    if (error) { console.error('Erreur Supabase, message technique complet:', error); return res.status(400).json({ error: traduireErreurSupabase(error.message) }); }

    await supabase.from('devis').update({ demande_modifiee: true }).eq('demande_id', req.params.id).eq('statut', 'envoye');

    res.json(data);
  } catch (e) {
    console.error(e);
    erreurServeur(res, 'PATCH /api/demandes/:id', e);
  }
});

// Met en pause, reprend, ou arrête définitivement la récurrence d'une demande — à tout moment,
// sans pénalité (contrairement à certains concurrents qui imposent un préavis ou des frais).
app.patch('/api/demandes/:id/recurrence', auth, async (req, res) => {
  try {
    const { action } = req.body; // 'pause' | 'reprendre' | 'arreter'
    const { data: demande } = await supabase.from('demandes').select('client_id, recurrence').eq('id', req.params.id).single();
    if (!demande) return res.status(404).json({ error: 'Cette demande n\'existe plus. Elle a sans doute été supprimée ou annulée par le client.' });
    if (demande.client_id !== req.user.id) return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });
    if (!demande.recurrence) return res.status(400).json({ error: 'Cette demande n\'est pas récurrente.' });

    if (action === 'pause') await supabase.from('demandes').update({ recurrence_active: false }).eq('id', req.params.id);
    else if (action === 'reprendre') await supabase.from('demandes').update({ recurrence_active: true }).eq('id', req.params.id);
    else if (action === 'arreter') await supabase.from('demandes').update({ recurrence: null, recurrence_active: false }).eq('id', req.params.id);
    else return res.status(400).json({ error: 'Action inconnue.' });

    res.json({ message: 'Récurrence mise à jour.' });
  } catch (e) {
    erreurServeur(res, 'PATCH /api/demandes/:id/recurrence', e);
  }
});

// Transforme une prestation déjà terminée (et appréciée) en une nouvelle récurrence — le moment
// le plus naturel pour le proposer au client, plutôt que de l'exiger dès la création initiale.
// Le pro à cibler est optionnel : le client peut choisir de la réadresser au même prestataire
// (celui qu'il vient d'apprécier), ou de la laisser ouverte à tous les pros disponibles.
app.post('/api/demandes/:id/relancer-recurrente', auth, async (req, res) => {
  try {
    const { recurrence, cibler_meme_pro } = req.body;
    if (!Number.isInteger(recurrence) || recurrence < 3 || recurrence > 365)
      return res.status(400).json({ error: 'Choisissez un délai entre 3 et 365 jours.' });

    const { data: demande } = await supabase.from('demandes').select('*').eq('id', req.params.id).single();
    if (!demande) return res.status(404).json({ error: 'Cette demande n\'existe plus. Elle a sans doute été supprimée ou annulée par le client.' });
    if (demande.client_id !== req.user.id) return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });
    if (demande.statut !== 'terminee') return res.status(400).json({ error: 'Seule une prestation terminée peut être relancée en récurrence.' });

    let proPrefereId = null;
    if (cibler_meme_pro) {
      const { data: devisAccepte } = await supabase.from('devis').select('societe_id').eq('demande_id', req.params.id).eq('statut', 'accepte').maybeSingle();
      proPrefereId = devisAccepte ? devisAccepte.societe_id : null;
    }

    const match = /(\d{4})-(\d{2})-(\d{2})\s*à\s*(\d{1,2})[h:](\d{2})/.exec(demande.creneau || '');
    const joursAAjouter = recurrence;
    const pad = n => String(n).padStart(2, '0');
    let dateStr, heureStr;
    if (match) {
      // Jours calendaires, heure locale préservée — voir creerProchaineOccurrenceRecurrente.
      const dateBase = new Date(Date.UTC(+match[1], +match[2] - 1, +match[3]));
      dateBase.setUTCDate(dateBase.getUTCDate() + joursAAjouter);
      dateStr = dateBase.getUTCFullYear() + '-' + pad(dateBase.getUTCMonth() + 1) + '-' + pad(dateBase.getUTCDate());
      heureStr = pad(+match[4]) + 'h' + pad(+match[5]);
    } else {
      const prochaine = new Date(Date.now() + joursAAjouter * 24 * 60 * 60 * 1000);
      dateStr = prochaine.getFullYear() + '-' + pad(prochaine.getMonth() + 1) + '-' + pad(prochaine.getDate());
      heureStr = '09h00';
    }

    const { data: nouvelleDemande } = await supabase.from('demandes').insert({
      client_id: demande.client_id,
      prestation: demande.prestation,
      adresse: demande.adresse,
      creneau: dateStr + ' à ' + heureStr,
      notes: demande.notes,
      numero_anonyme: 'Client #' + Math.floor(1000 + Math.random() * 9000),
      pro_prefere_id: proPrefereId,
      latitude: demande.latitude,
      longitude: demande.longitude,
      statut: 'en_attente',
      recurrence: recurrence,
      recurrence_active: true,
      recurrence_prochaine_creee: false
    }).select().single();

    res.status(201).json({ message: 'Prestation récurrente programmée !', demande: nouvelleDemande });
  } catch (e) {
    console.error('Erreur relance en récurrence:', e.message);
    erreurServeur(res, 'POST /api/demandes/:id/relancer-recurrente', e);
  }
});
// l'autre partie avant que le créneau ne change réellement, pour éviter qu'une personne décale
// unilatéralement un rendez-vous déjà convenu.
app.post('/api/demandes/:id/proposer-creneau', auth, async (req, res) => {
  try {
    const { date, time } = req.body;
    const erreurCreneau = validerCreneauFutur(date, time);
    if (erreurCreneau) return res.status(400).json({ error: erreurCreneau });

    const { data: demande } = await supabase.from('demandes').select('*').eq('id', req.params.id).single();
    if (!demande) return res.status(404).json({ error: 'Cette demande n\'existe plus. Elle a sans doute été supprimée ou annulée par le client.' });
    if (!['acceptee', 'en_cours'].includes(demande.statut))
      return res.status(400).json({ error: 'La reprogrammation n\'est possible que pour une prestation acceptée ou en cours.' });

    // ── LE PRESTATAIRE EST DÉJÀ SUR PLACE ───────────────────────────────
    // Avant son arrivée, un report ne coûte rien : il n'a pas bougé, et il
    // peut refuser — la reprogrammation exige l'accord des deux.
    //
    // Après, il s'est déplacé. Le report devient une annulation déguisée, et
    // l'annulation est déjà bloquée à ce stade. Deux gestes au même effet ne
    // peuvent pas avoir deux traitements opposés : un client à qui l'on refuse
    // d'annuler pouvait reprogrammer, et obtenir la même chose par un autre mot.
    //
    // Même code, même message que l'annulation : ce qui se passe une fois le
    // prestataire sur place se règle entre eux, ou par un signalement.
    // Le blocage suit désormais la QUALITÉ de l'arrivée, pas sa simple
    // déclaration : un report reste possible tant qu'une arrivée douteuse
    // n'a pas été confirmée par le client.
    if (!reportEncorePossible(demande)) {
      return res.status(409).json({
        error: 'Le prestataire est déjà sur place et a commencé la prestation. ' +
               'Elle ne peut plus être reprogrammée — si quelque chose ne va pas, ' +
               'signalez-le depuis la conversation et nous interviendrons.'
      });
    }

    const { data: devisAccepte } = await supabase.from('devis').select('societe_id').eq('demande_id', demande.id).eq('statut', 'accepte').maybeSingle();
    const estClient = demande.client_id === req.user.id;
    const estPro = devisAccepte && devisAccepte.societe_id === req.user.id;
    if (!estClient && !estPro) return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });

    const nouveauCreneau = date + ' à ' + time;
    await supabase.from('demandes').update({ creneau_propose: nouveauCreneau, creneau_propose_par: req.user.id }).eq('id', req.params.id);

    res.json({ message: 'Nouveau créneau proposé, en attente de confirmation de l\'autre partie.' });
  } catch (e) {
    erreurServeur(res, 'POST /api/demandes/:id/proposer-creneau', e);
  }
});

app.post('/api/demandes/:id/repondre-creneau', auth, async (req, res) => {
  try {
    const { accepter } = req.body;
    const { data: demande } = await supabase.from('demandes').select('*').eq('id', req.params.id).single();
    if (!demande) return res.status(404).json({ error: 'Cette demande n\'existe plus. Elle a sans doute été supprimée ou annulée par le client.' });
    if (!demande.creneau_propose) return res.status(400).json({ error: 'Aucune proposition de créneau en attente.' });
    if (demande.creneau_propose_par === req.user.id) return res.status(403).json({ error: 'Vous ne pouvez pas répondre à votre propre proposition.' });

    // ── LE MÊME GARDE-FOU, SUR L'AUTRE CHEMIN ───────────────────────────
    // Bloquer la PROPOSITION ne suffit pas : une proposition faite la veille,
    // encore en attente, pouvait être acceptée après l'arrivée du prestataire.
    // Le report se produisait alors quand même, par la porte de derrière.
    //
    // On refuse la réponse, et on retire la proposition devenue caduque :
    // la laisser en attente ferait réapparaître le bouton à chaque ouverture.
    // Le blocage suit désormais la QUALITÉ de l'arrivée, pas sa simple
    // déclaration : un report reste possible tant qu'une arrivée douteuse
    // n'a pas été confirmée par le client.
    if (!reportEncorePossible(demande)) {
      await supabase.from('demandes')
        .update({ creneau_propose: null, creneau_propose_par: null })
        .eq('id', demande.id);
      return res.status(409).json({
        error: 'Le prestataire est déjà sur place et a commencé la prestation. ' +
               'La proposition de report n\'est plus valable — si quelque chose ne va pas, ' +
               'signalez-le depuis la conversation et nous interviendrons.'
      });
    }

    const { data: devisAccepte } = await supabase.from('devis').select('societe_id').eq('demande_id', demande.id).eq('statut', 'accepte').maybeSingle();
    const estClient = demande.client_id === req.user.id;
    const estPro = devisAccepte && devisAccepte.societe_id === req.user.id;
    if (!estClient && !estPro) return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });

    if (accepter) {
      await supabase.from('demandes').update({ creneau: demande.creneau_propose, creneau_propose: null, creneau_propose_par: null }).eq('id', req.params.id);
      res.json({ message: 'Nouveau créneau confirmé ✨' });
    } else {
      await supabase.from('demandes').update({ creneau_propose: null, creneau_propose_par: null }).eq('id', req.params.id);
      res.json({ message: 'Proposition refusée. L\'ancien créneau reste valable.' });
    }
  } catch (e) {
    erreurServeur(res, 'POST /api/demandes/:id/repondre-creneau', e);
  }
});

// Rembourse automatiquement le client si la prestation avait déjà été payée au moment de
// l'annulation — sans ça, l'argent restait bloqué chez Gleam sans aucune résolution.
// Si `heuresRestantes` est fourni (annulation à l'initiative du CLIENT), applique le barème de
// frais à 3 paliers : le pro garde toujours ce qui lui a déjà été transféré (jamais lésé), seul
// le remboursement au client varie selon le délai avant le créneau prévu.
//   - 24h ou plus avant : remboursement intégral, gratuit
//   - Entre 2h et 24h avant : remboursement de 70% (30% de frais retenus, en compensation du pro)
//   - Moins de 2h avant : aucun remboursement (le pro reçoit l'intégralité, comme prévu)
// Si `heuresRestantes` n'est pas fourni (annulation à l'initiative du PRO), remboursement toujours
// intégral — ce n'est jamais au client de payer les frais d'une annulation qu'il n'a pas décidée.
// Rembourse automatiquement le client si la prestation avait déjà été payée au moment de
// l'annulation — sans ça, l'argent restait bloqué chez Gleam sans aucune résolution.
// Si `heuresRestantes` est fourni (annulation à l'initiative du CLIENT), applique le barème de
// frais à 3 paliers :
//   - 24h ou plus avant : remboursement intégral, gratuit
//   - Entre 2h et 24h avant : remboursement de 70% — les 30% retenus se répartissent
//     PROPORTIONNELLEMENT entre le pro et la commission Gleam (le pro garde donc sa part
//     habituelle sur ce qui est retenu, pas sur la totalité — sinon le total distribué dépasserait
//     ce que le client a réellement payé, ce qui n'est évidemment pas possible)
//   - Moins de 2h avant : aucun remboursement (le pro et Gleam gardent leurs parts complètes,
//     comme si la prestation avait eu lieu normalement)
// Si `heuresRestantes` n'est pas fourni (annulation à l'initiative du PRO), remboursement toujours
// intégral — ce n'est jamais au client de payer les frais d'une annulation qu'il n'a pas décidée.
async function rembourserPaiementSiPaye(demandeId, heuresRestantes) {
  const { data: paiement } = await supabase.from('paiements').select('*').eq('demande_id', demandeId).eq('statut', 'paye').maybeSingle();
  if (!paiement) return { rembourse: false };

  // ── UNE ARRIVÉE CONTESTÉE NE SE FACTURE PAS AU CLIENT ──────────────────
  // Le barème pénalise les annulations tardives : moins de deux heures avant
  // le créneau, aucun remboursement. C'est juste quand le client change d'avis
  // au dernier moment.
  //
  // Mais quand il vient de déclarer que PERSONNE N'EST VENU, il n'y est pour
  // rien. Le créneau étant passé, le calcul donne un temps négatif — donc
  // moins de deux heures — et il perdait tout.
  //
  // Il aurait payé une prestation qui n'a pas eu lieu, en punition de l'avoir
  // signalée.
  const { data: demandeArrivee } = await supabase.from('demandes')
    .select('arrivee_confirmee_client, prestation_demarree_le, creneau')
    .eq('id', demandeId).maybeSingle();

  // Cas 1 — le prestataire a déclaré son arrivée, le client la conteste.
  const arriveeContestee = demandeArrivee && demandeArrivee.arrivee_confirmee_client === false;

  // ── CAS 2 — L'ABSENCE PURE, MAIS PAS LE SIMPLE RETARD ──────────────────
  // Un prestataire peut avoir trente minutes de retard : embouteillage,
  // chantier précédent qui déborde, place de stationnement introuvable. Rendre
  // l'annulation gratuite à ce moment-là reviendrait à lui faire perdre sa
  // course pour un contretemps ordinaire.
  //
  // Une heure, en revanche, n'est plus un retard : celui qui n'a ni déclaré
  // son arrivée ni écrit un mot en soixante minutes ne viendra pas.
  //
  // Le seuil ne juge pas le prestataire — il départage deux situations que le
  // barème confondait : « je change d'avis au dernier moment » et « j'ai
  // attendu une heure pour rien ».
  const MINUTES_AVANT_ABSENCE = 60;
  let absenceConstatee = false;
  if (demandeArrivee && !demandeArrivee.prestation_demarree_le) {
    const instant = instantDuCreneau(demandeArrivee.creneau);
    if (instant) {
      absenceConstatee = (Date.now() - instant) / 60000 >= MINUTES_AVANT_ABSENCE;
    }
  }

  const sansFrais = arriveeContestee || absenceConstatee;

  let pourcentage = 1;
  if (!sansFrais && typeof heuresRestantes === 'number') {
    if (heuresRestantes < 2) pourcentage = 0;
    else if (heuresRestantes < 24) pourcentage = 0.7;
  }

  if (pourcentage === 0) {
    await supabase.from('paiements').update({ statut: 'rembourse_partiel', montant_rembourse: 0 }).eq('id', paiement.id);
    return { rembourse: false, fraisRetenus: true, montantRetenu: paiement.montant_ttc };
  }

  try {
    // Vérifié dans la documentation officielle de Stripe : SANS instruction explicite, Stripe ne
    // reprend RIEN sur la part déjà transférée au pro lors d'un remboursement — le pro garderait
    // sa part complète tout en laissant le client remboursé, ce qui ferait dépasser le total
    // redistribué par rapport à ce qui a été réellement payé (exactement le bug identifié).
    // Il faut donc explicitement demander la reprise proportionnelle des deux côtés.
    const paramsRemboursement = { payment_intent: paiement.stripe_payment_intent_id };
    if (pourcentage < 1) {
      paramsRemboursement.amount = Math.round(paiement.montant_ttc * pourcentage * 100);
      paramsRemboursement.reverse_transfer = true; // reprend au prorata sur la part du pro
      paramsRemboursement.refund_application_fee = true; // reprend au prorata sur la commission Gleam
    }
    await stripe.refunds.create(paramsRemboursement);
    const montantEffectivementRembourse = Math.round(paiement.montant_ttc * pourcentage * 100) / 100;

    // Plutôt que de recalculer à la main ce que le pro garde réellement (la mécanique interne de
    // Stripe pour les "destination charges" avec commission s'est révélée plus subtile que prévu —
    // le montant brut transféré n'est pas ce qu'on pensait), on va lire directement chez Stripe le
    // vrai montant final, une fois la reprise effectuée. Ça élimine tout risque de mauvais calcul
    // de notre côté : on rapporte fidèlement ce que Stripe confirme, jamais une estimation.
    let montantProCorrige = paiement.montant_societe;
    if (pourcentage < 1 && paiement.stripe_transfer_id) {
      try {
        const transfert = await stripe.transfers.retrieve(paiement.stripe_transfer_id);
        const montantTransfereNet = (transfert.amount - transfert.amount_reversed) / 100;
        let montantFeeRetenu = 0;
        if (paiement.stripe_application_fee_id) {
          const fee = await stripe.applicationFees.retrieve(paiement.stripe_application_fee_id);
          montantFeeRetenu = (fee.amount - fee.amount_refunded) / 100;
        }
        // Le pro garde le montant net du transfert, une fois la commission encore due déduite
        montantProCorrige = Math.round((montantTransfereNet - montantFeeRetenu) * 100) / 100;
      } catch (e) {
        console.error('Lecture du montant réel chez Stripe échouée, montant non recalculé:', e.message);
      }
    }

    await supabase.from('paiements').update({
      statut: pourcentage < 1 ? 'rembourse_partiel' : 'rembourse',
      montant_rembourse: montantEffectivementRembourse,
      montant_societe: montantProCorrige
    }).eq('id', paiement.id);

    // Si ce paiement était le tout premier du client (celui qui avait déclenché sa récompense de
    // parrainage) et qu'il est intégralement remboursé, la récompense doit être reprise si elle
    // n'a pas encore été utilisée — sinon le client garderait un avantage gagné sur une prestation
    // qui, finalement, n'a jamais eu lieu. On ne touche jamais à la récompense si elle a déjà été
    // utilisée sur une autre transaction légitime entre-temps (trop tard pour la reprendre).
    if (pourcentage === 1) {
      try {
        const { data: clientConcerne } = await supabase.from('users').select('parrainage_recompense_donnee, reduction_parrainage_disponible').eq('id', paiement.client_id).single();
        if (clientConcerne && clientConcerne.parrainage_recompense_donnee && clientConcerne.reduction_parrainage_disponible) {
          const { count: nbPaiementsValides } = await supabase.from('paiements').select('id', { count: 'exact', head: true })
            .eq('client_id', paiement.client_id).in('statut', ['paye', 'libere']);
          if (!nbPaiementsValides || nbPaiementsValides === 0) {
            // Plus aucun paiement valide pour ce client : celui-ci était bien le seul et unique
            // déclencheur de la récompense, encore jamais utilisée — on la reprend proprement,
            // le client pourra légitimement se requalifier avec un futur vrai paiement.
            await supabase.from('users').update({ reduction_parrainage_disponible: false, parrainage_recompense_donnee: false }).eq('id', paiement.client_id);
          }
        }
      } catch (e) {
        console.error('Vérification de reprise de récompense de parrainage ignorée:', e.message);
      }
    }
    return {
      rembourse: true,
      montant: montantEffectivementRembourse,
      fraisRetenus: pourcentage < 1,
      montantRetenu: pourcentage < 1 ? Math.round(paiement.montant_ttc * (1 - pourcentage) * 100) / 100 : 0
    };
  } catch (e) {
    console.error('Remboursement Stripe échoué:', e);
    return { rembourse: false, erreur: true };
  }
}

app.post('/api/demandes/:id/annuler-client', auth, async (req, res) => {
  try {
    const { data: demande } = await supabase.from('demandes').select('*').eq('id', req.params.id).single();
    if (!demande) return res.status(404).json({ error: 'Cette demande n\'existe plus. Elle a sans doute été supprimée ou annulée par le client.' });
    if (demande.client_id !== req.user.id) return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });
    if (demande.statut === 'terminee')
      return res.status(400).json({ error: 'Cette prestation est déjà terminée, elle ne peut plus être annulée.' });
    if (demande.statut !== 'acceptee' && demande.statut !== 'en_cours')
      return res.status(400).json({ error: 'Utilisez la suppression classique pour une demande pas encore acceptée.' });

    // ── PLUS D'ANNULATION UNE FOIS LE PRESTATAIRE SUR PLACE ──────────────
    // Il a fait la route, s'est garé, a sorti son matériel, et déclaré son
    // arrivée avec photos et position GPS. Annuler à ce moment lui coûtait du
    // temps et de l'essence pour rien, avec remboursement intégral du client.
    //
    // Le recours reste le signalement : il passe par vous et permet un
    // arbitrage. C'est la différence entre un litige, qu'on instruit, et un
    // désistement unilatéral, qu'on subit.
    // ── SAUF SI LE CLIENT A DÉJÀ DIT QUE PERSONNE N'EST VENU ────────────
    // Il avait répondu « non » à la question de l'arrivée, un litige était
    // ouvert — et l'annulation restait pourtant refusée au motif que « le
    // prestataire est déjà sur place ».
    //
    // On lui opposait une déclaration qu'il venait justement de contester.
    // Sa seule issue était d'attendre sept jours qu'on tranche.
    if (demande.prestation_demarree_le && demande.arrivee_confirmee_client !== false) {
      return res.status(409).json({
        error: 'Le prestataire est déjà sur place et a commencé la prestation. ' +
               'Elle ne peut plus être annulée — si quelque chose ne va pas, ' +
               'signalez-le depuis la conversation et nous interviendrons.'
      });
    }

    // Calcule précisément les heures restantes avant le créneau prévu, pour déterminer le palier
    // de frais applicable (voir rembourserPaiementSiPaye) — heuresRestantes reste `null` si aucun
    // créneau n'est renseigné, auquel cas le remboursement intégral s'applique par défaut.
    let heuresRestantes = null;
    if (demande.creneau) {
      // Ce calcul détermine le palier de remboursement : il doit raisonner sur
      // l'heure française du rendez-vous, pas sur celle du serveur. Sur Railway
      // (UTC), le créneau était lu deux heures trop tard en été — une annulation
      // à 1 h du rendez-vous paraissait faite à 3 h, et donnait droit à 70 % de
      // remboursement là où le barème n'en prévoyait aucun.
      const dateCreneau = creneauVersInstant(demande.creneau);
      if (dateCreneau) {
        heuresRestantes = (dateCreneau - new Date()) / (1000 * 60 * 60);
      }
    }
    const tardive = heuresRestantes !== null && heuresRestantes < 24;

    const { data: devisAccepte } = await supabase.from('devis').select('*').eq('demande_id', demande.id).eq('statut', 'accepte').maybeSingle();

    // ── L'ABSENCE EST NOTÉE, PAS SANCTIONNÉE ──────────────────────────────
    // Un prestataire qui ne vient pas ne laissait aucune trace : on ne le
    // savait qu'en lisant les litiges un par un.
    //
    // On compte SEULEMENT si le créneau est passé et qu'aucune arrivée n'a été
    // déclarée. Une annulation la veille n'est pas une absence — c'est le
    // client qui change d'avis, et le barème s'en charge.
    //
    // AUCUNE SUSPENSION AUTOMATIQUE : trois absences peuvent venir d'un
    // téléphone cassé, d'un accident, d'une hospitalisation. Le compteur sert
    // à REGARDER. Avec quatre prestataires, un chiffre visible suffit.
    if (devisAccepte && !demande.prestation_demarree_le) {
      const instantPrestation = instantDuCreneau(demande.creneau);
      if (instantPrestation && Date.now() > instantPrestation) {
        const { data: pro } = await supabase.from('users')
          .select('absences_constatees').eq('id', devisAccepte.societe_id).single();
        await supabase.from('users')
          .update({ absences_constatees: ((pro && pro.absences_constatees) || 0) + 1 })
          .eq('id', devisAccepte.societe_id);

        // Il doit l'apprendre tout de suite : s'il est en route, il fait
        // demi-tour. Par courriel, il l'apprendrait le lendemain — après avoir
        // fait le déplacement pour rien.
        envoyerNotificationPush(devisAccepte.societe_id, {
          titre: 'Prestation annulée',
          corps: 'Le client a annulé : votre arrivée n\'avait pas été déclarée. '
               + 'Si vous étiez en route, écrivez-lui depuis la conversation.',
          url: '/#pro-devis'
        }).catch(() => {});
      }
    }

    // Si la prestation était déjà payée (en cours), applique le barème de frais avant d'annuler
    const remboursement = demande.statut === 'en_cours' ? await rembourserPaiementSiPaye(demande.id, heuresRestantes) : { rembourse: false };

    await supabase.from('demandes').update({ statut: 'annulee_client' }).eq('id', demande.id);
    if (devisAccepte) await supabase.from('devis').update({ statut: 'annule_client' }).eq('id', devisAccepte.id);

    // 📧 Notifie immédiatement le prestataire concerné
    if (devisAccepte) {
      const { data: pro } = await supabase.from('users').select('email, prenom').eq('id', devisAccepte.societe_id).single();
      if (pro) {
        sendEmail('annulation_client', pro.email, {
          compteId: pro.id,
          prenom: pro.prenom || '', prestation: demande.prestation, creneau: demande.creneau || '',
          tardive, demandeId: demande.id,
        }).catch(e => console.error('Email annulation_client:', e));
      }
    }

    res.json({
      message: 'Prestation annulée.',
      tardive,
      rembourse: remboursement.rembourse,
      montant_rembourse: remboursement.montant || 0,
      frais_retenus: Boolean(remboursement.fraisRetenus),
      montant_retenu: remboursement.montantRetenu || 0
    });
  } catch (e) {
    console.error(e);
    erreurServeur(res, 'POST /api/demandes/:id/annuler-client', e);
  }
});

// Supprimer une demande (uniquement si aucun devis n'a été accepté)
// Le client "range" une demande définitivement close (annulée ou terminée) de sa vue,
// sans jamais la supprimer réellement — l'historique reste intact pour le suivi de fiabilité
// et en cas de litige. Utilisable à tout moment, contrairement à la suppression.
app.patch('/api/demandes/:id/archiver', auth, async (req, res) => {
  try {
    const { data: demande } = await supabase.from('demandes').select('client_id, statut').eq('id', req.params.id).single();
    if (!demande) return res.status(404).json({ error: 'Cette demande n\'existe plus. Elle a sans doute été supprimée ou annulée par le client.' });
    if (demande.client_id !== req.user.id) return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });

    const { error } = await supabase.from('demandes').update({ archivee_client: true }).eq('id', req.params.id);
    if (error) { console.error('Erreur Supabase, message technique complet:', error); return res.status(400).json({ error: traduireErreurSupabase(error.message) }); }
    res.json({ message: 'Demande archivée.' });
  } catch (e) {
    erreurServeur(res, 'PATCH /api/demandes/:id/archiver', e);
  }
});

app.delete('/api/demandes/:id', auth, async (req, res) => {
  try {
    const { data: demande } = await supabase.from('demandes').select('*').eq('id', req.params.id).single();
    if (!demande) return res.status(404).json({ error: 'Cette demande n\'existe plus. Elle a sans doute été supprimée ou annulée par le client.' });
    if (demande.client_id !== req.user.id) return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });
    if (demande.statut === 'acceptee' || demande.statut === 'en_cours' || demande.statut === 'terminee')
      return res.status(400).json({ error: 'Impossible de supprimer : un devis a déjà été accepté. Utilisez le bouton "Annuler cette prestation" à la place.' });
    if (demande.statut === 'annulee_client')
      return res.status(400).json({ error: 'Cette demande est déjà annulée.' });

    await supabase.from('devis').delete().eq('demande_id', req.params.id);
    await supabase.from('messages').delete().eq('demande_id', req.params.id);
    await supabase.from('paiements').delete().eq('demande_id', req.params.id);
    await supabase.from('evaluations').delete().eq('demande_id', req.params.id);
    const { error } = await supabase.from('demandes').delete().eq('id', req.params.id);
    if (error) { console.error('Erreur Supabase, message technique complet:', error); return res.status(400).json({ error: traduireErreurSupabase(error.message) }); }

    res.json({ message: 'Demande supprimée.' });
  } catch (e) {
    erreurServeur(res, 'DELETE /api/demandes/:id', e);
  }
});

// ══════════════ DEVIS ══════════════

// Les justificatifs qu'un prestataire doit avoir fournis avant de proposer un
// prix. Le devis est le moment où la relation commerciale commence : c'est là
// que le contrôle a du sens, pas à l'inscription.
//
// Renvoie la liste de ce qui manque, jamais un simple refus — le prestataire
// doit savoir quoi faire, et l'application doit pouvoir l'y emmener.
function justificatifsManquants(user) {
  const manquants = [];
  if (!user) return ['compte'];
  if (!/^\d{14}$/.test(String(user.siret || '').replace(/\s/g, '')))
    manquants.push('siret');
  if (!user.assurance_rc_pro)
    manquants.push('assurance');
  return manquants;
}


// ═══════════════════════════════════════════════════════════════════════════
// UN PRESTATAIRE PEUT-IL TRAVAILLER SUR GLEAM ?
//
// Deux conditions, nées de deux incidents réels.
//
// 1. SES PAIEMENTS SONT OPÉRATIONNELS
//    Le 19 août, deux versements ont échoué sur « balance_insufficient ». Le
//    prestataire n'avait pas de compte Connect actif au moment du paiement :
//    l'argent est resté sur le compte de la plateforme, et il fallait le lui
//    virer depuis un solde vide.
//
//    L'existence d'un `stripe_account_id` NE SUFFIT PAS — Christopher en avait
//    un, et le virement a quand même échoué. On interroge Stripe pour connaître
//    l'état réel du compte.
//
// 2. SES TROIS DOCUMENTS SONT VALIDÉS
//    Identité, immatriculation, assurance RC Pro. Un client qui réserve chez un
//    prestataire non vérifié n'a aucune garantie — et c'est la plateforme qui
//    répond du sinistre.
//
// La fonction dit CE QUI MANQUE. Un refus qui n'explique pas se transforme en
// appel au support, et en prestataire qui s'en va.
// ═══════════════════════════════════════════════════════════════════════════
// La liste des documents obligatoires est DÉDUITE de TYPES_DOCUMENTS, jamais
// recopiée. Elle y porte déjà un drapeau `requis`, et les pièces facultatives
// — vigilance URSSAF, agrément services à la personne — sont marquées
// `requis: false`. Les recopier ici aurait créé deux vérités qui finissent
// toujours par diverger : rendre un document facultatif dans un fichier sans
// le faire dans l'autre, et bloquer des prestataires en règle.
function documentsObligatoires() {
  return Object.keys(TYPES_DOCUMENTS).filter(t => TYPES_DOCUMENTS[t].requis);
}

async function prestataireEnRegle(proId) {
  const manques = [];

  const { data: pro } = await supabase.from('users')
    .select('stripe_account_id').eq('id', proId).single();

  if (!pro || !pro.stripe_account_id) {
    manques.push('Configurez vos paiements depuis votre profil pour pouvoir être réglé.');
  } else {
    try {
      const compte = await stripe.accounts.retrieve(pro.stripe_account_id);
      const pret = compte.charges_enabled &&
                   compte.capabilities && compte.capabilities.transfers === 'active';
      if (!pret) {
        manques.push('Votre configuration de paiement n\'est pas terminée — reprenez-la depuis votre profil.');
      }
    } catch (e) {
      // Stripe injoignable : on ne bloque pas un prestataire pour une panne qui
      // ne vient pas de lui. Le versement sera de toute façon vérifié plus tard.
      console.warn('Vérification Connect impossible (' + e.message + ') — prestataire non bloqué.');
    }
  }

  const { data: docs } = await supabase.from('documents_pro')
    .select('type, face, statut').eq('pro_id', proId);

  // Une pièce d'identité, ce sont DEUX faces. Ne vérifier que le type aurait
  // déclaré le dossier complet avec le seul recto validé — et le verso, celui
  // qui porte la date de validité, jamais regardé.
  const validees = new Set((docs || [])
    .filter(d => d.statut === 'valide')
    .map(d => d.type + '|' + (d.face || 'unique')));

  const absents = [];
  for (const type of documentsObligatoires()) {
    const faces = TYPES_DOCUMENTS[type].faces || ['unique'];
    if (faces.some(f => !validees.has(type + '|' + f))) absents.push(type);
  }

  if (absents.length) {
    manques.push('Documents à faire valider : ' +
      absents.map(t => (TYPES_DOCUMENTS[t] || {}).libelle || t).join(', ') + '.');
  }

  return { enRegle: manques.length === 0, manques };
}

// ═══════════════════════════════════════════════════════════════════════════
// UN PRIX DE DEVIS A UNE LIMITE HAUTE
//
// Le seul contrôle était « le prix doit être positif ». Un prestataire pouvait
// chiffrer un nettoyage de canapé à cinquante mille euros.
//
// CE N'EST PAS LA MALVEILLANCE QU'ON CRAINT, C'EST LA FAUTE DE FRAPPE
//
// Saisir 12000 au lieu de 120 arrive. Le client qui accepte sans regarder se
// voit débiter douze mille euros — remboursement Stripe, litige, client perdu.
// Le mal est fait avant que quiconque s'en aperçoive.
//
// LE PLAFOND EST GÉNÉREUX, DÉLIBÉRÉMENT
//
// Dix fois le tarif de référence le plus élevé de la prestation. Un canapé
// d'angle en cuir très sale peut légitimement coûter trois fois le tarif de
// base ; jamais trente. Le plafond n'est pas là pour discuter un prix, mais
// pour arrêter un chiffre impossible.
// ═══════════════════════════════════════════════════════════════════════════
function plafondDevis(prestationTexte) {
  // Une demande peut porter plusieurs prestations : le plafond est la somme
  // des plafonds, sinon un devis groupé légitime serait refusé.
  const types = String(prestationTexte || '')
    .split('+').map(t => t.trim().toLowerCase()).filter(Boolean);

  let total = 0;
  for (const type of types) {
    const config = PRESTATION_CONFIG[type];
    if (!config || !config.tierDefaults) {
      // Prestation inconnue — « autre », par exemple. On applique un plafond
      // large plutôt que de refuser : mieux vaut laisser passer un prix élevé
      // que bloquer une prestation légitime qu'on n'a pas prévue.
      total += 5000;
      continue;
    }
    const plusEleve = Math.max(...Object.values(config.tierDefaults));
    total += plusEleve * 10;
  }
  // Aucune prestation reconnue : on retombe sur le plafond large.
  return total > 0 ? total : 5000;
}

app.post('/api/devis', auth, async (req, res) => {
  try {
    const { demande_id, prix_ttc, description, creneau_propose } = req.body;
    if (!demande_id || !prix_ttc)
      return res.status(400).json({ error: 'Demande et prix requis.' });
    if (parseFloat(prix_ttc) <= 0)
      return res.status(400).json({ error: 'Le prix doit être positif.' });

    // Contrôle des justificatifs — le seul point de blocage du parcours
    // prestataire, et il arrive au moment où il est légitime.
    const { data: auteur } = await supabase.from('users')
      .select('type, siret, assurance_rc_pro').eq('id', req.user.id).single();
    // Aux justificatifs déclaratifs — SIRET et assurance — s'ajoutent
    // désormais deux conditions vérifiables : les paiements opérationnels et
    // les documents validés. Un seul point de contrôle, pour qu'ils ne
    // divergent jamais.
    const regle = await prestataireEnRegle(req.user.id);
    if (!regle.enRegle) {
      return res.status(403).json({
        error: 'Vous ne pouvez pas encore envoyer de devis. ' + regle.manques.join(' '),
        manques: regle.manques
      });
    }

    const manquants = justificatifsManquants(auteur);
    if (manquants.length) {
      return res.status(403).json({
        error: manquants.length === 2
          ? 'Avant votre premier devis, renseignez votre numéro SIRET et attestez de votre assurance RC Pro.'
          : (manquants[0] === 'siret'
              ? 'Avant votre premier devis, renseignez votre numéro SIRET.'
              : 'Avant votre premier devis, attestez de votre assurance RC Pro.'),
        justificatifs_manquants: manquants
      });
    }

    const { data: demande } = await supabase.from('demandes').select('*').eq('id', demande_id).single();

    // ── LE PRIX A UNE LIMITE HAUTE ────────────────────────────────────────
    // Le contrôle vient ICI et pas plus haut : le plafond dépend de la
    // prestation, qu'on ne connaît qu'après avoir lu la demande.
    //
    // Une faute de frappe — 12 000 au lieu de 120 — passait sans obstacle.
    if (demande) {
      const plafond = plafondDevis(demande.prestation);
      if (parseFloat(prix_ttc) > plafond) {
        return res.status(400).json({
          error: 'Ce montant dépasse la limite pour cette prestation ('
            + plafond.toLocaleString('fr-FR') + ' € maximum). '
            + 'Vérifiez que vous n\'avez pas ajouté un zéro de trop.'
        });
      }
    }
    if (!demande) return res.status(404).json({ error: 'Cette demande n\'existe plus. Elle a sans doute été supprimée ou annulée par le client.' });
    if (demande.statut === 'acceptee' || demande.statut === 'en_cours' || demande.statut === 'terminee' || demande.statut === 'annulee_client')
      return res.status(400).json({ error: 'Cette demande n\'est plus disponible.' });

    // Ne bloque que si un devis encore ACTIF existe déjà pour ce pro sur cette demande — un devis
    // qu'il a lui-même annulé, ou que le client a refusé, ne doit jamais l'empêcher de renvoyer
    // un nouveau devis (par exemple avec un prix différent) tant que la demande reste ouverte.
    const { data: existing } = await supabase.from('devis').select('id').eq('demande_id', demande_id).eq('societe_id', req.user.id).eq('statut', 'envoye').maybeSingle();
    if (existing) return res.status(400).json({ error: 'Vous avez déjà un devis en attente pour cette demande.' });

    const { data, error } = await supabase.from('devis').insert({
      demande_id: demande_id,
      societe_id: req.user.id,
      prix_ttc: parseFloat(prix_ttc),
      description: description || null,
      creneau_propose: creneau_propose || null,
      statut: 'envoye'
    }).select().single();

    if (error) { console.error('Erreur Supabase, message technique complet:', error); return res.status(400).json({ error: traduireErreurSupabase(error.message) }); }
    await supabase.from('demandes').update({ statut: 'devis_recus' }).eq('id', demande_id);

    // 📧 Email 2/8 : nouveau devis reçu → client
    const { data: client } = await supabase.from('users').select('email, prenom').eq('id', demande.client_id).single();
    if (client) {
      sendEmail('nouveau_devis', client.email, {
        compteId: client.id,
        prenom: client.prenom,
        prestation: demande.prestation,
        prix: parseFloat(prix_ttc),
        demandeId: demande_id
      });
      envoyerNotificationPush(demande.client_id, {
        titre: 'Nouveau devis reçu',
        corps: 'Un devis de ' + parseFloat(prix_ttc) + '€ pour ' + demande.prestation,
        url: '/#devis'
      });
    }

    res.status(201).json(data);
  } catch (e) {
    erreurServeur(res, 'POST /api/devis', e);
  }
});

// Devis reçus par un client pour une demande (avec infos pro)
app.get('/api/devis/demande/:id', auth, async (req, res) => {
  const { data: demande } = await supabase.from('demandes').select('client_id, statut').eq('id', req.params.id).single();
  if (!demande) return res.status(404).json({ error: 'Cette demande n\'existe plus. Elle a sans doute été supprimée ou annulée par le client.' });
  if (demande.client_id !== req.user.id) return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });

  const { data: devis } = await supabase.from('devis').select('*').eq('demande_id', req.params.id).order('prix_ttc', { ascending: true });
  if (!devis || !devis.length) return res.json([]);

  const proIds = [...new Set(devis.map(d => d.societe_id))];
  const { data: pros } = await supabase.from('users').// `siret` est ajouté pour le devis imprimable : les articles R.123-237 et
      // R.123-238 du Code de commerce imposent que tout document émis par une
      // entreprise porte son identification. Sans lui, le champ restait vide et
      // le devis n'était pas conforme.
      select('id, prenom, nom, note_moyenne, taux_fiabilite, photo, siret').in('id', proIds);
    await signerPhotosDeLot(pros);
  const proMap = {};
  (pros || []).forEach(p => proMap[p.id] = p);

  // Le code de validation (à donner au prestataire à la fin) n'est attaché qu'au devis accepté
  // d'une prestation en cours — jamais avant le paiement, jamais une fois terminée.
  let codeValidation = null;
  if (demande.statut === 'en_cours') {
    const { data: paiement } = await supabase.from('paiements').select('code_validation').eq('demande_id', req.params.id).eq('statut', 'paye').maybeSingle();
    if (paiement) codeValidation = paiement.code_validation;
  }

  const enriched = devis.map(d => ({ ...d, pro: proMap[d.societe_id] || null, code_validation: d.statut === 'accepte' ? codeValidation : null }));
  // Trie : les pros avec un taux de fiabilité < 80% passent en dernier
  enriched.sort((a, b) => {
    const tauxA = a.pro?.taux_fiabilite ?? 100;
    const tauxB = b.pro?.taux_fiabilite ?? 100;
    const lowA = tauxA < 80 ? 1 : 0;
    const lowB = tauxB < 80 ? 1 : 0;
    if (lowA !== lowB) return lowA - lowB;
    return a.prix_ttc - b.prix_ttc;
  });
  res.json(enriched);
});

// Tous les devis reçus par le client connecté, pour toutes ses demandes, en une seule requête —
// remplace l'ancien fonctionnement qui faisait une requête réseau séparée par demande (un vrai
// problème de performance et de volume de requêtes une fois combiné au rafraîchissement automatique).
app.get('/api/devis/mes-devis-recus', auth, async (req, res) => {
  try {
    // Signées plus bas, une fois le lot complet rassemblé.
    const { data: demandes } = await supabase.from('demandes').// `adresse` est ajoutée pour le devis imprimable : un devis de prestation à
      // domicile doit porter le LIEU d'exécution — attendu par le client, et
      // décisif en cas de litige.
      // `notes` porte le détail de chaque prestation. Sans elle, le devis
      // imprimable affichait « Prestation de nettoyage » sans dire laquelle —
      // ni ce qu'elle comprend.
      select('id, prestation, statut, photos_avant, photos_apres, prestation_demarree_le, creneau, creneau_propose, creneau_propose_par, adresse, notes')
      .eq('client_id', req.user.id).in('statut', ['devis_recus', 'acceptee', 'en_cours', 'terminee']);
    if (!demandes || !demandes.length) return res.json([]);

    const demandeIds = demandes.map(d => d.id);
    const demandeMap = {};
    demandes.forEach(d => demandeMap[d.id] = d);

    const { data: devis } = await supabase.from('devis').select('*').in('demande_id', demandeIds);
    if (!devis || !devis.length) return res.json([]);

    const proIds = [...new Set(devis.map(d => d.societe_id))];
    const { data: pros } = await supabase.from('users').// `siret` : R.123-237 et R.123-238 imposent que tout document émis par une
      // entreprise porte son identification. Sans lui, le champ du devis restait
      // vide et le document n'était pas conforme.
      select('id, prenom, nom, note_moyenne, taux_fiabilite, photo, siret').in('id', proIds);
    await signerPhotosDeLot(pros);
    const proMap = {};
    (pros || []).forEach(p => proMap[p.id] = p);

    // Codes de validation des demandes en cours, récupérés en une seule requête groupée
    const demandeIdsEnCours = demandes.filter(d => d.statut === 'en_cours').map(d => d.id);
    const codeMap = {};
    if (demandeIdsEnCours.length) {
      const { data: paiementsEnCours } = await supabase.from('paiements').select('demande_id, code_validation').in('demande_id', demandeIdsEnCours).eq('statut', 'paye');
      (paiementsEnCours || []).forEach(p => codeMap[p.demande_id] = p.code_validation);
    }

    const enriched = devis.map(d => {
      const demandeInfo = demandeMap[d.demande_id];
      return {
        ...d,
        pro: proMap[d.societe_id] || null,
        prestation: demandeInfo ? demandeInfo.prestation : null,
        demande_statut: demandeInfo ? demandeInfo.statut : null,
        code_validation: d.statut === 'accepte' ? (codeMap[d.demande_id] || null) : null,
        photos_avant: demandeInfo && demandeInfo.photos_avant ? JSON.parse(demandeInfo.photos_avant) : [],
        photos_apres: demandeInfo && demandeInfo.photos_apres ? JSON.parse(demandeInfo.photos_apres) : [],
        prestation_demarree: demandeInfo ? Boolean(demandeInfo.prestation_demarree_le) : false,
        creneau: demandeInfo ? demandeInfo.creneau : null,
        creneau_propose: demandeInfo ? demandeInfo.creneau_propose : null,
        creneau_propose_par: demandeInfo ? demandeInfo.creneau_propose_par : null
      };
    });

    // Les photos avant/après voyagent ici à la racine de chaque devis, et non
    // dans un objet `demande` : le lot est donc signé tel quel.
    await signerPhotosDesDemandes(enriched);

    res.json(enriched);
  } catch (e) {
    erreurServeur(res, 'GET /api/devis/mes-devis-recus', e);
  }
});
app.get('/api/devis/mes-devis', auth, async (req, res) => {
  try {
    const { data: devis } = await supabase.from('devis').select('*').eq('societe_id', req.user.id).order('created_at', { ascending: false });
    if (!devis || !devis.length) return res.json([]);

    const demandeIds = [...new Set(devis.map(d => d.demande_id))];
    const { data: demandes } = await supabase.from('demandes').select('id, prestation, adresse, statut, numero_anonyme, client_id, notes, creneau, photos_avant, photos_apres, prestation_demarree_le, creneau_propose, creneau_propose_par').in('id', demandeIds);
    const demandeMap = {};
    (demandes || []).forEach(d => demandeMap[d.id] = d);

    const enriched = devis.map(d => {
      const demandeInfo = demandeMap[d.demande_id];
      const demandeAvecPhotos = demandeInfo ? {
        ...demandeInfo,
        photos_avant: demandeInfo.photos_avant ? JSON.parse(demandeInfo.photos_avant) : [],
        photos_apres: demandeInfo.photos_apres ? JSON.parse(demandeInfo.photos_apres) : [],
        prestation_demarree: Boolean(demandeInfo.prestation_demarree_le)
      } : null;
      return { ...d, demande: demandeAvecPhotos };
    });
    // Ici les photos sont portées par l'objet `demande` imbriqué dans chaque devis.
    await signerPhotosDesDemandes(enriched.map(d => d.demande).filter(Boolean));
    res.json(enriched);
  } catch (e) {
    erreurServeur(res, 'GET /api/devis/mes-devis', e);
  }
});

app.post('/api/devis/:id/accepter', auth, async (req, res) => {
  try {
    const { data: devis } = await supabase.from('devis').select('*').eq('id', req.params.id).single();
    if (!devis) return res.status(404).json({ error: 'Ce devis n\'existe plus. Il a peut-être été retiré par le prestataire, ou la demande a été supprimée.' });

    const { data: demande } = await supabase.from('demandes').select('*').eq('id', devis.demande_id).single();
    if (!demande || demande.client_id !== req.user.id) return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });
    if (demande.statut === 'acceptee') return res.status(400).json({ error: 'Une demande a déjà été acceptée pour cette prestation.' });

    // La demande est réservée par écriture conditionnelle. Le contrôle ci-dessus
    // ne suffisait pas : entre lui et l'écriture, une seconde requête — double-tap
    // sur mobile, ou deux onglets — passait le même test. Deux devis se
    // retrouvaient acceptés, et deux prestataires recevaient « Devis accepté ».
    const gagnee = await reserverLigne('demandes', devis.demande_id, ['en_attente', 'devis_recus'], 'acceptee');
    if (!gagnee) {
      return res.status(409).json({ error: 'Un devis vient d\'être accepté pour cette prestation.' });
    }

    // ── TRENTE MINUTES POUR PAYER ─────────────────────────────────────────
    // Le devis n'expirait qu'une heure APRÈS le créneau : accepté le lundi
    // pour une prestation le samedi, il restait valable toute la semaine sans
    // règlement.
    //
    // Il fallait donc prévenir le prestataire dès l'acceptation — sinon il
    // prenait une autre course pour ce créneau et découvrait le paiement le
    // vendredi. D'où les trois messages successifs, et leur confusion.
    //
    // Avec une échéance courte, il n'a plus rien à savoir avant le paiement :
    // la fenêtre est trop brève pour qu'il s'engage ailleurs.
    // ── L'ÉCHÉANCE NE DÉPASSE JAMAIS LE CRÉNEAU ───────────────────────────
    // Trente minutes fixes créaient une contradiction : accepter un devis dix
    // minutes avant l'heure de la prestation laissait trente minutes pour
    // payer — le créneau passait avant l'échéance.
    //
    // Le devis restait alors « réservé » sur une prestation déjà manquée, et
    // le prestataire ne recevait jamais rien.
    //
    // On plafonne à l'heure du créneau, avec un plancher de cinq minutes :
    // en dessous, personne n'a le temps de saisir une carte, et refuser
    // l'acceptation serait plus honnête qu'une échéance impossible.
    let finEcheance = Date.now() + 30 * 60 * 1000;
    const instantCreneauDevis = instantDuCreneau(demande.creneau);
    if (instantCreneauDevis && instantCreneauDevis < finEcheance) {
      finEcheance = Math.max(instantCreneauDevis, Date.now() + 5 * 60 * 1000);
    }
    const echeance = new Date(finEcheance).toISOString();
    await supabase.from('devis')
      .update({ statut: 'accepte', paiement_avant: echeance })
      .eq('id', req.params.id);

    // ── LES AUTRES DEVIS NE SONT PAS ENCORE REFUSÉS ───────────────────────
    // Ils l'étaient immédiatement. Si le client ne payait pas, il perdait
    // toutes ses options d'un coup — et devait tout recommencer.
    //
    // Ils sont désormais refusés AU PAIEMENT, quand le choix devient réel.

    // ── AUCUN MESSAGE AU PRESTATAIRE À CE STADE ───────────────────────────
    // Il en recevait deux — notification et courriel — annonçant un devis
    // « retenu » qui ne garantissait rien. Quel que soit le soin des mots, un
    // artisan qui lit « votre devis a été retenu » peut s'organiser, refuser
    // une course, voire partir.
    //
    // Le seul message qui compte part au PAIEMENT, et il veut dire : vous
    // pouvez y aller. Un message qui ne demande aucune interprétation vaut
    // mieux que trois bien rédigés.

    res.json({ message: 'Devis accepté !', demande_id: devis.demande_id, societe_id: devis.societe_id });
  } catch (e) {
    erreurServeur(res, 'POST /api/devis/:id/accepter', e);
  }
});

app.post('/api/devis/:id/refuser', auth, async (req, res) => {
  try {
    const { data: devis } = await supabase.from('devis').select('*').eq('id', req.params.id).single();
    if (!devis) return res.status(404).json({ error: 'Ce devis n\'existe plus. Il a peut-être été retiré par le prestataire, ou la demande a été supprimée.' });

    const { data: demande } = await supabase.from('demandes').select('*').eq('id', devis.demande_id).single();
    if (!demande || demande.client_id !== req.user.id) return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });

    await supabase.from('devis').update({ statut: 'refuse' }).eq('id', req.params.id);

    // 📧 Email "devis refusé" désactivé pour l'instant (peu actionnable, peut être mal vécu par les pros).
    // Pour le réactiver, décommentez le bloc ci-dessous :
    // const { data: proRefuse } = await supabase.from('users').select('email, prenom').eq('id', devis.societe_id).single();
    // if (proRefuse) {
    //   sendEmail('devis_refuse', proRefuse.email, { compteId: proRefuse.id, prenom: proRefuse.prenom, prestation: demande.prestation });
    // }

    res.json({ message: 'Devis refusé.' });
  } catch (e) {
    erreurServeur(res, 'POST /api/devis/:id/refuser', e);
  }
});

// Le pro annule un devis qu'il avait fait accepter par le client
app.post('/api/devis/:id/annuler-pro', auth, async (req, res) => {
  try {
    const { data: devis } = await supabase.from('devis').select('*').eq('id', req.params.id).single();
    if (!devis) return res.status(404).json({ error: 'Ce devis n\'existe plus. Il a peut-être été retiré par le prestataire, ou la demande a été supprimée.' });
    if (devis.societe_id !== req.user.id) return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });
    if (devis.statut !== 'accepte') return res.status(400).json({ error: 'Ce devis n\'est pas accepté.' });

    const { data: demande } = await supabase.from('demandes').select('*').eq('id', devis.demande_id).single();
    if (!demande) return res.status(404).json({ error: 'Cette demande n\'existe plus. Elle a sans doute été supprimée ou annulée par le client.' });

    // Vérifie le délai de 24h avant le créneau (signalé, mais jamais bloquant — cohérent avec l'annulation côté client)
    let tardive = false;
    if (demande.creneau) {
      // Même correction que pour l'annulation côté client : le délai de 24 h se
      // mesure par rapport à l'heure française du rendez-vous.
      const dateCreneau = creneauVersInstant(demande.creneau);
      if (dateCreneau) {
        const heuresRestantes = (dateCreneau - new Date()) / (1000 * 60 * 60);
        tardive = heuresRestantes < 24;
      }
    }

    // Si la prestation était déjà payée (en cours), rembourse automatiquement le client avant
    // de remettre la demande en circulation pour d'autres pros
    const remboursement = demande.statut === 'en_cours' ? await rembourserPaiementSiPaye(demande.id) : { rembourse: false };

    // Système de sanction progressive : chaque annulation d'un devis déjà accepté fait baisser le
    // taux de fiabilité du pro de 20 points (déjà utilisé ailleurs pour le classement des devis).
    // En dessous de 40% (après 3 annulations), le compte est suspendu automatiquement — il faudra
    // contacter le support Gleam pour être réactivé. Une annulation isolée reste sans grande
    // conséquence ; c'est la répétition qui devient pénalisante.
    const { data: proActuel } = await supabase.from('users').select('taux_fiabilite, nombre_annulations_pro, email, prenom').eq('id', req.user.id).single();
    const tauxActuel = (proActuel && typeof proActuel.taux_fiabilite === 'number') ? proActuel.taux_fiabilite : 100;
    const nouveauTaux = Math.max(0, tauxActuel - 20);
    const nombreAnnulations = ((proActuel && proActuel.nombre_annulations_pro) || 0) + 1;
    const suspendu = nouveauTaux <= 40;

    const misAJourPro = { taux_fiabilite: nouveauTaux, nombre_annulations_pro: nombreAnnulations };
    if (suspendu) misAJourPro.disponible = false;
    await supabase.from('users').update(misAJourPro).eq('id', req.user.id);

    if (suspendu && proActuel) {
      sendEmail('compte_suspendu', proActuel.email, { compteId: proActuel.id, prenom: proActuel.prenom || '' }).catch(e => console.error('Email compte_suspendu:', e));
    }

    // Annule le devis, puis vérifie s'il reste d'autres devis actifs pour cette demande : s'il n'y
    // en a plus aucun, la demande redevient "en attente" (comme neuve) ; sinon elle reste
    // "devis_recus" puisque le client a encore d'autres offres à consulter.
    await supabase.from('devis').update({ statut: 'annule_pro' }).eq('id', req.params.id);
    const { data: autresDevisActifs } = await supabase.from('devis').select('id').eq('demande_id', devis.demande_id).eq('statut', 'envoye');
    const nouveauStatut = (autresDevisActifs && autresDevisActifs.length) ? 'devis_recus' : 'en_attente';
    await supabase.from('demandes').update({ statut: nouveauStatut }).eq('id', devis.demande_id);

    // 📧 Email 7/8 : annulation pro → client
    const { data: client } = await supabase.from('users').select('email, prenom').eq('id', demande.client_id).single();
    if (client) {
      sendEmail('annulation_pro', client.email, {
        compteId: client.id,
        prenom: client.prenom,
        prestation: demande.prestation,
        creneau: demande.creneau,
        demandeId: devis.demande_id
      });
    }

    res.json({
      message: suspendu
        ? 'Devis annulé. Votre compte a été suspendu suite à plusieurs annulations — contactez le support Gleam pour être réactivé.'
        : 'Devis annulé. Le client a été notifié et peut recevoir d\'autres devis.',
      tardive,
      rembourse: remboursement.rembourse,
      taux_fiabilite: nouveauTaux,
      suspendu
    });
  } catch (e) {
    console.error(e);
    erreurServeur(res, 'POST /api/devis/:id/annuler-pro', e);
  }
});

// ══════════════ MESSAGES ══════════════

// Vérifie que l'utilisateur connecté a le droit de participer à la conversation de cette demande
// (le client propriétaire, ou le pro dont le devis a été accepté) — protège la confidentialité des échanges.
// ═══════════════════════════════════════════════════════════════════════════
// LA CONVERSATION S'OUVRE AU PAIEMENT, PAS À L'ACCEPTATION
//
// La fonction ouvrait l'accès dès qu'un devis portait le statut « accepte » —
// c'est-à-dire dès que le client cliquait, AVANT tout règlement.
//
// L'application masquait bien le bouton « Discuter » côté client. Mais la
// route restait ouverte : n'importe quel appel direct passait, et le
// prestataire, lui, y accédait sans obstacle.
//
// POURQUOI CELA COMPTE
//
// Toute la protection de Gleam repose sur le fait que les deux parties ne se
// parlent qu'une fois l'argent bloqué. Avant paiement, une conversation permet
// d'échanger un numéro et de conclure en dehors de la plateforme — le serveur
// bloque déjà les numéros de téléphone, précisément pour cette raison.
//
// Ouvrir la conversation avant le paiement, c'était laisser la porte que ce
// blocage cherche à fermer.
//
// LE CLIENT NON PLUS N'Y ACCÈDE PLUS AVANT
//
// Il en est propriétaire, mais il n'a personne à qui parler tant qu'aucun
// prestataire n'est engagé. Et c'est lui qui a le plus intérêt à contourner.
// ═══════════════════════════════════════════════════════════════════════════
async function peutAccederConversation(demandeId, userId) {
  const { data: demande } = await supabase.from('demandes')
    .select('client_id, statut').eq('id', demandeId).single();
  if (!demande) return false;

  // Un devis retenu ne suffit pas : il faut qu'il soit PAYÉ.
  const { data: paiement } = await supabase.from('paiements')
    .select('id').eq('demande_id', demandeId)
    .in('statut', ['paye', 'libere', 'liberation_en_cours', 'rembourse_partiel'])
    .maybeSingle();

  if (!paiement) return false;

  if (demande.client_id === userId) return true;

  const { data: devisAccepte } = await supabase.from('devis')
    .select('societe_id').eq('demande_id', demandeId).eq('statut', 'accepte').maybeSingle();
  return !!(devisAccepte && devisAccepte.societe_id === userId);
}

// ══════════════ APPEL MASQUÉ (Twilio Voice) ══════════════
// Permet au client et au pro de s'appeler par téléphone sans jamais se voir le numéro l'un de
// l'autre — le même principe que Uber, Deliveroo, Airbnb (numéro intermédiaire qui relaie l'appel).
// Nécessite un compte Twilio configuré (TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN,
// TWILIO_PHONE_NUMBER) — tant que ces variables ne sont pas renseignées, la fonctionnalité
// répond simplement "non disponible" plutôt que de planter.
const twilioConfigure = !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_PHONE_NUMBER);
const twilioClient = twilioConfigure ? require('twilio')(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN) : null;

// Déclenche un appel masqué pour une demande donnée : appelle d'abord celui qui a fait la demande
// (l'appelant), et une fois qu'il décroche, le relie à l'autre partie — sans qu'aucun des deux ne
// voie jamais le vrai numéro de l'autre (seul le numéro Twilio partagé s'affiche des deux côtés).
app.post('/api/appels/demarrer', auth, async (req, res) => {
  try {
    if (!twilioConfigure)
      return res.status(503).json({ error: 'L\'appel depuis l\'application n\'est pas encore configuré. Contactez le support Gleam.' });

    const { demande_id } = req.body;
    if (!demande_id) return res.status(400).json({ error: 'Demande requise.' });
    const peutAcceder = await peutAccederConversation(demande_id, req.user.id);
    if (!peutAcceder) return res.status(403).json({ error: 'Accès refusé à cette conversation.' });

    const { data: demande } = await supabase.from('demandes').select('client_id').eq('id', demande_id).single();
    const { data: devisAccepte } = await supabase.from('devis').select('societe_id').eq('demande_id', demande_id).eq('statut', 'accepte').maybeSingle();
    if (!devisAccepte) return res.status(400).json({ error: 'Aucun prestataire encore associé à cette demande.' });

    const autrePartieId = req.user.id === demande.client_id ? devisAccepte.societe_id : demande.client_id;
    const { data: autrePartie } = await supabase.from('users').select('telephone, prenom').eq('id', autrePartieId).single();
    const { data: appelant } = await supabase.from('users').select('telephone').eq('id', req.user.id).single();
    if (!autrePartie || !autrePartie.telephone) return res.status(400).json({ error: 'Le numéro de l\'autre partie n\'est pas renseigné.' });
    if (!appelant || !appelant.telephone) return res.status(400).json({ error: 'Renseignez votre numéro de téléphone dans votre profil pour pouvoir appeler.' });

    // Appelle d'abord l'appelant (celui qui vient de cliquer sur "Appeler") — une fois qu'il
    // décroche, Twilio suit les instructions du webhook /api/appels/twiml, qui le relie à l'autre
    // numéro. Le numéro affiché des deux côtés est celui de Twilio (callerId), jamais le vrai.
    const call = await twilioClient.calls.create({
      to: appelant.telephone,
      from: process.env.TWILIO_PHONE_NUMBER,
      url: (process.env.FRONTEND_API_URL || '') + '/api/appels/twiml?numero_a_relier='
        + encodeURIComponent(autrePartie.telephone)
        + '&jeton=' + signerNumeroAppel(autrePartie.telephone)
    });

    res.json({ message: 'Appel en cours, décrochez votre téléphone.', callSid: call.sid });
  } catch (e) {
    console.error('Erreur démarrage appel masqué:', e.message);
    res.status(500).json({ error: 'Impossible de démarrer l\'appel pour le moment.' });
  }
});

// Webhook appelé par Twilio une fois que l'appelant a décroché — répond avec les instructions
// TwiML qui relient l'appel au numéro de l'autre partie, en masquant le numéro de l'appelant.
app.post('/api/appels/twiml', (req, res) => {
  const numeroARelier = req.query.numero_a_relier;
  res.type('text/xml');

  // Sans signature valide, on raccroche. Le numéro n'est jamais composé.
  const attendu = signerNumeroAppel(numeroARelier);
  const fourni = String(req.query.jeton || '');
  // La longueur est vérifiée AVANT la comparaison. Sans cela, `padEnd(32).slice(0,32)`
  // tronquait un jeton trop long : « bonJeton » + « zzzz » redevenait « bonJeton »
  // et passait. Mon propre test l'a trouvé — huit cas d'attaque, un seul passait.
  if (fourni.length !== attendu.length || !crypto.timingSafeEqual(
        Buffer.from(fourni), Buffer.from(attendu))) {
    console.warn('⚠️  Webhook d\'appel refusé — signature absente ou invalide.');
    return res.send('<?xml version="1.0" encoding="UTF-8"?><Response><Reject/></Response>');
  }

  res.send(
    '<?xml version="1.0" encoding="UTF-8"?>' +
    '<Response><Say language="fr-FR">Mise en relation avec votre correspondant Gleam.</Say>' +
    '<Dial callerId="' + (process.env.TWILIO_PHONE_NUMBER || '') + '">' + escapeXml(numeroARelier || '') + '</Dial></Response>'
  );
});
function escapeXml(s) { return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

// ── SIGNATURE DES APPELS TWILIO ─────────────────────────────────────────────
// Le webhook /api/appels/twiml est appelé PAR Twilio, donc il ne peut pas être
// protégé par un jeton d'utilisateur. Sans autre garde, n'importe qui pouvait
// lui demander de composer le numéro de son choix — facturé sur le compte
// Gleam. C'est la fraude au péage, et elle est automatisée par des robots qui
// balayent les URL publiques.
//
// On signe le numéro au moment où le serveur crée l'appel, et le webhook
// vérifie la signature. Sans JWT_SECRET, aucune URL valide ne peut être
// fabriquée.
//
// Pourquoi pas twilio.validateRequest() : la méthode officielle reconstruit
// l'URL exacte de la requête, et derrière un proxy comme Railway elle échoue
// si X-Forwarded-Proto n'est pas pris en compte. Un webhook de téléphonie qui
// rejette les appels légitimes est pire que le problème d'origine.
function signerNumeroAppel(numero) {
  return crypto.createHmac('sha256', process.env.JWT_SECRET || '')
    .update(String(numero || '')).digest('hex').slice(0, 32);
}

// Détecte un numéro de téléphone français reconstitué en ne gardant que les chiffres d'un texte
// (ex: "0633" + "233367" mis bout à bout donne bien "0633233367", un numéro valide, même si
// chaque message pris séparément semblait innocent).
function contientNumeroReconstitue(texte) {
  const chiffresSeuls = texte.replace(/\D/g, '');
  return /0[1-9]\d{8}/.test(chiffresSeuls);
}

app.post('/api/messages', auth, async (req, res) => {
  try {
    const { demande_id, contenu } = req.body;
    if (!demande_id || !contenu || !contenu.trim())
      return res.status(400).json({ error: 'Message vide.' });

    // Vérifie non seulement CE message, mais aussi les derniers messages envoyés par la même
    // personne dans cette conversation, sur une courte période — pour attraper une tentative de
    // partager un numéro en plusieurs étapes (un message avec "0633", un autre avec "233367").
    const cinqMinutesAvant = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const { data: messagesRecents } = await supabase.from('messages').select('contenu')
      .eq('demande_id', demande_id).eq('expediteur_id', req.user.id)
      .gte('created_at', cinqMinutesAvant).order('created_at', { ascending: true }).limit(5);
    const contenuRecent = (messagesRecents || []).map(m => m.contenu).join(' ') + ' ' + contenu;

    if (contientCoordonnees(contenu) || contientNumeroReconstitue(contenuRecent))
      return res.status(400).json({ error: 'Gleam bloque les coordonnées avant paiement.', blocked: true });

    const { data: demande } = await supabase.from('demandes').select('*').eq('id', demande_id).single();
    if (!demande) return res.status(404).json({ error: 'Cette demande n\'existe plus. Elle a sans doute été supprimée ou annulée par le client.' });
    if (!(await peutAccederConversation(demande_id, req.user.id)))
      return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });

    const { data, error } = await supabase.from('messages').insert({
      demande_id: demande_id,
      expediteur_id: req.user.id,
      contenu: contenu.trim(),
      type: 'texte'
    }).select().single();

    if (error) { console.error('Erreur Supabase, message technique complet:', error); return res.status(400).json({ error: traduireErreurSupabase(error.message) }); }

    // 📧 Email 8/8 : nouveau message → destinataire (client ou pro selon l'expéditeur)
    const { data: expediteur } = await supabase.from('users').select('prenom, type').eq('id', req.user.id).single();
    let destinataireId = null;

    if (expediteur && isProType(expediteur.type)) {
      destinataireId = demande.client_id;
    } else {
      const { data: devisAccepte } = await supabase.from('devis').select('societe_id').eq('demande_id', demande_id).eq('statut', 'accepte').maybeSingle();
      destinataireId = devisAccepte ? devisAccepte.societe_id : null;
    }

    if (destinataireId) {
      const { data: destinataire } = await supabase.from('users').select('email, prenom').eq('id', destinataireId).single();
      if (destinataire) {
        sendEmail('nouveau_message', destinataire.email, {
          compteId: destinataire.id,
          prenom: destinataire.prenom,
          expediteurNom: (expediteur && expediteur.prenom) || 'Un utilisateur',
          prestation: demande.prestation,
          apercu: contenu.trim().slice(0, 100),
          demandeId: demande_id
        });
        envoyerNotificationPush(destinataireId, {
          titre: 'Nouveau message',
          corps: ((expediteur && expediteur.prenom) || 'Un utilisateur') + ' : ' + contenu.trim().slice(0, 80),
          url: '/#messages'
        });
      }
    }

    res.status(201).json(data);
  } catch (e) {
    erreurServeur(res, 'POST /api/messages', e);
  }
});

app.get('/api/messages/:demande_id', auth, async (req, res) => {
  if (!(await peutAccederConversation(req.params.demande_id, req.user.id)))
    return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });
  const { data } = await supabase.from('messages').select('*').eq('demande_id', req.params.demande_id).order('created_at', { ascending: true });
  res.json(data || []);
});

// Liste des conversations actives pour l'utilisateur connecté (client ou pro)
// ═══════════════════════════════════════════════════════════════════════════
// POURQUOI LES PHOTOS NE PARTENT PLUS DANS LES LISTES
//
// Les photos de profil sont stockées en base64 DANS la table users : jusqu'à
// 48 Ko par personne, 10 Ko en moyenne.
//
// Les routes de liste — conversations, devis reçus, favoris — les renvoyaient
// à chaque appel. Or l'application sonde toutes les 15 à 20 secondes, et la
// discussion toutes les 6.
//
// Relevé dans la base : 109 383 lectures de la table users, 787 062 lignes
// lues. À 11 Ko la ligne, cela fait environ 8 Go pour cette seule table — sur
// un quota mensuel de 5,5 Go, avec 14 utilisateurs et 7 demandes.
//
// Les listes reçoivent désormais le nom et la note. L'application affiche les
// initiales, ce qu'elle sait déjà faire. La photo reste servie par /auth/me,
// appelée une fois par session, et par les écrans de profil.
//
// Le vrai correctif reste à faire : sortir les photos de la base et les mettre
// dans le stockage, qui est prévu pour ça. Ceci arrête l'hémorragie.
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/conversations', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('type').eq('id', req.user.id).single();
    let demandeIds = [];

    if (isProType(user?.type)) {
      const { data: devis } = await supabase.from('devis').select('demande_id').eq('societe_id', req.user.id).eq('statut', 'accepte');
      demandeIds = [...new Set((devis || []).map(d => d.demande_id))];
    } else {
      const { data: demandes } = await supabase.from('demandes').select('id').eq('client_id', req.user.id);
      demandeIds = (demandes || []).map(d => d.id);
    }

    // ── UNE CONVERSATION N'EXISTE QU'APRÈS PAIEMENT ──────────────────────
    // La liste retenait tout devis « accepte » — donc dès le clic du client,
    // avant tout règlement. L'onglet Messages ouvrait ainsi une conversation
    // que les cartes de devis, elles, masquaient correctement.
    //
    // Deux chemins vers le même écran, deux règles différentes : c'est le
    // second qui laissait passer.
    //
    // Toute la protection de Gleam repose sur le fait que les deux parties ne
    // se parlent qu'une fois l'argent bloqué — le serveur refuse d'ailleurs
    // les numéros de téléphone pour cette raison exacte.
    if (demandeIds.length) {
      const { data: payees } = await supabase.from('paiements')
        .select('demande_id')
        .in('demande_id', demandeIds)
        .in('statut', ['paye', 'libere', 'liberation_en_cours', 'rembourse_partiel']);
      const ensemblePayees = new Set((payees || []).map(p => p.demande_id));
      demandeIds = demandeIds.filter(id => ensemblePayees.has(id));
    }

    if (!demandeIds.length) return res.json([]);

    const { data: demandes } = await supabase.from('demandes').select('*').in('id', demandeIds);

    // Tout ce qui suit se fait en requêtes groupées (une poignée au total, quel que soit le nombre
    // de conversations) — plutôt qu'une requête séparée par conversation, qui devenait un vrai
    // problème de volume une fois combiné au rafraîchissement automatique.
    const { data: tousMessages } = await supabase.from('messages').select('*').in('demande_id', demandeIds).order('created_at', { ascending: false });
    const dernierMessageParDemande = {};
    (tousMessages || []).forEach(m => { if (!dernierMessageParDemande[m.demande_id]) dernierMessageParDemande[m.demande_id] = m; });

    let autrePartieParDemande = {};
    if (isProType(user?.type)) {
      const clientIds = [...new Set((demandes || []).map(d => d.client_id))];
      const { data: clients } = await supabase.from('users').select('id, prenom, nom, note_moyenne, photo').in('id', clientIds);
    await signerPhotosDeLot(clients);
      const clientMap = {};
      (clients || []).forEach(c => clientMap[c.id] = c);
      (demandes || []).forEach(d => { autrePartieParDemande[d.id] = clientMap[d.client_id] || null; });
    } else {
      const { data: devisAcceptes } = await supabase.from('devis').select('demande_id, societe_id').in('demande_id', demandeIds).eq('statut', 'accepte');
      const proIdParDemande = {};
      (devisAcceptes || []).forEach(dv => { proIdParDemande[dv.demande_id] = dv.societe_id; });
      const proIds = [...new Set(Object.values(proIdParDemande))];
      const { data: pros } = await supabase.from('users').select('id, prenom, nom, note_moyenne, photo').in('id', proIds);
    await signerPhotosDeLot(pros);
      const proMap = {};
      (pros || []).forEach(p => proMap[p.id] = p);
      Object.keys(proIdParDemande).forEach(demId => { autrePartieParDemande[demId] = proMap[proIdParDemande[demId]] || null; });
    }

    const conversations = (demandes || []).map(d => {
      const lastMsg = dernierMessageParDemande[d.id] || null;
      return {
        demande_id: d.id,
        prestation: d.prestation,
        statut: d.statut,
        numero_anonyme: d.numero_anonyme,
        dernier_message: lastMsg ? lastMsg.contenu : null,
        dernier_message_date: lastMsg ? lastMsg.created_at : d.created_at,
        dernier_message_expediteur_id: lastMsg ? lastMsg.expediteur_id : null,
        autre_partie: autrePartieParDemande[d.id] || null
      };
    });

    conversations.sort((a, b) => new Date(b.dernier_message_date) - new Date(a.dernier_message_date));
    res.json(conversations);
  } catch (e) {
    console.error(e);
    erreurServeur(res, 'GET /api/conversations', e);
  }
});

// ══════════════ PAIEMENTS ══════════════

// Crée (si besoin) le compte Stripe Connect du pro, puis renvoie un lien d'inscription hébergé
// par Stripe lui-même — Gleam ne collecte ni ne stocke jamais l'IBAN ou l'identité du pro,
// tout se passe directement chez Stripe, qui gère la conformité (DSP2, vérification d'identité...).
app.post('/api/paiements/connect/onboarding', auth, exigerEmailVerifie, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('type, stripe_account_id, email').eq('id', req.user.id).single();
    if (!user || !isProType(user.type)) return res.status(403).json({ error: 'Cette action est réservée aux comptes prestataires. Votre compte est un compte client.' });

    let accountId = user.stripe_account_id;
    if (!accountId) {
      const account = await stripe.accounts.create({
        type: 'express',
        email: user.email,
        capabilities: { transfers: { requested: true } },
        business_type: 'individual'
      });
      accountId = account.id;
      await supabase.from('users').update({ stripe_account_id: accountId }).eq('id', req.user.id);
    }

    const accountLink = await stripe.accountLinks.create({
      account: accountId,
      refresh_url: `${process.env.FRONTEND_URL || 'https://gleam-app.fr/'}#paiements-refresh`,
      return_url: `${process.env.FRONTEND_URL || 'https://gleam-app.fr/'}#paiements-retour`,
      type: 'account_onboarding'
    });

    res.json({ url: accountLink.url });
  } catch (e) {
    console.error('Stripe Connect onboarding:', e);
    res.status(500).json({ error: 'Impossible de démarrer la configuration des paiements. Réessayez dans un instant.' });
  }
});

// Vérifie où en est le pro dans la configuration de ses paiements (jamais configuré / en cours / prêt)
app.get('/api/paiements/connect/statut', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('stripe_account_id').eq('id', req.user.id).single();
    if (!user || !user.stripe_account_id) return res.json({ statut: 'non_configure' });

    const account = await stripe.accounts.retrieve(user.stripe_account_id);
    const pret = account.charges_enabled && account.payouts_enabled;
    res.json({ statut: pret ? 'pret' : 'en_cours' });
  } catch (e) {
    res.json({ statut: 'non_configure' });
  }
});

// Ce qu'une entreprise doit avoir renseigné avant son premier paiement. Ce sont
// les mentions que portera sa facture — et depuis le décret 2022-1299, le SIREN
// du client devient une mention obligatoire des factures entre professionnels.
//
// Un particulier n'est pas concerné : sa facture n'a pas à porter ces éléments.
function facturationManquante(user) {
  if (!user || user.type !== 'entreprise') return [];
  const manquants = [];
  if (!String(user.raison_sociale || '').trim()) manquants.push('raison_sociale');
  if (!/^\d{14}$/.test(String(user.siret || '').replace(/\s/g, ''))) manquants.push('siret');
  if (!String(user.adresse_facturation || '').trim()) manquants.push('adresse_facturation');
  return manquants;
}

// Compléter ses informations de facturation après l'inscription.
app.patch('/api/entreprises/facturation', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('type').eq('id', req.user.id).single();
    if (!user || user.type !== 'entreprise')
      return res.status(403).json({ error: 'Réservé aux comptes entreprise.' });

    const misAJour = {};
    if (req.body.siret !== undefined) {
      const siret = String(req.body.siret || '').replace(/\s/g, '').trim();
      if (siret && !/^\d{14}$/.test(siret))
        return res.status(400).json({ error: 'Numéro SIRET invalide (14 chiffres attendus).' });
      misAJour.siret = siret || null;
    }
    if (req.body.raison_sociale !== undefined)
      misAJour.raison_sociale = String(req.body.raison_sociale || '').trim() || null;
    if (req.body.adresse_facturation !== undefined)
      misAJour.adresse_facturation = String(req.body.adresse_facturation || '').trim() || null;
    if (req.body.tva_intracom !== undefined)
      misAJour.tva_intracom = String(req.body.tva_intracom || '').trim() || null;

    if (!Object.keys(misAJour).length)
      return res.status(400).json({ error: 'Aucune modification à enregistrer : les champs sont identiques aux valeurs actuelles.' });

    const { error } = await supabase.from('users').update(misAJour).eq('id', req.user.id);
    if (error) return res.status(400).json({ error: traduireErreurSupabase(error.message) });

    // Sans await : la réponse ne doit pas attendre un service extérieur.
    if (misAJour.siret) enregistrerVerificationSiret(req.user.id, misAJour.siret).catch(() => {});

    const { data: apres } = await supabase.from('users')
      .select('type, raison_sociale, siret, adresse_facturation').eq('id', req.user.id).single();
    res.json({ message: 'Informations de facturation enregistrées.',
               facturation_manquante: facturationManquante(apres) });
  } catch (e) {
    erreurServeur(res, 'PATCH /api/entreprises/facturation', e);
  }
});

app.post('/api/paiements/intent', auth, exigerEmailVerifie, async (req, res) => {
  try {
    const { devis_id } = req.body;

    // Contrôle des informations de facturation. C'est le paiement qui déclenche
    // la facture : c'est donc ici, et nulle part avant, que ces informations
    // deviennent nécessaires.
    const { data: payeur } = await supabase.from('users')
      .select('type, raison_sociale, siret, adresse_facturation').eq('id', req.user.id).single();
    const manquantes = facturationManquante(payeur);
    if (manquantes.length) {
      return res.status(403).json({
        error: 'Avant votre premier paiement, complétez vos informations de facturation.',
        facturation_manquante: manquantes
      });
    }
    if (!devis_id) return res.status(400).json({ error: 'Devis requis.' });

    // ── GARDE CONTRE LA DOUBLE INTENTION ────────────────────────────────
    // Deux appuis rapprochés sur le bouton de paiement créaient deux
    // intentions Stripe pour le même devis. En mode test c'était sans
    // conséquence ; en production, le client peut être débité deux fois.
    //
    // On RÉUTILISE l'intention en attente au lieu de refuser : un client dont
    // la première tentative a échoué en silence — réseau coupé, application
    // fermée — doit pouvoir réessayer, pas se heurter à un « paiement déjà en
    // cours » qu'il ne comprendrait pas.
    const { data: intentionEnCours } = await supabase.from('paiements')
      .select('id, stripe_payment_intent_id')
      .eq('devis_id', devis_id)
      .eq('statut', 'en_attente')
      .maybeSingle();

    if (intentionEnCours && intentionEnCours.stripe_payment_intent_id) {
      try {
        const existante = await stripe.paymentIntents.retrieve(intentionEnCours.stripe_payment_intent_id);
        // Une intention encore ouverte se réutilise telle quelle. Si elle a
        // été annulée ou a échoué chez Stripe, on la laisse et on en crée une
        // neuve : la réutiliser mènerait à un paiement impossible à finaliser.
        if (['requires_payment_method', 'requires_confirmation', 'requires_action', 'processing'].includes(existante.status)) {
          console.log('↩️  Intention réutilisée pour le devis ' + devis_id + ' (' + existante.status + ')');
          return res.json({
            client_secret: existante.client_secret,
            paiement_id: intentionEnCours.id,
            publishable_key: process.env.STRIPE_PUBLISHABLE_KEY,
            reutilisee: true
          });
        }
      } catch (e) {
        // Intention introuvable chez Stripe : on continue et on en crée une.
        console.warn('Intention en attente illisible, création d\'une nouvelle :', e.message);
      }
    }

    const { data: devis } = await supabase.from('devis').select('*').eq('id', devis_id).single();
    if (!devis) return res.status(404).json({ error: 'Ce devis n\'existe plus. Il a peut-être été retiré par le prestataire, ou la demande a été supprimée.' });

    const { data: demandePourPaiement } = await supabase.from('demandes').select('client_id').eq('id', devis.demande_id).single();
    if (!demandePourPaiement || demandePourPaiement.client_id !== req.user.id)
      return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });

    // Récompense de parrainage éventuellement disponible : le client paie 10% de moins, le pro
    // reçoit toujours sa part pleine (85% du prix du devis) — c'est la commission Gleam, et
    // seulement elle, qui absorbe l'intégralité de la réduction. Jamais d'argent sorti de la poche
    // de Gleam ni du pro, uniquement un manque à gagner sur une transaction qui a réellement lieu.
    // Protégé par un try/catch : si cette vérification échoue pour une raison quelconque, le
    // paiement continue normalement sans réduction, plutôt que de bloquer tout le paiement.
    let parrainageApplique = false;
    try {
      const { data: clientPourReduction } = await supabase.from('users').select('reduction_parrainage_disponible').eq('id', req.user.id).single();
      parrainageApplique = Boolean(clientPourReduction && clientPourReduction.reduction_parrainage_disponible);
    } catch (e) { console.error('Vérification parrainage ignorée:', e.message); }

    // ── TOUT SE CALCULE EN CENTIMES ENTIERS ─────────────────────────────
    // L'ancien calcul travaillait en euros décimaux puis arrondissait deux
    // fois, séparément : une fois pour Stripe, une fois pour la base.
    //
    // Les deux arrondis divergeaient d'un centime sur 10 588 prix testés
    // entre 1 € et 500 € — soit plus de 10 % des cas. Ce que Stripe versait
    // réellement au prestataire ne correspondait pas à ce que la base
    // enregistrait, et donc ni à sa page « mes gains », ni à sa facture, ni au
    // montant déclaré à l'administration en janvier.
    //
    // Un centime par paiement est invisible sur douze paiements. Sur dix
    // mille, ce sont des comptes qui ne se réconcilient plus — et une
    // déclaration DAC7 qui ne correspond pas aux relevés Stripe.
    //
    // En partant de centimes entiers, le montant versé est DÉDUIT du calcul
    // au lieu d'être recalculé : la divergence devient impossible.
    const centimesPrix     = Math.round(Number(devis.prix_ttc) * 100);
    const centimesFacture  = parrainageApplique ? Math.round(centimesPrix * 0.90) : centimesPrix;
    const centimesPro      = Math.round(centimesPrix * 0.85);
    const centimesCommission = centimesFacture - centimesPro;

    // Ce que Stripe versera au prestataire vaut exactement centimesPro :
    // total − commission. La base enregistre la même valeur, par construction.
    const montantPro      = centimesPro / 100;
    const montantFacture  = centimesFacture / 100;
    const commissionGleam = centimesCommission / 100;
    const montant    = centimesFacture;
    const commission = centimesCommission;

    // Si le pro a déjà configuré ses paiements, on utilise une "destination charge" Stripe :
    // l'argent se répartit automatiquement à la source (commission Gleam + part du pro), sans
    // jamais passer par un virement séparé après coup — ce qui évite le blocage classique de
    // "solde disponible insuffisant" que l'on aurait avec un virement fait après le paiement.
    // Protégé de la même façon : si le pro n'a pas encore configuré ses paiements (ou si la
    // vérification échoue), le paiement se fait quand même normalement, sans répartition automatique.
    let proConfigure = false, proPourPaiement = null;
    try {
      const { data } = await supabase.from('users').select('stripe_account_id').eq('id', devis.societe_id).single();
      proPourPaiement = data;

      // ── EXISTER NE SUFFIT PAS ────────────────────────────────────────────
      // On vérifiait seulement que l'identifiant du compte Connect était
      // présent. Or un compte créé mais dont l'inscription n'est pas terminée
      // ne peut pas recevoir de virement : Stripe REFUSE alors de créer
      // l'intention, et tout le paiement échoue.
      //
      // Le message d'erreur était générique — « Impossible de démarrer le
      // paiement » — alors que le client n'y était pour rien et que sa carte
      // était valide.
      //
      // On demande donc à Stripe si le compte peut réellement recevoir. S'il
      // ne le peut pas, le paiement se fait quand même : l'argent arrive chez
      // Gleam et le virement au prestataire se fera à la main. C'était déjà
      // l'intention du code — la vérification était simplement incomplète.
      if (proPourPaiement && proPourPaiement.stripe_account_id) {
        try {
          const compte = await stripe.accounts.retrieve(proPourPaiement.stripe_account_id);
          const transfertsActifs = compte.capabilities && compte.capabilities.transfers === 'active';
          proConfigure = Boolean(compte.charges_enabled && transfertsActifs);
          if (!proConfigure) {
            console.warn('⚠️  Compte Connect ' + proPourPaiement.stripe_account_id +
              ' pas encore opérationnel (charges_enabled=' + compte.charges_enabled +
              ', transfers=' + (compte.capabilities && compte.capabilities.transfers) +
              ') — paiement sans répartition automatique.');
          }
        } catch (e) {
          // Compte introuvable — typiquement un compte de TEST utilisé avec des
          // clés de PRODUCTION, ou l'inverse. Le paiement continue sans
          // répartition plutôt que d'échouer entièrement.
          console.warn('⚠️  Compte Connect illisible (' + e.message + ') — paiement sans répartition automatique.');
          proConfigure = false;
        }
      }
    } catch (e) { console.error('Vérification Stripe Connect ignorée:', e.message); }

    const paramsIntent = {
      amount: montant,
      currency: 'eur',
      metadata: { devis_id: devis_id, gleam: 'true' }
    };
    if (proConfigure) {
      paramsIntent.application_fee_amount = commission;
      paramsIntent.transfer_data = { destination: proPourPaiement.stripe_account_id };
    }

    const intent = await stripe.paymentIntents.create(paramsIntent);

    await supabase.from('paiements').insert({
      demande_id: devis.demande_id,
      devis_id: devis_id,
      client_id: req.user.id,
      societe_id: devis.societe_id,
      montant_ttc: montantFacture,
      commission: commissionGleam,
      montant_societe: montantPro,
      stripe_payment_intent_id: intent.id,
      transfert_automatique: proConfigure,
      parrainage_applique: parrainageApplique,
      statut: 'en_attente'
    });

    res.json({ client_secret: intent.client_secret, publishable_key: process.env.STRIPE_PUBLISHABLE_KEY, reduction_parrainage: parrainageApplique });
  } catch (e) {
    // Le message de Stripe est journalisé en entier : sans lui, on cherche une
    // panne de paiement à l'aveugle. Le type et le code permettent de
    // distinguer un refus de carte d'un défaut de configuration.
    console.error('Erreur création intention de paiement:', {
      message: e.message, type: e.type, code: e.code, param: e.param,
      devis_id: req.body && req.body.devis_id
    });
    res.status(500).json({ error: 'Impossible de démarrer le paiement pour l\'instant. Réessayez dans un instant ou contactez le support si le problème persiste.' });
  }
});

// Logique de confirmation d'un paiement, partagée entre la route appelée par le client juste
// après le paiement, et le webhook Stripe (utilisé uniquement en filet de sécurité, si jamais le
// navigateur du client se ferme avant que sa propre confirmation n'ait eu le temps de s'exécuter).
// Protégée contre toute double exécution : si le paiement est déjà confirmé, ne fait rien.
async function finaliserConfirmationPaiement(payment_intent_id) {
  const { data: paiementActuel } = await supabase.from('paiements').select('statut').eq('stripe_payment_intent_id', payment_intent_id).maybeSingle();
  if (!paiementActuel || paiementActuel.statut !== 'en_attente') return; // déjà confirmé (ou introuvable) : rien à refaire

  const intent = await stripe.paymentIntents.retrieve(payment_intent_id, { expand: ['latest_charge'] });
  if (intent.status !== 'succeeded') return;

  // Génère le code à 6 chiffres que le client devra donner au prestataire à la fin de la
  // prestation (comme un code de livraison Uber Eats) — preuve que les deux parties étaient
  // bien en contact au moment de la finalisation, plutôt qu'une simple confirmation unilatérale.
  const codeValidation = codeSecret6();
  // Capture les identifiants du transfert et de la commission Stripe pour cette charge — permet,
  // en cas d'annulation avec remboursement partiel, d'aller lire directement chez Stripe le
  // montant réellement reçu par le pro, plutôt que de le recalculer à la main de notre côté
  // (une mécanique interne à Stripe plus subtile qu'il n'y paraît, voir plus loin).
  const charge = intent.latest_charge;
  const stripeTransferId = charge && charge.transfer ? charge.transfer : null;
  const stripeApplicationFeeId = charge && charge.application_fee ? charge.application_fee : null;
  await supabase.from('paiements').update({
    statut: 'paye',
    code_validation: codeValidation,
    stripe_transfer_id: stripeTransferId,
    stripe_application_fee_id: stripeApplicationFeeId
  }).eq('stripe_payment_intent_id', payment_intent_id);
  const { data: paiement } = await supabase.from('paiements').select('*').eq('stripe_payment_intent_id', payment_intent_id).single();

  // Le numéro de facture est attribué au moment exact de l'encaissement : c'est
  // la date qui doit correspondre à la position dans la séquence. Sans await —
  // un échec de numérotation ne doit jamais compromettre un paiement abouti.
  if (paiement && !paiement.numero_facture) {
    attribuerNumeroFacture(paiement.id).catch(() => {});
  }

  if (paiement) {
    await supabase.from('demandes').update({ statut: 'en_cours' }).eq('id', paiement.demande_id);

    // ── C'EST ICI QUE LE PRESTATAIRE PEUT S'ENGAGER ──────────────────────
    // Jusqu'à ce point, le devis était « retenu » : le client l'avait choisi
    // mais n'avait rien payé, et la demande pouvait encore expirer.
    //
    // Le paiement change tout — l'argent est bloqué chez Stripe, la prestation
    // aura lieu. C'est le moment où le prestataire peut réserver son créneau
    // sans risque.
    //
    // Sans cette notification, il ne saurait jamais que la confirmation est
    // arrivée : il resterait sur le « retenu » et continuerait de douter.
    try {
      const { data: devisPaye } = await supabase.from('devis')
        .select('societe_id').eq('id', paiement.devis_id).maybeSingle();
      const { data: demandePayee } = await supabase.from('demandes')
        .select('prestation, creneau').eq('id', paiement.demande_id).maybeSingle();

      if (devisPaye) {
        // ── C'EST ICI QUE LE CHOIX DEVIENT RÉEL ──────────────────────────
        // Les autres devis étaient refusés dès l'acceptation. Si le client ne
        // payait pas, il perdait toutes ses options d'un coup et devait tout
        // recommencer.
        //
        // On les refuse au paiement : jusque-là, il peut encore changer d'avis
        // ou laisser l'échéance passer.
        await supabase.from('devis')
          .update({ statut: 'refuse' })
          .eq('demande_id', paiement.demande_id)
          .neq('id', paiement.devis_id);

        // L'échéance a joué son rôle : on l'efface pour que le balayage ne
        // reprenne pas un devis désormais payé.
        await supabase.from('devis')
          .update({ paiement_avant: null }).eq('id', paiement.devis_id);

        // ── UN MESSAGE DANS LA CONVERSATION, PAS SEULEMENT UNE ALERTE ────
        // Une notification se lit une fois puis disparaît. Le prestataire qui
        // rouvre la demande trois jours plus tard ne retrouve rien — et il
        // reste sur le « votre devis a été retenu », qui ne promet aucun
        // paiement.
        //
        // Le message, lui, demeure. Il devient la preuve datée que le règlement
        // est arrivé, visible des deux côtés, sans que le client ait à le
        // confirmer lui-même.
        //
        // `expediteur_id` porte l'identifiant du CLIENT : la table exige un
        // expéditeur réel, et c'est bien son paiement qu'on annonce.
        await supabase.from('messages').insert({
          demande_id: paiement.demande_id,
          expediteur_id: paiement.client_id,
          contenu: '💳 Paiement confirmé — la prestation est réservée. '
                 + 'Le montant est bloqué et vous sera versé après validation.',
          type: 'systeme'
        });

        envoyerNotificationPush(devisPaye.societe_id, {
          titre: 'Paiement confirmé — prestation réservée',
          // `prestation` est déjà lisible côté serveur — « voiture + canape ». Ma
          // première version appelait une fonction de mise en forme qui n'existe
          // qu'au client : elle aurait planté à la première notification.
          corps: (demandePayee ? demandePayee.prestation + ' — ' : '')
               + (demandePayee && demandePayee.creneau ? demandePayee.creneau : 'créneau confirmé')
               + '. Vous pouvez bloquer ce créneau.',
          url: '/#devis'
        }).catch(() => {});
      }
    } catch (e) {
      // Une notification manquée ne doit jamais compromettre un paiement
      // abouti : le client a déjà été débité.
      console.warn('Notification de paiement au prestataire :', e.message);
    }

    // Tout ce qui touche au parrainage est protégé dans son propre bloc : une erreur ici (colonne
    // manquante, etc.) ne doit jamais empêcher la confirmation du paiement lui-même de réussir —
    // le client a déjà payé, la prestation doit passer en cours quoi qu'il arrive.
    try {
      // Consomme le crédit de réduction s'il vient d'être utilisé sur ce paiement
      if (paiement.parrainage_applique) {
        await supabase.from('users').update({ reduction_parrainage_disponible: false }).eq('id', paiement.client_id);
      }

      // Si c'est le tout premier paiement réussi de ce client ET qu'il a été parrainé, on
      // récompense le parrain ET le filleul avec une réduction sur leur prochaine prestation —
      // financée uniquement par la commission Gleam (jamais d'argent réel versé), et seulement
      // au moment d'une vraie transaction. Ne se déclenche qu'une seule fois par filleul.
      const { data: clientPaye } = await supabase.from('users').select('parraine_par, parrainage_recompense_donnee').eq('id', paiement.client_id).single();
      if (clientPaye && clientPaye.parraine_par && !clientPaye.parrainage_recompense_donnee) {
        const { count: nbPaiementsAnterieurs } = await supabase.from('paiements').select('id', { count: 'exact', head: true })
          .eq('client_id', paiement.client_id).in('statut', ['paye', 'libere']);
        if (nbPaiementsAnterieurs === 1) { // celui-ci est bien le tout premier
          await supabase.from('users').update({ reduction_parrainage_disponible: true, parrainage_recompense_donnee: true }).eq('id', paiement.client_id);
          await supabase.from('users').update({ reduction_parrainage_disponible: true }).eq('id', clientPaye.parraine_par);
        }
      }
    } catch (e) {
      console.error('Logique de parrainage ignorée (paiement déjà confirmé normalement) :', e.message);
    }

    // 📧 Email 5/8 : paiement confirmé → pro
    const { data: pro } = await supabase.from('users').select('email, prenom').eq('id', paiement.societe_id).single();
    const { data: demandeInfo } = await supabase.from('demandes').select('prestation').eq('id', paiement.demande_id).single();
    if (pro) {
      sendEmail('paiement_confirme', pro.email, {
        compteId: pro.id,
        prenom: pro.prenom,
        prestation: demandeInfo ? demandeInfo.prestation : '',
        montantTotal: paiement.montant_ttc,
        commission: paiement.commission,
        montantPro: paiement.montant_societe,
        demandeId: paiement.demande_id
      });
      envoyerNotificationPush(paiement.societe_id, {
        titre: 'Paiement confirmé 💰',
        corps: 'Le client a payé pour ' + (demandeInfo ? demandeInfo.prestation : 'votre prestation'),
        url: '/#devis'
      });
    }
  }
}

app.post('/api/paiements/confirmer', auth, async (req, res) => {
  try {
    const { payment_intent_id } = req.body;
    await finaliserConfirmationPaiement(payment_intent_id);
    res.json({ message: 'Paiement confirmé ✨' });
  } catch (e) {
    console.error('Erreur confirmation de paiement:', e);
    res.status(500).json({ error: 'Le paiement a peut-être réussi mais la confirmation a échoué. Contactez le support Gleam avec votre référence de paiement pour vérifier.' });
  }
});

// Finalise une prestation : déclenche le vrai virement Stripe vers le pro, met à jour les statuts,
// et notifie les deux parties par email. Partagée entre la validation par code (le pro saisit le
// code donné par le client) et toute finalisation manuelle éventuelle.
async function finaliserPrestation(paiement) {
  const { data: pro } = await supabase.from('users').select('email, prenom, stripe_account_id').eq('id', paiement.societe_id).single();
  if (!pro || !pro.stripe_account_id) {
    return { erreur: 'Le prestataire n\'a pas encore configuré ses paiements. Le virement ne peut pas être effectué pour l\'instant — contactez le support Gleam.' };
  }

  // Si l'argent a déjà été réparti automatiquement au moment du paiement (destination charge),
  // il n'y a rien de plus à transférer ici — un virement séparé serait en trop et échouerait de
  // toute façon (le solde de la plateforme ne contient jamais la part du pro dans ce cas).
  if (!paiement.transfert_automatique) {
    try {
      await stripe.transfers.create({
        amount: Math.round(parseFloat(paiement.montant_societe) * 100),
        currency: 'eur',
        destination: pro.stripe_account_id,
        transfer_group: `demande_${paiement.demande_id}`
      });
    } catch (stripeErr) {
      console.error('Virement Stripe échoué:', stripeErr);

      // ── L'ÉCHEC DOIT LAISSER UNE TRACE ──────────────────────────────────
      // On rendait la main sans rien écrire : le paiement restait dans l'état
      // de réservation « liberation_en_cours », posé par l'appelant.
      //
      // Aucun balayage ne cherche cet état — le paiement devenait invisible.
      // Ni versé, ni remboursé, ni signalé. Le prestataire attendait un
      // virement qui ne partirait jamais.
      //
      // C'est ce qui s'est produit le 19 août avec les deux virements de
      // Christopher : on ne l'a découvert qu'en cherchant autre chose.
      //
      // On rend le paiement à « paye » — l'état d'où une nouvelle tentative
      // peut repartir — et on note pourquoi.
      await supabase.from('paiements').update({
        statut: 'paye',
        transfert_erreur: String(stripeErr.message || 'inconnue').slice(0, 300),
        transfert_tentative_le: new Date().toISOString(),
        transfert_tentatives: (paiement.transfert_tentatives || 0) + 1
      }).eq('id', paiement.id);

      return { erreur: 'Le virement vers le prestataire a échoué (' + (stripeErr.message || 'compte Stripe non prêt') + '). Réessayez plus tard ou contactez le support.' };
    }
  }

  // Le paiement porte ici le statut de réservation posé par l'appelant ('liberation_en_cours'),
  // ou encore 'paye' pour les appels internes qui ne réservent pas : les deux sont acceptés.
  await supabase.from('paiements').update({
      statut: 'libere',
      // La colonne existait et n'était jamais remplie. Sans elle, impossible de
      // savoir QUAND un versement a été libéré — et donc de dire ce qui a été
      // gagné « ce mois ». L'application retombait sur created_at, la date de
      // paiement du client, qui n'est pas la même chose.
      libere_le: new Date().toISOString()
    }).eq('id', paiement.id).in('statut', ['liberation_en_cours', 'paye']);
  await supabase.from('demandes').update({ statut: 'terminee' }).eq('id', paiement.demande_id);
  creerProchaineOccurrenceRecurrente(paiement.demande_id).catch(e => console.error('Récurrence non créée:', e.message));

  const { data: demandeInfo } = await supabase.from('demandes').select('prestation').eq('id', paiement.demande_id).single();
  const { data: client } = await supabase.from('users').select('email, prenom').eq('id', paiement.client_id).single();
  if (client) {
    sendEmail('prestation_confirmee', client.email, {
      compteId: client.id,
      prenom: client.prenom, role: 'client', prestation: demandeInfo ? demandeInfo.prestation : '', demandeId: paiement.demande_id
    }).catch(e => console.error('Email prestation_confirmee client:', e));
  }
  if (pro) {
    sendEmail('prestation_confirmee', pro.email, {
      compteId: pro.id,
      prenom: pro.prenom, role: 'pro', prestation: demandeInfo ? demandeInfo.prestation : '', montantPro: paiement.montant_societe, demandeId: paiement.demande_id
    }).catch(e => console.error('Email prestation_confirmee pro:', e));
  }

  return { ok: true };
}

// Fonction utilitaire de validation d'un tableau de photos (format, taille, quantité) —
// réutilisée pour les photos "avant" et "après" de la prestation.
function validerPhotos(photos, max) {
  if (!photos || !Array.isArray(photos)) return null;
  if (photos.length > max) return `Maximum ${max} photos.`;
  for (const p of photos) {
    if (typeof p !== 'string' || !/^data:image\/(jpeg|jpg|png|webp);base64,/.test(p)) {
      return 'Format de photo non supporté (JPEG, PNG ou WEBP uniquement).';
    }
    if (p.length > 800 * 1024) {  // 800 ko : une demande reste sous 4 Mo au total
      return 'Une photo est trop volumineuse. Réessayez avec une photo plus légère.';
    }
  }
  return null;
}

// Le PRESTATAIRE confirme son arrivée chez le client et prend une photo de l'état initial,
// avant de commencer le travail — première étape logique, avant la validation de fin de
// prestation. Rien ne change de statut ici, c'est purement informatif et rassurant pour le client.
app.post('/api/demandes/:id/demarrer-prestation', auth, async (req, res) => {
  try {
    // `position_indisponible` : le prestataire déclare explicitement ne pas
    // pouvoir partager sa position. Un geste conscient vaut mieux qu'un null
    // silencieux — il distingue l'échec technique de l'absence voulue.
    const { photos_avant, latitude_pro, longitude_pro, position_indisponible } = req.body;
    const { data: demande } = await supabase.from('demandes').select('*').eq('id', req.params.id).single();
    if (!demande) return res.status(404).json({ error: 'Cette demande n\'existe plus. Elle a sans doute été supprimée ou annulée par le client.' });
    if (demande.statut !== 'en_cours') return res.status(400).json({ error: 'Cette prestation n\'est pas en cours.' });

    const { data: devisAccepte } = await supabase.from('devis').select('societe_id').eq('demande_id', req.params.id).eq('statut', 'accepte').maybeSingle();

    // ── ON N'ARRIVE PAS TROIS JOURS À L'AVANCE ──────────────────────────
    // Rien ne vérifiait la date. Un prestataire pouvait déclarer son arrivée
    // dès l'acceptation du devis — et cela verrouillait tout :
    //
    //   le client ne pouvait plus reprogrammer
    //   il ne pouvait plus annuler
    //   la clôture des 48 h démarrait
    //
    // Autrement dit, l'argent pouvait partir AVANT MÊME le créneau, pour une
    // prestation qui n'avait pas eu lieu. Le client se retrouvait sans recours
    // sur une décision qu'il n'avait pas prise.
    //
    // POURQUOI DEUX HEURES DE MARGE
    // Un prestataire arrive souvent en avance, et il a raison de le déclarer
    // en arrivant plutôt qu'à l'heure dite. Deux heures couvrent l'avance
    // raisonnable sans ouvrir la porte à une déclaration de la veille.
    //
    // AUCUNE LIMITE DANS L'AUTRE SENS : une prestation peut commencer en
    // retard, et refuser une arrivée tardive empêcherait de travailler
    // quelqu'un qui est déjà sur place.
    const instantPrestation = instantDuCreneau(demande.creneau);
    if (instantPrestation) {
      const MARGE_AVANCE_MS = 2 * 3600 * 1000;
      if (Date.now() < instantPrestation - MARGE_AVANCE_MS) {
        const ouverture = new Date(instantPrestation - MARGE_AVANCE_MS);
        return res.status(409).json({
          error: 'Vous pourrez déclarer votre arrivée à partir de '
            + ouverture.toLocaleString('fr-FR',
                { day: '2-digit', month: 'long', hour: '2-digit', minute: '2-digit' })
            + ', soit deux heures avant le créneau convenu.'
        });
      }
    }
    if (!devisAccepte || devisAccepte.societe_id !== req.user.id) return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });

    const erreurPhotos = validerPhotos(photos_avant, 5);
    if (erreurPhotos) return res.status(400).json({ error: erreurPhotos });

    // ── L'ABSENCE DE PHOTO EST ENREGISTRÉE, PAS BLOQUÉE ─────────────────
    // Rendre la photo obligatoire bloquerait un prestataire honnête dans un
    // parking souterrain sans réseau, au moment précis où le client l'attend.
    // On préfère la noter : un prestataire qui déclare systématiquement son
    // arrivée sans photo devient repérable dans l'administration.
    //
    // Le blocage punit l'accident, la trace punit l'habitude.
    const sansPhoto = !Array.isArray(photos_avant) || photos_avant.length === 0;

    // Vérifie que le prestataire est réellement sur place, en comparant sa position GPS au moment
    // de l'arrivée à l'adresse déclarée par le client (formule de Haversine, distance à vol
    // d'oiseau) — une preuve technique difficile à falsifier, contrairement à une simple
    // déclaration. Ne bloque jamais la prestation (le GPS peut être imprécis ou désactivé),
    // seulement enregistré comme preuve consultable en cas de litige.
    let distanceGpsMetres = null;
    if (typeof latitude_pro === 'number' && typeof longitude_pro === 'number' && demande.latitude && demande.longitude) {
      const R = 6371000; // rayon de la Terre en mètres
      const toRad = (deg) => deg * Math.PI / 180;
      const dLat = toRad(latitude_pro - demande.latitude);
      const dLon = toRad(longitude_pro - demande.longitude);
      const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(demande.latitude)) * Math.cos(toRad(latitude_pro)) * Math.sin(dLon / 2) ** 2;
      distanceGpsMetres = Math.round(R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)));
    }

    // ── QUALIFIER L'ARRIVÉE ────────────────────────────────────────────
    // DEUX kilomètres de tolérance.
    //
    // Une adresse approximative, un grand ensemble, une entrée de service à
    // l'arrière du bâtiment, un lieu-dit mal géocodé — il y a trop de raisons
    // légitimes d'être loin du point enregistré pour être strict.
    //
    // Le seuil ne sert pas à détecter les imprécisions, mais les absences :
    // quelqu'un qui déclare son arrivée depuis chez lui est à des kilomètres,
    // pas à quinze cents mètres. Deux kilomètres écartent tout le bruit sans
    // laisser passer ce qu'on cherche.
    const SEUIL_METRES = 2000;
    let qualiteArrivee;
    if (distanceGpsMetres === null) {
      qualiteArrivee = 'non_verifiee';   // pas de position, ou pas de coordonnées
    } else if (distanceGpsMetres <= SEUIL_METRES) {
      qualiteArrivee = 'sur_place';
    } else {
      qualiteArrivee = 'eloignee';
    }

    await supabase.from('demandes').update({
      photos_avant: photos_avant && photos_avant.length
        ? JSON.stringify(await televerserPhotos(photos_avant, 'demandes/' + req.params.id + '/avant'))
        : null,
      prestation_demarree_le: new Date().toISOString(),
      distance_gps_arrivee: distanceGpsMetres,
      // Ce qui manque est noté, pas refusé. Consultable dans l'administration
      // pour repérer un prestataire qui n'en fournit jamais.
      arrivee_sans_photo: sansPhoto,

      // Trois états, et aucun ne refuse l'arrivée. Ils servent à décider du
      // délai de clôture et à consulter le client — jamais à empêcher
      // quelqu'un de travailler.
      arrivee_qualite: qualiteArrivee,
      position_refusee_par_pro: position_indisponible === true
    }).eq('id', req.params.id);

    res.json({ message: 'Arrivée confirmée. Bonne prestation !' });
  } catch (e) {
    erreurServeur(res, 'POST /api/demandes/:id/demarrer-prestation', e);
  }
});

// Le PRESTATAIRE saisit le code à 6 chiffres que le client lui a donné en personne, à la fin de
// la prestation (même logique qu'un code de livraison Uber Eats) — remplace la confirmation
// unilatérale par le client seul, et prouve que les deux parties étaient bien en contact.
app.post('/api/paiements/valider-code', auth, async (req, res) => {
  try {
    const { demande_id, code, photos_apres } = req.body;
    if (!demande_id || !code) return res.status(400).json({ error: 'Saisissez le code de validation que le client vous a communiqué à la fin de la prestation.' });

    const { data: paiement } = await supabase.from('paiements').select('*').eq('demande_id', demande_id).eq('statut', 'paye').maybeSingle();
    if (!paiement) return res.status(404).json({ error: 'Aucun paiement en attente pour cette prestation.' });
    if (paiement.societe_id !== req.user.id) return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });
    if (String(code).trim() !== paiement.code_validation) return res.status(400).json({ error: 'Code incorrect. Vérifiez le code donné par le client.' });

    const erreurPhotos = validerPhotos(photos_apres, 5);
    if (erreurPhotos) return res.status(400).json({ error: erreurPhotos });
    if (photos_apres && photos_apres.length) {
      const cheminsApres = await televerserPhotos(photos_apres, 'demandes/' + demande_id + '/apres');
      await supabase.from('demandes').update({ photos_apres: JSON.stringify(cheminsApres) }).eq('id', demande_id);
    }

    // ⚠️ Point le plus sensible du serveur : au-delà de cette ligne, de l'argent
    // bouge réellement. Le paiement est réservé AVANT le virement, par écriture
    // conditionnelle. Sans cela, un double appui du pro sur un réseau lent
    // faisait lire 'paye' aux deux requêtes, et déclenchait DEUX virements
    // Stripe vers le même prestataire pour une seule prestation.
    const reserve = await reserverLigne('paiements', paiement.id, ['paye'], 'liberation_en_cours');
    if (!reserve) {
      return res.status(409).json({ error: 'Cette prestation est déjà en cours de validation.' });
    }

    let resultat;
    try {
      resultat = await finaliserPrestation(paiement);
    } catch (erreurFinalisation) {
      // La réservation est rendue, sans quoi le paiement resterait bloqué dans un
      // statut intermédiaire qu'aucune autre requête ne saurait reprendre.
      await supabase.from('paiements').update({ statut: 'paye' }).eq('id', paiement.id).eq('statut', 'liberation_en_cours');
      throw erreurFinalisation;
    }
    if (resultat.erreur) {
      await supabase.from('paiements').update({ statut: 'paye' }).eq('id', paiement.id).eq('statut', 'liberation_en_cours');
      return res.status(400).json({ error: resultat.erreur });
    }

    res.json({ message: 'Prestation validée, paiement transféré ✨' });
  } catch (e) {
    erreurServeur(res, 'POST /api/paiements/valider-code', e);
  }
});

// Historique des paiements du client (rubrique "Paiements" du profil)
app.get('/api/paiements/mes-paiements', auth, async (req, res) => {
  try {
    // On n'affiche que les paiements réellement effectués (payé, libéré, ou remboursé) — un paiement
    // "en_attente" (intention de paiement créée mais jamais finalisée) ne représente aucune transaction
    // réelle. Le remboursement, lui, doit rester visible pour la transparence du client.
    const { data: paiements } = await supabase.from('paiements').select('*').eq('client_id', req.user.id).in('statut', ['paye', 'libere', 'rembourse', 'rembourse_partiel']).order('created_at', { ascending: false });
    if (!paiements || !paiements.length) return res.json([]);
    const demandeIds = [...new Set(paiements.map(p => p.demande_id))];
    const { data: demandes } = await supabase.from('demandes').select('id, prestation, adresse').in('id', demandeIds);
    const demandesMap = {};
    (demandes || []).forEach(d => { demandesMap[d.id] = d; });
    // Tri logique : payé (en attente de confirmation, encore "actif") avant libéré (réglé, historique),
    // remboursé en dernier — cohérent avec la priorité "actionnable avant historique" du reste de l'app.
    const prioritePaiement = { paye: 0, libere: 1, rembourse_partiel: 2, rembourse: 3 };
    const enrichis = paiements.map(p => ({ ...p, demande: demandesMap[p.demande_id] || null }));
    enrichis.sort((a, b) => (prioritePaiement[a.statut] ?? 9) - (prioritePaiement[b.statut] ?? 9));
    res.json(enrichis);
  } catch (e) {
    erreurServeur(res, 'route inconnue', e);
  }
});

// Historique des gains du pro (rubrique "Mes gains" du profil)
app.get('/api/paiements/mes-gains', auth, async (req, res) => {
  try {
    // Même logique : un paiement jamais finalisé ne représente aucun gain, réel ou potentiel.
    // "rembourse_partiel" est inclus : dans ce cas précis (annulation tardive du client), le pro
    // garde sa part déjà transférée en compensation — ça reste donc un vrai gain pour lui, même si
    // le client a été partiellement ou pas remboursé de son côté.
    const { data: paiements } = await supabase.from('paiements').select('*').eq('societe_id', req.user.id).in('statut', ['paye', 'libere', 'rembourse_partiel']).order('created_at', { ascending: false });
    if (!paiements || !paiements.length) return res.json({ total_libere: 0, total_en_attente: 0, paiements: [] });
    const demandeIds = [...new Set(paiements.map(p => p.demande_id))];
    const { data: demandes } = await supabase.from('demandes').select('id, prestation, adresse').in('id', demandeIds);
    const demandesMap = {};
    (demandes || []).forEach(d => { demandesMap[d.id] = d; });
    const totalLibere = paiements.filter(p => p.statut === 'libere' || p.statut === 'rembourse_partiel').reduce((a, p) => a + parseFloat(p.montant_societe), 0);
    const totalEnAttente = paiements.filter(p => p.statut === 'paye').reduce((a, p) => a + parseFloat(p.montant_societe), 0);
    // Tri logique : en attente de confirmation client (encore "actif") avant reçu (déjà réglé, historique)
    const prioriteGain = { paye: 0, libere: 1, rembourse_partiel: 1 };
    const enrichis = paiements.map(p => ({ ...p, demande: demandesMap[p.demande_id] || null }));
    enrichis.sort((a, b) => (prioriteGain[a.statut] ?? 9) - (prioriteGain[b.statut] ?? 9));
    res.json({
      total_libere: Math.round(totalLibere * 100) / 100,
      total_en_attente: Math.round(totalEnAttente * 100) / 100,
      paiements: enrichis
    });
  } catch (e) {
    erreurServeur(res, 'GET /api/paiements/mes-gains', e);
  }
});

// Génère les données d'une facture pour une prestation terminée — accessible au client (ou à
// l'entreprise) et au prestataire concernés. Le document lui-même (mise en forme imprimable)
// est construit côté app à partir de ces données ; rien n'est stocké en double ici.
// Construit une description complète de la prestation (matière, surface/quantité, état) à partir
// des notes structurées de la demande — plutôt que d'afficher juste le nom brut de la catégorie
// sur la facture, ce qui serait trop pauvre pour un usage comptable ou professionnel sérieux.
// ═══════════════════════════════════════════════════════════════════════════
// LES PRESTATIONS, UNE PAR LIGNE
//
// `construireDescriptionPrestation` fusionnait tout en une seule chaîne,
// séparée par des points-virgules :
//
//   Nettoyage — voiture (Intérieur, Shampouinage…, Citadine, 2 places,
//   Parking souterrain, Propre) ; Nettoyage — canape (Droit, Coussins…) ;
//   Nettoyage — matelas (140x190 cm, Sommier…, 1)
//
// Sur une facture, cela donne un pavé de six lignes que personne ne lit. Ni
// le client, qui veut vérifier ce qu'il paie ; ni le prestataire, qui veut
// savoir ce qu'il doit faire ; ni un comptable, qui cherche le détail.
//
// On renvoie donc une LISTE STRUCTURÉE, et l'application en fait des lignes
// de tableau. La chaîne reste disponible pour les courriels et les écrans qui
// n'ont pas la place d'un tableau.
// ═══════════════════════════════════════════════════════════════════════════
function detaillerPrestations(notes, prestationFallback) {
  try {
    const n = JSON.parse(notes);
    if (n.prestations && Array.isArray(n.prestations) && n.prestations.length) {
      return n.prestations.map(p => ({
        type: p.type || '',
        // Les détails restent groupés : ce sont des caractéristiques d'une
        // même prestation, pas des lignes distinctes.
        details: (p.details && Object.keys(p.details).length)
          ? Object.values(p.details).filter(Boolean).join(' · ')
          : '',
        note: p.description || ''
      }));
    }
  } catch (e) { /* notes non structurées ou absentes */ }
  return [{ type: prestationFallback || '', details: '', note: '' }];
}

function construireDescriptionPrestation(notes, prestationFallback) {
  try {
    const n = JSON.parse(notes);
    if (n.prestations && Array.isArray(n.prestations) && n.prestations.length) {
      return n.prestations.map(p => {
        const details = p.details && Object.keys(p.details).length ? Object.values(p.details).join(', ') : '';
        let ligne = 'Nettoyage — ' + (p.type || '');
        if (details) ligne += ' (' + details + ')';
        if (p.description) ligne += ' : ' + p.description;
        return ligne;
      }).join(' ; ');
    }
  } catch (e) { /* notes non structurées ou absentes */ }
  return 'Nettoyage — ' + (prestationFallback || '');
}

app.get('/api/demandes/:id/facture', auth, async (req, res) => {
  try {
    const { data: demande } = await supabase.from('demandes').select('*').eq('id', req.params.id).single();
    if (!demande) return res.status(404).json({ error: 'Cette demande n\'existe plus. Elle a sans doute été supprimée ou annulée par le client.' });
    if (demande.statut !== 'terminee') return res.status(400).json({ error: 'La facture n\'est disponible qu\'une fois la prestation terminée.' });

    const { data: devisAccepte } = await supabase.from('devis').select('*').eq('demande_id', demande.id).eq('statut', 'accepte').maybeSingle();
    if (!devisAccepte) return res.status(404).json({ error: 'Ce devis n\'existe plus. Il a peut-être été retiré par le prestataire, ou la demande a été supprimée.' });

    const estClient = demande.client_id === req.user.id;
    const estPro = devisAccepte.societe_id === req.user.id;
    if (!estClient && !estPro) return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });

    const { data: client } = await supabase.from('users').select('prenom, nom, email, type, raison_sociale, siret, tva_intracom, adresse_facturation').eq('id', demande.client_id).single();
    const { data: pro } = await supabase.from('users').select('prenom, nom, email, siret').eq('id', devisAccepte.societe_id).single();
    const { data: paiement } = await supabase.from('paiements').select('*').eq('demande_id', demande.id).maybeSingle();

    // ── LE NUMÉRO EST ATTRIBUÉ ICI SI ON NE L'A PAS ENCORE ──────────────
    // Il l'est normalement à l'encaissement. Mais si cette attribution a
    // échoué — Supabase indisponible une seconde, par exemple —, la facture
    // affichait un identifiant de repli « GLEAM-XXXXXXXX » construit sur
    // l'identifiant de la demande.
    //
    // Un tel numéro n'est PAS conforme : l'article 242 nonies A du CGI exige
    // une suite continue, sans rupture ni doublon. Deux factures pouvaient
    // porter des numéros sans lien entre eux, et l'administration y verrait
    // une comptabilité non probante.
    //
    // On rattrape donc ici, au moment où quelqu'un consulte réellement la
    // facture — le dernier instant où c'est encore possible.
    let numeroFacture = paiement && paiement.numero_facture;
    if (!numeroFacture && paiement) {
      numeroFacture = await attribuerNumeroFacture(paiement.id);
    }

    // ── LA FACTURE DE COMMISSION ─────────────────────────────────────────
    // Elle n'est attribuée que si le paiement est LIBÉRÉ : tant que l'argent
    // est retenu, la prestation d'intermédiation n'est pas achevée, et une
    // facture émise trop tôt devrait être annulée en cas de remboursement.
    //
    // Une facture annulée laisse une trace dans la suite — un avoir à émettre,
    // une ligne à justifier. Autant ne l'émettre qu'une fois l'opération sûre.
    let numeroCommission = paiement && paiement.numero_facture_commission;
    if (!numeroCommission && paiement && paiement.statut === 'libere') {
      numeroCommission = await attribuerNumeroCommission(paiement.id);
    }
    if (!numeroFacture) {
      // Aucun paiement rattaché : il n'y a rien à facturer. Mieux vaut le dire
      // que d'émettre un document sans numéro valable.
      return res.status(409).json({
        error: 'La facture sera disponible dès que le paiement aura été enregistré.'
      });
    }

    const montantTtc = parseFloat(devisAccepte.prix_ttc);
    const commission = paiement ? parseFloat(paiement.commission) : Math.round(montantTtc * 0.15 * 100) / 100;
    const montantPro = paiement ? parseFloat(paiement.montant_societe) : Math.round((montantTtc - commission) * 100) / 100;

    res.json({
      // Numéro séquentiel attribué en base à l'encaissement. Le repli sur
      // l'ancien format ne concerne que les paiements antérieurs à cette
      // correction, s'il en restait ; il ne doit jamais servir en production.
      numero: numeroFacture,
      date: demande.updated_at || demande.created_at,
      prestation: construireDescriptionPrestation(demande.notes, demande.prestation),
      // La même chose, mais structurée : une entrée par prestation, pour que
      // la facture puisse en faire des lignes de tableau distinctes.
      prestations: detaillerPrestations(demande.notes, demande.prestation),
      adresse: demande.adresse,
      client: client ? {
        est_entreprise: client.type === 'entreprise',
        nom_affiche: client.type === 'entreprise' ? client.raison_sociale : ((client.prenom || '') + ' ' + (client.nom || '')).trim(),
        siret: client.type === 'entreprise' ? client.siret : null,
        tva_intracom: client.type === 'entreprise' ? client.tva_intracom : null,
        adresse_facturation: client.type === 'entreprise' ? client.adresse_facturation : null
      } : null,
      pro: pro ? { nom_affiche: ((pro.prenom || '') + ' ' + (pro.nom || '')).trim(), siret: pro.siret } : null,
      montant_ttc: montantTtc,
      commission_gleam: commission,

      // Tout ce qu'il faut pour composer la seconde facture, celle que Gleam
      // adresse au prestataire. Elle n'existe qu'une fois le paiement libéré.
      facture_commission: numeroCommission ? {
        numero: numeroCommission,
        date: paiement.libere_le || paiement.created_at,
        montant: commission,
        // Le prestataire est ici l'ACHETEUR, alors qu'il est le vendeur sur
        // l'autre facture. C'est ce renversement qui interdit de fusionner
        // les deux documents.
        acheteur: pro ? {
          nom_affiche: ((pro.prenom || '') + ' ' + (pro.nom || '')).trim(),
          siret: pro.siret
        } : null
      } : null,
      montant_pro: montantPro
    });
  } catch (e) {
    erreurServeur(res, 'GET /api/demandes/:id/facture', e);
  }
});

// ══════════════ FAVORIS ══════════════
// Permet au client de retravailler facilement avec un prestataire déjà apprécié — fonctionnalité
// standard des marketplaces de service (Wecasa, TaskRabbit), jusqu'ici absente de Gleam.

app.post('/api/favoris', auth, async (req, res) => {
  try {
    const { pro_id } = req.body;
    if (!pro_id) return res.status(400).json({ error: 'Prestataire requis.' });
    const { data: pro } = await supabase.from('users').select('type').eq('id', pro_id).single();
    if (!pro || !isProType(pro.type)) return res.status(400).json({ error: 'Ce compte n\'est pas un prestataire.' });

    const { data: dejaFavori } = await supabase.from('favoris').select('id').eq('client_id', req.user.id).eq('pro_id', pro_id).maybeSingle();
    if (dejaFavori) return res.json({ message: 'Déjà dans vos favoris.' });

    const { error } = await supabase.from('favoris').insert({ client_id: req.user.id, pro_id: pro_id });
    if (error) { console.error('Erreur Supabase, message technique complet:', error); return res.status(400).json({ error: traduireErreurSupabase(error.message) }); }
    res.status(201).json({ message: 'Ajouté à vos favoris ✨' });
  } catch (e) {
    erreurServeur(res, 'POST /api/favoris', e);
  }
});

app.delete('/api/favoris/:proId', auth, async (req, res) => {
  try {
    await supabase.from('favoris').delete().eq('client_id', req.user.id).eq('pro_id', req.params.proId);
    res.json({ message: 'Retiré de vos favoris.' });
  } catch (e) {
    erreurServeur(res, 'DELETE /api/favoris/:proId', e);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// PROPOSER UN FAVORI, UNE SEULE FOIS
//
// Quand une prestation se termine, on demande au client s'il veut retrouver ce
// prestataire. S'il refuse, on ne redemande plus POUR LUI — le refus porte sur
// la personne, pas sur la prestation.
//
// Pourquoi ne pas ajouter automatiquement : un favori qu'on n'a pas choisi
// n'en est pas un. Au bout de dix prestations avec dix prestataires, la liste
// deviendrait un historique — et on en a déjà un.
//
// Et le fait qu'un client ajoute un favori est un signal précieux : il dit
// qui l'on veut revoir, bien plus sûrement qu'une note, parce que c'est un
// geste et non une déclaration. L'automatiser effacerait ce signal.
// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════
// ROUVRIR UNE DEMANDE À TOUS LES PRESTATAIRES
//
// L'application le promettait au client — « Si non disponible, vous pourrez
// toujours rouvrir la demande à tous les prestataires » — et rien ne le
// permettait. C'était une promesse en l'air depuis le premier jour.
//
// L'ouverture automatique couvre le cas où le client n'y pense pas ; ce bouton
// couvre celui où il n'attend pas.
// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════
// LE CLIENT RÉPOND : QUELQU'UN EST-IL VENU ?
//
// Quand l'arrivée déclarée est éloignée ou non vérifiée, on demande au client
// de confirmer. C'est lui qui sait — aucune donnée GPS ne le remplace.
//
//   « oui »   la clôture reprend son délai normal de 48 h
//   « non »   un litige s'ouvre automatiquement
//
// POURQUOI LE LITIGE EST AUTOMATIQUE
//
// Un client qui prend la peine de répondre « personne n'est venu » ne devrait
// pas avoir à faire une seconde démarche pour être entendu. Lui demander de
// signaler ensuite, c'est perdre la moitié des réponses.
//
// L'argent reste bloqué jusqu'à votre arbitrage — ni versé, ni remboursé.
// ═══════════════════════════════════════════════════════════════════════════
app.post('/api/demandes/:id/confirmer-arrivee', auth, async (req, res) => {
  try {
    const estVenu = req.body && req.body.est_venu === true;

    const { data: demande } = await supabase.from('demandes')
      .select('id, client_id, statut, arrivee_qualite, prestation')
      .eq('id', req.params.id).maybeSingle();

    if (!demande) return res.status(404).json({ error: 'Cette demande n\'existe plus.' });
    if (demande.client_id !== req.user.id) {
      return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément.' });
    }
    if (demande.statut !== 'en_cours') {
      return res.status(409).json({ error: 'Cette prestation n\'est plus en cours.' });
    }

    await supabase.from('demandes')
      .update({ arrivee_confirmee_client: estVenu })
      .eq('id', demande.id);

    if (estVenu) {
      return res.json({ message: 'Merci. Vous pourrez valider la prestation une fois terminée.' });
    }

    // ── LE LITIGE S'OUVRE SEUL ─────────────────────────────────────────
    // On évite le doublon : si le client répond deux fois, ou s'il avait déjà
    // signalé, un second signalement brouillerait votre arbitrage.
    const { data: dejaSignale } = await supabase.from('signalements')
      .select('id').eq('demande_id', demande.id)
      .not('statut', 'in', '(traite,resolu,rejete)')
      .maybeSingle();

    if (!dejaSignale) {
      await supabase.from('signalements').insert({
        demande_id: demande.id,
        // La colonne s'appelle `reporter_id`, pas `auteur_id`. Vérifié dans le
        // schéma : une insertion sur un nom inventé aurait échoué en silence,
        // et le litige ne se serait jamais ouvert.
        reporter_id: req.user.id,
        motif: 'Arrivée contestée',
        description: 'Le client déclare que le prestataire n\'est pas venu, '
          + 'alors qu\'une arrivée a été enregistrée'
          + (demande.arrivee_qualite === 'eloignee' ? ' à plus d\'un kilomètre de l\'adresse.' : ' sans position vérifiable.'),
        statut: 'nouveau'
      });
    }

    res.json({
      message: 'C\'est noté. Nous examinons la situation — votre paiement reste bloqué en attendant.'
    });
  } catch (e) {
    erreurServeur(res, 'POST /api/demandes/:id/confirmer-arrivee', e);
  }
});

app.patch('/api/demandes/:id/ouvrir-a-tous', auth, async (req, res) => {
  try {
    const { data: demande } = await supabase.from('demandes')
      .select('id, client_id, statut, pro_prefere_id')
      .eq('id', req.params.id).maybeSingle();

    if (!demande) {
      return res.status(404).json({ error: 'Cette demande n\'existe plus.' });
    }
    if (demande.client_id !== req.user.id) {
      return res.status(403).json({
        error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte.'
      });
    }
    if (!demande.pro_prefere_id) {
      return res.status(400).json({ error: 'Cette demande est déjà ouverte à tous.' });
    }
    // Une demande déjà acceptée ne se rouvre pas : un devis a été retenu, et
    // rouvrir ferait arriver des propositions sur une affaire conclue.
    if (demande.statut !== 'en_attente' && demande.statut !== 'devis_recus') {
      return res.status(409).json({
        error: 'Cette demande n\'est plus en attente de devis.'
      });
    }

    // On efface le favori désigné ET la date : la demande redevient une
    // demande ordinaire. Garder le favori aurait laissé un filtre actif que
    // plus rien ne justifie.
    const { error } = await supabase.from('demandes')
      .update({ pro_prefere_id: null, exclusivite_jusqu_a: null })
      .eq('id', demande.id);
    if (error) return erreurServeur(res, 'PATCH ouvrir-a-tous', error);

    res.json({ message: 'Votre demande est maintenant visible par tous les prestataires de votre zone.' });
  } catch (e) {
    erreurServeur(res, 'PATCH /api/demandes/:id/ouvrir-a-tous', e);
  }
});

app.post('/api/favoris/refuser', auth, async (req, res) => {
  try {
    const proId = req.body && req.body.pro_id;
    if (!proId) return res.status(400).json({ error: 'Prestataire requis.' });

    // `upsert` plutôt qu'`insert` : refuser deux fois ne doit pas produire
    // d'erreur — le client peut cliquer deux fois, ou revenir en arrière.
    const { error } = await supabase.from('favoris_refuses')
      .upsert({ client_id: req.user.id, pro_id: proId },
              { onConflict: 'client_id,pro_id' });
    if (error) return erreurServeur(res, 'POST /api/favoris/refuser', error);
    res.json({ message: 'Nous ne vous le proposerons plus.' });
  } catch (e) {
    erreurServeur(res, 'POST /api/favoris/refuser', e);
  }
});

// L'état complet, en un appel : qui est favori, et à qui on ne doit plus le
// proposer. Deux requêtes séparées auraient fait deux allers-retours pour une
// information qu'on lit toujours ensemble.
app.get('/api/favoris/etat', auth, async (req, res) => {
  try {
    const [favoris, refuses] = await Promise.all([
      supabase.from('favoris').select('pro_id').eq('client_id', req.user.id),
      supabase.from('favoris_refuses').select('pro_id').eq('client_id', req.user.id)
    ]);
    res.json({
      favoris: (favoris.data || []).map(f => f.pro_id),
      refuses: (refuses.data || []).map(f => f.pro_id)
    });
  } catch (e) {
    // En cas d'échec, on renvoie des listes vides : le bouton s'affichera à
    // tort plutôt que de priver quelqu'un de la possibilité d'ajouter.
    res.json({ favoris: [], refuses: [] });
  }
});

app.get('/api/favoris', auth, async (req, res) => {
  try {
    const { data: favoris } = await supabase.from('favoris').select('pro_id, created_at').eq('client_id', req.user.id).order('created_at', { ascending: false });
    if (!favoris || !favoris.length) return res.json([]);
    const proIds = favoris.map(f => f.pro_id);
    const { data: pros } = await supabase.from('users').select('id, prenom, nom, note_moyenne, photo, prestations_proposees, disponible').in('id', proIds);
    await signerPhotosDeLot(pros);
    const proMap = {};
    (pros || []).forEach(p => proMap[p.id] = p);
    res.json(favoris.map(f => proMap[f.pro_id]).filter(Boolean));
  } catch (e) {
    erreurServeur(res, 'GET /api/favoris', e);
  }
});

// ══════════════ SIGNALEMENTS ══════════════
// Recueille les signalements de comportement inapproprié — le mécanisme de recueil est en place
// dès maintenant ; leur traitement se fera pour l'instant manuellement (consultation directe en
// base), en attendant un vrai tableau de bord de modération.

app.post('/api/signalements', auth, async (req, res) => {
  try {
    const { signale_id, demande_id, motif, description } = req.body;
    if (!motif) return res.status(400).json({ error: 'Motif requis.' });

    const { data: signalement, error } = await supabase.from('signalements').insert({
      reporter_id: req.user.id,
      signale_id: signale_id || null,
      demande_id: demande_id || null,
      motif: motif,
      description: description || null,
      statut: 'nouveau'
    }).select().single();
    if (error) {
      console.error('Erreur création signalement:', error);
      return res.status(400).json({ error: 'Impossible d\'envoyer votre message pour l\'instant. Réessayez dans un instant.' });
    }

    // Notifie immédiatement l'équipe Gleam par email — sans ça, un signalement resterait stocké
    // silencieusement en base sans que personne ne soit jamais prévenu qu'il existe. C'est
    // exactement ce que font les autres plateformes (Uber, Wecasa...) : une alerte immédiate à
    // chaque signalement, jamais un simple enregistrement passif.
    const { data: reporter } = await supabase.from('users').select('prenom, nom, email').eq('id', req.user.id).single();
    let signaleInfo = null;
    if (signale_id) {
      const { data } = await supabase.from('users').select('prenom, nom, email').eq('id', signale_id).single();
      signaleInfo = data;
    }

    // Si le signalement concerne une demande précise, on rassemble automatiquement les preuves
    // techniques déjà disponibles — plutôt que de devoir aller les chercher manuellement en cas de
    // litige (ex: un client prétendant que le pro n'est jamais venu, alors que l'arrivée a bien
    // été confirmée avec une position GPS cohérente avec l'adresse déclarée).
    let preuves = 'Aucune demande précise associée à ce signalement.';
    if (demande_id) {
      const { data: demandeConcernee } = await supabase.from('demandes').select('statut, prestation_demarree_le, distance_gps_arrivee, photos_avant, photos_apres').eq('id', demande_id).maybeSingle();
      if (demandeConcernee) {
        const aDesPhotosAvant = demandeConcernee.photos_avant ? JSON.parse(demandeConcernee.photos_avant).length : 0;
        const aDesPhotosApres = demandeConcernee.photos_apres ? JSON.parse(demandeConcernee.photos_apres).length : 0;
        preuves = `Statut de la demande : ${demandeConcernee.statut}. ` +
          (demandeConcernee.prestation_demarree_le
            ? `Le prestataire a confirmé son arrivée le ${new Date(demandeConcernee.prestation_demarree_le).toLocaleString('fr-FR')}` +
              (demandeConcernee.distance_gps_arrivee !== null ? ` (position GPS à ${demandeConcernee.distance_gps_arrivee}m de l'adresse déclarée).` : ' (position GPS non disponible).')
            : 'Le prestataire n\'a jamais confirmé son arrivée dans l\'app.') +
          ` Photos avant : ${aDesPhotosAvant}. Photos après : ${aDesPhotosApres}.`;
      }
    }

    const adminEmail = process.env.ADMIN_EMAIL || process.env.FROM_EMAIL;
    if (adminEmail) {
      sendEmail('nouveau_signalement', adminEmail, {
        reporterNom: reporter ? `${reporter.prenom} ${reporter.nom} (${reporter.email})` : req.user.id,
        signaleNom: signaleInfo ? `${signaleInfo.prenom} ${signaleInfo.nom} (${signaleInfo.email})` : 'Non spécifié (contact général)',
        motif: motif,
        description: description || 'Aucune description fournie.',
        preuves: preuves,
        signalementId: signalement.id
      }).catch(e => console.error('Email nouveau_signalement:', e));
    }

    res.status(201).json({ message: 'Signalement envoyé. Notre équipe va l\'examiner.' });
  } catch (e) {
    erreurServeur(res, 'route inconnue', e);
  }
});

// ══════════════ ÉVALUATIONS ══════════════

app.post('/api/evaluations', auth, async (req, res) => {
  try {
    const { demande_id, evalue_id, note, commentaire } = req.body;
    if (!demande_id || !evalue_id || !note) return res.status(400).json({ error: 'Champs manquants.' });
    if (note < 1 || note > 5) return res.status(400).json({ error: 'Note entre 1 et 5.' });
    if (evalue_id === req.user.id) return res.status(400).json({ error: 'Vous ne pouvez pas vous auto-évaluer.' });

    const { data: demande } = await supabase.from('demandes').select('*').eq('id', demande_id).single();
    if (!demande) return res.status(404).json({ error: 'Cette demande n\'existe plus. Elle a sans doute été supprimée ou annulée par le client.' });
    if (demande.statut !== 'terminee') return res.status(400).json({ error: 'Vous ne pouvez noter qu\'une prestation terminée.' });

    const { data: devisAccepte } = await supabase.from('devis').select('societe_id').eq('demande_id', demande_id).eq('statut', 'accepte').maybeSingle();
    const estClient = demande.client_id === req.user.id;
    const estPro = devisAccepte && devisAccepte.societe_id === req.user.id;
    if (!estClient && !estPro) return res.status(403).json({ error: 'Vous n\'avez pas accès à cet élément. Il appartient peut-être à un autre compte — vérifiez que vous êtes connecté avec le bon.' });

    // Vérifie que la personne notée est bien "l'autre partie" de cette prestation précise
    const autrePartieAttendue = estClient ? (devisAccepte && devisAccepte.societe_id) : demande.client_id;
    if (evalue_id !== autrePartieAttendue) return res.status(400).json({ error: 'Cette personne n\'est pas liée à cette prestation.' });

    // Empêche de noter deux fois la même prestation
    const { data: dejaNote } = await supabase.from('evaluations').select('id').eq('demande_id', demande_id).eq('evaluateur_id', req.user.id).maybeSingle();
    if (dejaNote) return res.status(400).json({ error: 'Vous avez déjà évalué cette prestation.' });

    const { data, error } = await supabase.from('evaluations').insert({
      demande_id: demande_id,
      evaluateur_id: req.user.id,
      evalue_id: evalue_id,
      note: parseInt(note),
      commentaire: commentaire || null
    }).select().single();
    if (error) { console.error('Erreur Supabase, message technique complet:', error); return res.status(400).json({ error: traduireErreurSupabase(error.message) }); }

    const { data: notes } = await supabase.from('evaluations').select('note').eq('evalue_id', evalue_id);
    const moyenne = notes.reduce(function(a, b) { return a + b.note; }, 0) / notes.length;
    await supabase.from('users').update({ note_moyenne: Math.round(moyenne * 100) / 100 }).eq('id', evalue_id);

    // ── LA PERSONNE NOTÉE DOIT LE SAVOIR ────────────────────────────────
    // C'est une reconnaissance autant qu'une information : un artisan qui
    // reçoit cinq étoiles et n'en sait rien perd la seule récompense
    // immatérielle de la plateforme.
    //
    // Et pour une note basse, il doit pouvoir réagir — vous écrire,
    // s'expliquer — plutôt que de la découvrir des semaines plus tard.
    envoyerNotificationPush(evalue_id, {
      titre: note >= 4 ? 'Vous avez reçu ' + note + ' étoiles' : 'Vous avez reçu un avis',
      corps: note >= 4
        ? 'Merci pour votre travail — cet avis apparaîtra sur votre profil.'
        : 'Un client vient de vous évaluer. Consultez son commentaire.',
      url: '/#profile'
    }).catch(() => {});

    res.status(201).json(data);
  } catch (e) {
    erreurServeur(res, 'POST /api/evaluations', e);
  }
});

// Liste des avis reçus par l'utilisateur connecté (rubrique "Mes avis")
app.get('/api/evaluations/mes-avis', auth, async (req, res) => {
  try {
    const { data: evaluations } = await supabase.from('evaluations').select('*').eq('evalue_id', req.user.id).order('created_at', { ascending: false });
    if (!evaluations || !evaluations.length) return res.json([]);
    const demandeIds = [...new Set(evaluations.map(e => e.demande_id))];
    const evaluateurIds = [...new Set(evaluations.map(e => e.evaluateur_id))];
    const { data: demandes } = await supabase.from('demandes').select('id, prestation').in('id', demandeIds);
    const { data: evaluateurs } = await supabase.from('users').select('id, prenom').in('id', evaluateurIds);
    const demandesMap = {}; (demandes || []).forEach(d => { demandesMap[d.id] = d; });
    const evaluateursMap = {}; (evaluateurs || []).forEach(u => { evaluateursMap[u.id] = u; });
    res.json(evaluations.map(e => ({
      ...e,
      prestation: demandesMap[e.demande_id] ? demandesMap[e.demande_id].prestation : null,
      evaluateur_prenom: evaluateursMap[e.evaluateur_id] ? evaluateursMap[e.evaluateur_id].prenom : 'Utilisateur Gleam'
    })));
  } catch (e) {
    erreurServeur(res, 'GET /api/evaluations/mes-avis', e);
  }
});

// Liste des identifiants de demandes déjà notées par l'utilisateur connecté (pour cacher le
// bouton "Noter" une fois l'avis déjà donné, plutôt que de compter uniquement sur le refus serveur)
app.get('/api/evaluations/mes-notes-donnees', auth, async (req, res) => {
  try {
    const { data } = await supabase.from('evaluations').select('demande_id').eq('evaluateur_id', req.user.id);
    res.json((data || []).map(e => e.demande_id));
  } catch (e) {
    erreurServeur(res, 'GET /api/evaluations/mes-notes-donnees', e);
  }
});

// Écarter une demande — action personnelle et réversible. Le client n'en est
// jamais informé : lui annoncer un refus serait décourageant sans rien lui
// apprendre d'actionnable.
app.post('/api/demandes/:id/masquer', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('type').eq('id', req.user.id).single();
    if (!user || !isProType(user.type)) return res.status(403).json({ error: 'Cette action est réservée aux comptes prestataires. Votre compte est un compte client.' });

    // Le motif est facultatif, et volontairement borné à une liste connue :
    // du texte libre serait impossible à agréger, donc inutile pour comprendre
    // pourquoi les demandes n'aboutissent pas.
    //
    // « prix trop bas » ne figure PAS dans cette liste, et c'est délibéré : le
    // prestataire fixe lui-même son prix dans son devis. Aucun montant ne lui est
    // imposé — une demande ne porte ni budget ni prix indicatif, l'estimation
    // n'étant montrée qu'au client avant publication. Lui proposer ce motif
    // l'inviterait à répondre à une question qui ne se pose pas.
    //
    // Le vrai motif économique est ailleurs : la prestation est trop petite pour
    // justifier le déplacement. Celui-là appelle une décision produit — panier
    // minimum, frais de déplacement, ou regroupement de demandes.
    const motifsAdmis = ['trop_loin', 'creneau_impossible', 'trop_petit', 'hors_competence', 'autre'];
    const motif = motifsAdmis.includes(req.body && req.body.motif) ? req.body.motif : null;

    const { error } = await supabase.from('demandes_masquees')
      .upsert({ pro_id: req.user.id, demande_id: req.params.id, motif },
              { onConflict: 'pro_id,demande_id' });
    if (error) return res.status(500).json({ error: 'Impossible d\'écarter cette demande.' });

    res.json({ message: 'Demande écartée.' });
  } catch (e) {
    erreurServeur(res, 'POST /api/demandes/:id/masquer', e);
  }
});

// Annuler : la demande réapparaît dans la liste.
app.delete('/api/demandes/:id/masquer', auth, async (req, res) => {
  try {
    await supabase.from('demandes_masquees').delete()
      .eq('pro_id', req.user.id).eq('demande_id', req.params.id);
    res.json({ message: 'Demande rétablie.' });
  } catch (e) {
    erreurServeur(res, 'DELETE /api/demandes/:id/masquer', e);
  }
});

// Vérification en direct pendant la saisie du SIRET. Volontairement accessible
// sans compte : elle sert précisément au moment de l'inscription, avant qu'un
// compte n'existe. Elle ne renvoie que des données publiques du répertoire
// officiel — rien qui n'apparaisse déjà sur annuaire-entreprises.data.gouv.fr.
app.get('/api/verification/siret', publicLimiter, async (req, res) => {
  const resultat = await verifierSiretOfficiel(req.query.siret);
  res.json({
    statut: resultat.statut,
    nom: resultat.infos ? resultat.infos.nom : null,
    activite: resultat.infos ? resultat.infos.activite_libelle : null,
    activite_code: resultat.infos ? resultat.infos.activite_code : null,
    commune: resultat.infos ? resultat.infos.commune : null
  });
});

// ══════════════ PROS / SOCIÉTÉS ══════════════

app.get('/api/societes', auth, async (req, res) => {
  const { data } = await supabase.from('users').select('id, prenom, nom, note_moyenne, disponible').eq('type', 'pro').eq('disponible', true);
  res.json(data || []);
});

app.patch('/api/societes/disponibilite', auth, async (req, res) => {
  await supabase.from('users').update({ disponible: Boolean(req.body.disponible) }).eq('id', req.user.id);
  res.json({ message: 'Disponibilité mise à jour.' });
});

// Compléter ses justificatifs après l'inscription. Le SIRET est vérifié auprès
// du répertoire officiel au passage, sans bloquer : un numéro introuvable est
// enregistré et signalé à l'administrateur, il n'est pas refusé.
app.patch('/api/societes/justificatifs', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('type').eq('id', req.user.id).single();
    if (!user || !isProType(user.type)) return res.status(403).json({ error: 'Cette action est réservée aux comptes prestataires. Votre compte est un compte client.' });

    const misAJour = {};

    if (req.body.siret !== undefined) {
      const siret = String(req.body.siret || '').replace(/\s/g, '').trim();
      if (siret && !/^\d{14}$/.test(siret))
        return res.status(400).json({ error: 'Numéro SIRET invalide (14 chiffres attendus).' });
      misAJour.siret = siret || null;
    }
    if (req.body.assurance_rc_pro !== undefined)
      misAJour.assurance_rc_pro = Boolean(req.body.assurance_rc_pro);
    if (req.body.assurance_compagnie !== undefined)
      misAJour.assurance_compagnie = String(req.body.assurance_compagnie || '').trim() || null;
    if (req.body.assurance_police !== undefined)
      misAJour.assurance_police = String(req.body.assurance_police || '').trim() || null;

    if (!Object.keys(misAJour).length)
      return res.status(400).json({ error: 'Aucune modification à enregistrer : les champs sont identiques aux valeurs actuelles.' });

    const { error } = await supabase.from('users').update(misAJour).eq('id', req.user.id);
    if (error) return res.status(400).json({ error: traduireErreurSupabase(error.message) });

    // Le partage est vérifié tout de suite — c'est immédiat, une seule requête —
    // afin de pouvoir en informer le prestataire dans la même réponse. La
    // vérification auprès du répertoire officiel, elle, part sans await.
    let partage = { partage: false };
    if (misAJour.siret) {
      partage = await signalerSiretPartage(req.user.id, misAJour.siret);
      enregistrerVerificationSiret(req.user.id, misAJour.siret).catch(() => {});
    }

    const { data: apres } = await supabase.from('users')
      .select('siret, assurance_rc_pro').eq('id', req.user.id).single();
    res.json({
      message: 'Justificatifs enregistrés.',
      justificatifs_manquants: justificatifsManquants(apres),
      siret_partage: partage.partage
    });
  } catch (e) {
    erreurServeur(res, 'PATCH /api/societes/justificatifs', e);
  }
});

// Attribue un numéro de facture séquentiel, une seule fois par paiement.
//
// L'article 242 nonies A de l'annexe II du CGI impose une séquence
// « chronologique continue, sans rupture ». L'attribution se fait donc en base,
// par une fonction atomique : deux paiements aboutissant dans la même
// milliseconde ne peuvent pas recevoir le même numéro.
//
// Ne lève jamais d'exception : un échec de numérotation ne doit pas empêcher un
// encaissement. Le numéro sera attribué au prochain accès à la facture.
// ═══════════════════════════════════════════════════════════════════════════
// LE NUMÉRO DE LA FACTURE DE COMMISSION
//
// Gleam vend un service d'intermédiation au prestataire : c'est une vente
// entre professionnels, et l'article L.441-9 impose une facture, sans seuil.
//
// Sa suite est SÉPARÉE de celle des prestations — série « COM- ». Les deux
// factures n'ont pas le même émetteur : la prestation est vendue par le
// prestataire, la commission par Gleam. Mêler les deux séries rendrait la
// numérotation incompréhensible à un contrôle.
// ═══════════════════════════════════════════════════════════════════════════
async function attribuerNumeroCommission(paiementId) {
  try {
    const { data: existant } = await supabase.from('paiements')
      .select('numero_facture_commission').eq('id', paiementId).single();
    if (existant && existant.numero_facture_commission) {
      return existant.numero_facture_commission;
    }
    const { data: numero, error } = await supabase
      .rpc('attribuer_numero_commission', { p_annee: new Date().getFullYear() });
    if (error || !numero) {
      console.error('Numérotation de commission impossible :', error && error.message);
      return null;
    }
    await supabase.from('paiements')
      .update({ numero_facture_commission: numero }).eq('id', paiementId);
    return numero;
  } catch (e) {
    console.error('Numérotation de commission :', e.message);
    return null;
  }
}

async function attribuerNumeroFacture(paiementId) {
  try {
    const { data: existant } = await supabase.from('paiements')
      .select('numero_facture').eq('id', paiementId).single();
    if (existant && existant.numero_facture) return existant.numero_facture;

    const { data: numero, error } = await supabase
      .rpc('attribuer_numero_facture', { p_annee: new Date().getFullYear() });
    if (error || !numero) {
      console.error('Numérotation de facture impossible :', error && error.message);
      return null;
    }

    await supabase.from('paiements').update({ numero_facture: numero }).eq('id', paiementId);
    console.log('🧾 Facture ' + numero + ' — paiement ' + paiementId);
    return numero;
  } catch (e) {
    console.error('Numérotation de facture :', e.message);
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// DÉCLARATION ANNUELLE DES REVENUS DES PRESTATAIRES — dispositif DPI-DAC7
//
// Directive (UE) 2021/514, transposée aux articles 1649 ter A à 1649 ter E du
// CGI. En vigueur depuis le 1ᵉʳ janvier 2023.
//
// Gleam entre dans le périmètre sans ambiguïté : le texte vise « tout logiciel
// ou application permettant à des prestataires d'être connectés à des
// acheteurs », et « inclut également tout mécanisme de perception et de
// paiement d'une contrepartie ». Mise en relation ET encaissement.
//
// Ce que la DGFiP attend, pour chaque prestataire actif :
//   · ses coordonnées d'identification
//   · le nombre d'opérations réalisées
//   · les revenus perçus, ventilés PAR TRIMESTRE
//   · les frais, commissions et taxes prélevés par la plateforme
//
// À déposer avant le 31 janvier de l'année suivante, en XML normalisé.
//
// Cette route produit les agrégats exacts. Elle ne génère PAS le fichier XML
// au format DPI_OECD : c'est un travail spécialisé, avec un schéma imposé et
// deux niveaux de contrôle. Elle fournit les données justes, sous une forme
// qu'un comptable ou un prestataire spécialisé peut reprendre.
//
// L'article 242 bis du CGI impose en outre de transmettre à chaque prestataire
// un récapitulatif annuel de ses opérations, dans le même délai. Les mêmes
// données servent.
// ─────────────────────────────────────────────────────────────────────────────
// Les revenus de Gleam : la commission est votre chiffre d'affaires, celui que
// vous déclarez. Ventilé par mois ET par trimestre, parce que la TVA se déclare
// selon l'un ou l'autre régime.
app.get('/api/admin/mes-revenus', adminAuth, async (req, res) => {
  try {
    const annee = parseInt(req.query.annee, 10) || new Date().getFullYear();
    const { data: paiements } = await supabase.from('paiements')
      .select('montant, commission, montant_societe, statut, created_at, numero_facture')
      .in('statut', ['paye', 'libere'])
      .gte('created_at', annee + '-01-01T00:00:00.000Z')
      .lt('created_at', (annee + 1) + '-01-01T00:00:00.000Z')
      .limit(20000);

    const mois = Array.from({ length: 12 }, () => ({ encaisse: 0, commission: 0, reverse: 0, nb: 0 }));
    (paiements || []).forEach((p) => {
      const m = new Date(p.created_at).getMonth();
      mois[m].encaisse += parseFloat(p.montant) || 0;
      mois[m].commission += parseFloat(p.commission) || 0;
      mois[m].reverse += parseFloat(p.montant_societe) || 0;
      mois[m].nb += 1;
    });

    const arrondir = (n) => Math.round(n * 100) / 100;
    const noms = ['Janvier','Février','Mars','Avril','Mai','Juin',
                  'Juillet','Août','Septembre','Octobre','Novembre','Décembre'];

    const parMois = mois.map((m, i) => ({
      mois: i + 1, nom: noms[i], nb: m.nb,
      encaisse: arrondir(m.encaisse), commission: arrondir(m.commission), reverse: arrondir(m.reverse)
    }));

    const parTrimestre = [0, 1, 2, 3].map((t) => {
      const tranche = mois.slice(t * 3, t * 3 + 3);
      return {
        trimestre: 'T' + (t + 1),
        nb: tranche.reduce((s, m) => s + m.nb, 0),
        encaisse: arrondir(tranche.reduce((s, m) => s + m.encaisse, 0)),
        commission: arrondir(tranche.reduce((s, m) => s + m.commission, 0)),
        reverse: arrondir(tranche.reduce((s, m) => s + m.reverse, 0))
      };
    });

    res.json({
      annee, par_mois: parMois, par_trimestre: parTrimestre,
      total: {
        nb: parMois.reduce((s, m) => s + m.nb, 0),
        encaisse: arrondir(parMois.reduce((s, m) => s + m.encaisse, 0)),
        commission: arrondir(parMois.reduce((s, m) => s + m.commission, 0)),
        reverse: arrondir(parMois.reduce((s, m) => s + m.reverse, 0))
      }
    });
  } catch (e) {
    erreurServeur(res, 'GET /api/admin/mes-revenus', e);
  }
});

// La liste des factures émises, avec contrôle de séquence.
//
// Une numérotation irrégulière ne se rattrape pas : mieux vaut la surveiller en
// permanence que la découvrir lors d'un contrôle. Cette route vérifie à chaque
// consultation qu'il n'existe ni doublon, ni trou dans la suite.
app.get('/api/admin/factures', adminAuth, async (req, res) => {
  try {
    const annee = parseInt(req.query.annee, 10) || new Date().getFullYear();
    const { data: paiements } = await supabase.from('paiements')
      .select('id, demande_id, numero_facture, montant, commission, montant_societe, statut, created_at, client_id, societe_id')
      .in('statut', ['paye', 'libere'])
      .gte('created_at', annee + '-01-01T00:00:00.000Z')
      .lt('created_at', (annee + 1) + '-01-01T00:00:00.000Z')
      .order('created_at', { ascending: true })
      .limit(20000);

    const ids = [...new Set([].concat(
      (paiements || []).map(p => p.client_id), (paiements || []).map(p => p.societe_id)
    ).filter(Boolean))];
    const { data: gens } = ids.length
      ? await supabase.from('users').select('id, prenom, nom, raison_sociale, type').in('id', ids)
      : { data: [] };
    const nomDe = {};
    (gens || []).forEach(u => {
      nomDe[u.id] = u.raison_sociale || ((u.prenom || '') + ' ' + (u.nom || '')).trim() || '—';
    });

    const factures = (paiements || []).map(p => ({
      numero: p.numero_facture,
      date: p.created_at,
      client: nomDe[p.client_id] || '—',
      prestataire: nomDe[p.societe_id] || '—',
      montant: parseFloat(p.montant) || 0,
      commission: parseFloat(p.commission) || 0,
      net: parseFloat(p.montant_societe) || 0
    }));

    // Contrôle de séquence : les rangs doivent former 1, 2, 3… sans trou.
    const rangs = factures.filter(f => f.numero)
      .map(f => parseInt(String(f.numero).split('-').pop(), 10))
      .filter(n => !isNaN(n)).sort((a, b) => a - b);

    const doublons = rangs.filter((n, i) => i > 0 && n === rangs[i - 1]);
    const trous = [];
    for (let i = 1; i <= (rangs.length ? rangs[rangs.length - 1] : 0); i++) {
      if (rangs.indexOf(i) === -1) trous.push(i);
    }

    res.json({
      annee, factures,
      sans_numero: factures.filter(f => !f.numero).length,
      sequence: {
        conforme: !doublons.length && !trous.length && !factures.filter(f => !f.numero).length,
        doublons: [...new Set(doublons)],
        trous,
        premier: rangs.length ? rangs[0] : null,
        dernier: rangs.length ? rangs[rangs.length - 1] : null
      }
    });
  } catch (e) {
    erreurServeur(res, 'GET /api/admin/factures', e);
  }
});

app.get('/api/admin/declaration-annuelle', adminAuth, async (req, res) => {
  try {
    const annee = parseInt(req.query.annee, 10) || (new Date().getFullYear() - 1);
    const debut = annee + '-01-01T00:00:00.000Z';
    const fin = (annee + 1) + '-01-01T00:00:00.000Z';

    // Seuls les paiements réellement encaissés comptent : un paiement remboursé
    // ou abandonné n'a produit aucun revenu à déclarer.
    const { data: paiements } = await supabase.from('paiements')
      .select('id, demande_id, societe_id, montant, montant_societe, commission, statut, created_at')
      .in('statut', ['paye', 'libere'])
      .gte('created_at', debut).lt('created_at', fin)
      .limit(20000);

    const idsPros = [...new Set((paiements || []).map(p => p.societe_id).filter(Boolean))];
    const { data: pros } = idsPros.length
      ? await supabase.from('users')
          .select('id, prenom, nom, email, telephone, siret, raison_sociale, adresse_facturation, type, siret_donnees')
          .in('id', idsPros)
      : { data: [] };

    const parPro = {};
    (pros || []).forEach((p) => {
      parPro[p.id] = {
        id: p.id,
        nom: (p.raison_sociale || ((p.prenom || '') + ' ' + (p.nom || '')).trim() || p.email),
        email: p.email,
        telephone: p.telephone || null,
        siret: p.siret || null,
        // Le nom officiel du répertoire prime sur le nom déclaré : c'est celui
        // que l'administration reconnaîtra.
        nom_officiel: (p.siret_donnees && p.siret_donnees.nom) || null,
        adresse: p.adresse_facturation || null,
        nb_operations: 0,
        revenu_brut: 0,
        commission_prelevee: 0,
        revenu_net: 0,
        trimestres: { T1: 0, T2: 0, T3: 0, T4: 0 }
      };
    });

    (paiements || []).forEach((p) => {
      const f = parPro[p.societe_id];
      if (!f) return;
      const brut = parseFloat(p.montant) || 0;
      const commission = parseFloat(p.commission) || 0;
      const net = parseFloat(p.montant_societe) || (brut - commission);
      const trimestre = 'T' + (Math.floor(new Date(p.created_at).getMonth() / 3) + 1);

      f.nb_operations += 1;
      f.revenu_brut += brut;
      f.commission_prelevee += commission;
      f.revenu_net += net;
      f.trimestres[trimestre] += net;
    });

    const arrondir = (n) => Math.round(n * 100) / 100;
    const prestataires = Object.values(parPro).map((f) => ({
      ...f,
      revenu_brut: arrondir(f.revenu_brut),
      commission_prelevee: arrondir(f.commission_prelevee),
      revenu_net: arrondir(f.revenu_net),
      trimestres: {
        T1: arrondir(f.trimestres.T1), T2: arrondir(f.trimestres.T2),
        T3: arrondir(f.trimestres.T3), T4: arrondir(f.trimestres.T4)
      },
      // Un prestataire sans SIRET renseigné ne peut pas être déclaré : c'est
      // son identifiant fiscal. À signaler avant l'échéance, pas après.
      declarable: !!f.siret
    })).sort((a, b) => b.revenu_net - a.revenu_net);

    res.json({
      annee,
      echeance: '31 janvier ' + (annee + 1),
      prestataires,
      totaux: {
        nb_prestataires: prestataires.length,
        nb_operations: prestataires.reduce((s, p) => s + p.nb_operations, 0),
        revenu_brut: arrondir(prestataires.reduce((s, p) => s + p.revenu_brut, 0)),
        commission_prelevee: arrondir(prestataires.reduce((s, p) => s + p.commission_prelevee, 0)),
        revenu_net: arrondir(prestataires.reduce((s, p) => s + p.revenu_net, 0)),
        sans_siret: prestataires.filter((p) => !p.declarable).length
      }
    });
  } catch (e) {
    console.error('Déclaration annuelle :', e.message);
    erreurServeur(res, 'GET /api/admin/declaration-annuelle', e);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// DIAGNOSTIC — les chiffres qui disent quoi corriger
//
// Les statistiques existantes comptent des volumes : combien de clients,
// combien de demandes, combien encaissé. Utile, mais muet sur la seule question
// qui compte tant que la plateforme démarre : qu'est-ce qui ne marche pas ?
//
// Tout est agrégé ici en JavaScript plutôt qu'en SQL. À ces volumes — quelques
// dizaines de lignes — la différence est imperceptible, et cela évite d'écrire
// des requêtes que le client Supabase ne sait pas composer. Le plafond de 5 000
// lignes garde la route rapide si l'activité décolle ; il faudra passer à des
// vues SQL agrégées bien avant de l'atteindre.
// ─────────────────────────────────────────────────────────────────────────────
const LIBELLES_MOTIF_SIGNALEMENT = {
  reclamation: 'Réclamation sur une prestation',
  bug: 'Problème technique',
  absence: 'Prestataire absent',
  paiement: 'Litige de paiement',
  comportement: 'Comportement inapproprié',
  autre: 'Autre'
};

const LIBELLES_MOTIF_ECARTEMENT = {
  trop_loin: 'Trop loin',
  creneau_impossible: 'Créneau impossible',
  trop_petit: 'Prestation trop petite',
  hors_competence: 'Hors de leur métier',
  autre: 'Autre'
};

function compterPar(liste, cle, libelles) {
  const compte = {};
  (liste || []).forEach((x) => {
    const v = x[cle] || 'autre';
    compte[v] = (compte[v] || 0) + 1;
  });
  return Object.keys(compte)
    .map((k) => ({ cle: k, libelle: (libelles && libelles[k]) || k, nombre: compte[k] }))
    .sort((a, b) => b.nombre - a.nombre);
}

function mediane(valeurs) {
  const v = valeurs.filter((x) => typeof x === 'number' && isFinite(x)).sort((a, b) => a - b);
  if (!v.length) return null;
  const m = Math.floor(v.length / 2);
  return v.length % 2 ? v[m] : (v[m - 1] + v[m]) / 2;
}

// Quelle version du serveur tourne réellement ?
//
// Nous avons perdu plusieurs échanges à corriger des défauts déjà corrigés,
// sans moyen de savoir si le fichier déployé était le bon. Une empreinte
// calculée au démarrage tranche la question en une seconde.
const VERSION_SERVEUR = (function(){
  try {
    const crypto = require('crypto');
    const contenu = require('fs').readFileSync(__filename, 'utf8');
    return crypto.createHash('md5').update(contenu).digest('hex').slice(0, 7);
  } catch (e) { return 'inconnue'; }
})();
const DEMARRE_LE = new Date().toISOString();

// ═══════════════════════════════════════════════════════════════════════════
// STRIPE EST-IL EN TEST OU EN PRODUCTION ?
//
// Les clés viennent des variables d'environnement — aucune n'est en dur, c'est
// bien. Mais rien ne disait laquelle était chargée.
//
// Une clé de test en production ne lève AUCUNE erreur : les paiements
// s'enchaînent, les écrans confirment, les montants s'affichent. Simplement,
// aucun euro ne bouge. On peut prendre des commandes pendant des jours sans
// s'en apercevoir.
//
// C'est exactement le genre de défaut que cette application a eu ailleurs :
// tout fonctionne, rien ne se passe.
// ═══════════════════════════════════════════════════════════════════════════
const STRIPE_MODE = (process.env.STRIPE_SECRET_KEY || '').startsWith('sk_live_')
  ? 'production'
  : ((process.env.STRIPE_SECRET_KEY || '').startsWith('sk_test_') ? 'test' : 'absente');

// La clé publique et la clé secrète doivent être du même mode. Les mélanger
// produit des erreurs incompréhensibles au moment du paiement, jamais avant.
const STRIPE_MODE_PUBLIC = (process.env.STRIPE_PUBLISHABLE_KEY || '').startsWith('pk_live_')
  ? 'production'
  : ((process.env.STRIPE_PUBLISHABLE_KEY || '').startsWith('pk_test_') ? 'test' : 'absente');

if (STRIPE_MODE !== STRIPE_MODE_PUBLIC) {
  console.error('╔═══════════════════════════════════════════════════════════════╗');
  console.error('║  CLÉS STRIPE INCOHÉRENTES                                     ║');
  console.error('║  secrète : ' + STRIPE_MODE.padEnd(12) + '  publique : ' + STRIPE_MODE_PUBLIC.padEnd(12) + '     ║');
  console.error('║  Les paiements échoueront au moment du règlement, pas avant.  ║');
  console.error('╚═══════════════════════════════════════════════════════════════╝');
}

if (STRIPE_MODE === 'test' && process.env.NODE_ENV === 'production') {
  console.warn('╔═══════════════════════════════════════════════════════════════╗');
  console.warn('║  STRIPE EST EN MODE TEST, SUR UN SERVEUR DE PRODUCTION        ║');
  console.warn('║  Les clients paieront sans qu\'aucun euro ne soit encaissé.    ║');
  console.warn('║  Remplacez STRIPE_SECRET_KEY et STRIPE_PUBLISHABLE_KEY.       ║');
  console.warn('╚═══════════════════════════════════════════════════════════════╝');
}

app.get('/api/admin/version', adminAuth, (req, res) => {
  res.json({
    version: VERSION_SERVEUR,
    demarre_le: DEMARRE_LE,
    // Les routes récentes : leur présence dit si le déploiement a pris.
    // Le mode Stripe, visible en une seconde depuis l'administration. Sans
    // cela, il faut ouvrir Railway et lire une variable d'environnement.
    stripe: STRIPE_MODE,
    stripe_coherent: STRIPE_MODE === STRIPE_MODE_PUBLIC,
    // Le seul marqueur qui distingue vraiment les deux versions : la fonction
    // de balayage n'existait pas avant. `cloture_automatique` était vrai dans
    // les deux, donc inutile pour savoir si le déploiement a pris.
    cloture_planifiee: typeof balayerPrestationsAValider === 'function',
    cloture_dernier_passage: CLOTURE_DERNIER_PASSAGE,
    cloture_dernier_resultat: CLOTURE_DERNIER_RESULTAT,
    routes_recentes: {
      dossiers: true,
      cloture_automatique: typeof cloturerPrestationsOubliees === 'function',
      photos_stockage: typeof lienPhotoProfil === 'function'
    }
  });
});

app.get('/api/admin/diagnostic', adminAuth, async (req, res) => {
  try {
    const [demandes, devis, signalements, ecartements, documents, evaluations] = await Promise.all([
      supabase.from('demandes').select('id, statut, prestation, adresse, created_at').limit(5000).then(r => r.data || []),
      supabase.from('devis').select('id, demande_id, statut, prix_ttc, created_at').limit(5000).then(r => r.data || []),
      supabase.from('signalements').select('motif, statut').limit(5000).then(r => r.data || []),
      supabase.from('demandes_masquees').select('motif').not('motif', 'is', null).limit(5000).then(r => r.data || []),
      supabase.from('documents_pro').select('statut, motif_refus').limit(5000).then(r => r.data || []),
      supabase.from('evaluations').select('note').limit(5000).then(r => r.data || [])
    ]);

    // ── Taux de réponse : LE chiffre central ──────────────────────────────
    // Une demande sans devis n'a servi à rien : ni au client, ni au prestataire,
    // ni à vous. C'est la mesure la plus honnête de la santé de la place de marché.
    const premierDevisPar = {};
    devis.forEach((v) => {
      const t = new Date(v.created_at).getTime();
      if (!premierDevisPar[v.demande_id] || t < premierDevisPar[v.demande_id]) premierDevisPar[v.demande_id] = t;
    });

    const avecDevis = demandes.filter((d) => premierDevisPar[d.id]).length;
    const sansDevis = demandes.length - avecDevis;
    const morteSansDevis = demandes.filter(
      (d) => !premierDevisPar[d.id] && (d.statut === 'expiree' || d.statut === 'expire_sans_paiement')
    ).length;

    // Délai de première réponse, en heures. La médiane plutôt que la moyenne :
    // une seule demande répondue au bout de trois jours fausserait la moyenne.
    const delais = demandes
      .filter((d) => premierDevisPar[d.id])
      .map((d) => (premierDevisPar[d.id] - new Date(d.created_at).getTime()) / 3600000)
      .filter((h) => h >= 0);

    // ── Conversion des devis ──────────────────────────────────────────────
    const devisRepondus = devis.filter((v) => v.statut !== 'envoye').length;
    const devisAcceptes = devis.filter((v) => v.statut === 'accepte').length;

    // ── Villes ────────────────────────────────────────────────────────────
    const parVille = {};
    demandes.forEach((d) => {
      const ville = String(d.adresse || '').split(',').pop().trim() || 'Inconnue';
      if (!parVille[ville]) parVille[ville] = { ville, demandes: 0, sans_devis: 0 };
      parVille[ville].demandes++;
      if (!premierDevisPar[d.id]) parVille[ville].sans_devis++;
    });

    const notes = evaluations.map((e) => parseFloat(e.note)).filter((n) => !isNaN(n));

    res.json({
      reponse: {
        total_demandes: demandes.length,
        avec_devis: avecDevis,
        sans_devis: sansDevis,
        taux_reponse: demandes.length ? Math.round((avecDevis / demandes.length) * 100) : null,
        mortes_sans_devis: morteSansDevis,
        delai_median_heures: delais.length ? Math.round(mediane(delais) * 10) / 10 : null
      },
      conversion: {
        devis_envoyes: devis.length,
        devis_repondus: devisRepondus,
        devis_acceptes: devisAcceptes,
        // Calculé sur les devis ayant reçu une réponse : inclure ceux encore en
        // attente ferait baisser le taux à mesure que l'activité augmente.
        taux_acceptation: devisRepondus ? Math.round((devisAcceptes / devisRepondus) * 100) : null
      },
      signalements: {
        par_motif: compterPar(signalements, 'motif', LIBELLES_MOTIF_SIGNALEMENT),
        ouverts: signalements.filter((s) => s.statut !== 'traite').length,
        total: signalements.length
      },
      ecartements: {
        par_motif: compterPar(ecartements, 'motif', LIBELLES_MOTIF_ECARTEMENT),
        total: ecartements.length
      },
      documents: {
        en_attente: documents.filter((d) => d.statut === 'en_attente').length,
        refuses_par_motif: compterPar(documents.filter((d) => d.statut === 'refuse'), 'motif_refus', MOTIFS_REFUS),
        total: documents.length
      },
      villes: Object.values(parVille).sort((a, b) => b.demandes - a.demandes).slice(0, 8),
      qualite: {
        nombre_avis: notes.length,
        note_moyenne: notes.length ? Math.round((notes.reduce((a, b) => a + b, 0) / notes.length) * 100) / 100 : null
      }
    });
  } catch (e) {
    console.error('Diagnostic admin :', e.message);
    erreurServeur(res, 'GET /api/admin/diagnostic', e);
  }
});

// ══════════════ DOCUMENTS DES PRESTATAIRES ══════════════

// Déposer un document. Un dépôt du même type remplace le précédent : l'ancien
// passe en « expire », il n'est jamais supprimé.
app.post('/api/documents', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('type').eq('id', req.user.id).single();
    if (!user || !isProType(user.type)) return res.status(403).json({ error: 'Cette action est réservée aux comptes prestataires. Votre compte est un compte client.' });

    const type = String(req.body.type || '').trim();
    if (!TYPES_DOCUMENTS[type]) return res.status(400).json({ error: 'Type de document inconnu.' });

    // La face doit faire partie de celles attendues pour ce type : on ne veut
    // pas d'un « verso » sur une attestation qui n'en a pas.
    const facesAttendues = TYPES_DOCUMENTS[type].faces || ['unique'];
    const face = facesAttendues.indexOf(String(req.body.face || 'unique')) >= 0
      ? String(req.body.face || 'unique') : facesAttendues[0];

    const televerse = await televerserDocument(req.body.fichier, req.user.id, type + '/' + face);
    if (televerse.erreur) return res.status(400).json({ error: televerse.erreur });

    // Le précédent document de la MÊME FACE sort de la circulation. Déposer un
    // nouveau verso ne doit pas invalider le recto déjà validé.
    await supabase.from('documents_pro')
      .update({ statut: 'expire' })
      .eq('pro_id', req.user.id).eq('type', type).eq('face', face)
      .in('statut', ['en_attente', 'valide']);

    // La date d'expiration est calculée quand la durée de validité est connue
    // et que le prestataire a indiqué la date d'émission — sinon on laisse
    // l'administrateur la renseigner en lisant le document.
    let dateExpiration = req.body.date_expiration || null;
    const emission = req.body.date_emission || null;
    const regle = TYPES_DOCUMENTS[type];
    if (!dateExpiration && emission && regle.mois_validite) {
      const d = new Date(emission);
      if (!isNaN(d.getTime())) {
        d.setMonth(d.getMonth() + regle.mois_validite);
        dateExpiration = d.toISOString().slice(0, 10);
      }
    }

    const { data, error } = await supabase.from('documents_pro').insert({
      pro_id: req.user.id,
      type,
      statut: 'en_attente',
      chemin_fichier: televerse.chemin,
      nom_original: String(req.body.nom_original || '').slice(0, 200) || null,
      taille_octets: televerse.taille,
      type_mime: televerse.typeMime,
      face,
      // Mesure faite dans le navigateur avant l'envoi. Indicative : elle est
      // enregistrée, jamais opposée au prestataire.
      qualite: (req.body.qualite && typeof req.body.qualite === 'object') ? req.body.qualite : null,
      date_emission: emission,
      date_expiration: dateExpiration,
      reference: String(req.body.reference || '').slice(0, 100) || null
    }).select().single();

    if (error) return res.status(400).json({ error: traduireErreurSupabase(error.message) });

    console.log('📄 Document déposé — ' + regle.libelle +
      (face !== 'unique' ? ' (' + face + ')' : '') + ' — prestataire ' + req.user.id +
      (req.body.qualite && req.body.qualite.net === false ? ' — signalé peu net' : ''));
    res.status(201).json({ message: 'Document déposé, il sera vérifié rapidement.', document: { id: data.id, type, face, statut: data.statut } });
  } catch (e) {
    console.error('Dépôt document :', e.message);
    erreurServeur(res, 'POST /api/documents', e);
  }
});

// Ce que le prestataire voit de ses propres documents : l'état de chacun, et ce
// qu'il lui reste à fournir. Les documents expirés ne sont pas listés — il n'y
// peut rien, et les afficher brouillerait la lecture.
app.get('/api/documents', auth, async (req, res) => {
  try {
    const { data: docs } = await supabase.from('documents_pro')
      .select('id, type, face, statut, date_emission, date_expiration, reference, motif_refus, commentaire, created_at, verifie_le')
      .eq('pro_id', req.user.id).neq('statut', 'expire')
      .order('created_at', { ascending: false });

    // Indexé par type ET par face : un recto validé et un verso en attente
    // coexistent, et doivent s'afficher séparément.
    const parFace = {};
    (docs || []).forEach(d => {
      const cle = d.type + '|' + (d.face || 'unique');
      if (!parFace[cle]) parFace[cle] = d;
    });

    const etat = Object.keys(TYPES_DOCUMENTS).map(type => {
      const regle = TYPES_DOCUMENTS[type];
      const faces = (regle.faces || ['unique']).map(face => ({
        face,
        libelle_face: LIBELLES_FACE[face],
        document: parFace[type + '|' + face] || null
      }));
      return {
        type,
        libelle: regle.libelle,
        requis: regle.requis,
        faces,
        // Un document n'est complet que si TOUTES ses faces sont validées.
        complet: faces.every(f => f.document && f.document.statut === 'valide')
      };
    });

    res.json({ documents: etat });
  } catch (e) {
    erreurServeur(res, 'GET /api/documents', e);
  }
});

// ══════════════ DOCUMENTS — ADMINISTRATION ══════════════

// La file d'attente, ou le dossier complet d'un prestataire.
// Les plus anciens d'abord : aucun dossier ne doit rester oublié au fond.
// ═══════════════════════════════════════════════════════════════════════════
// LES DOSSIERS PRESTATAIRES — une ligne par personne, pas par fichier
//
// La liste à plat fonctionne avec trois prestataires. Avec mille, elle devient
// inutilisable : cinq documents par personne, dispersés par ordre d'arrivée,
// et il faut reconstituer mentalement qui a fourni quoi.
//
// Cette route renvoie des DOSSIERS. L'unité de travail devient « ce
// prestataire est-il en règle ? », qui est la vraie question — un document
// valide isolé ne sert à rien si les deux autres manquent.
//
// L'ordre est celui de l'utilité : les dossiers COMPLETS en attente d'abord.
// Ce sont ceux où une décision débloque immédiatement quelqu'un qui veut
// travailler. Les dossiers incomplets viennent ensuite : rien à décider tant
// que les pièces manquent.
// ═══════════════════════════════════════════════════════════════════════════
app.get('/api/admin/dossiers', adminAuth, async (req, res) => {
  try {
    const filtre = req.query.filtre || 'a_traiter';

    const { data: documents, error } = await supabase.from('documents_pro')
      .select('id, pro_id, type, face, statut, motif_refus, created_at, date_expiration')
      .order('created_at', { ascending: false })
      .limit(5000);
    if (error) {
      // « Lecture impossible » ne dit ni quelle table, ni quelle colonne. Nous
      // avons perdu deux échanges à chercher un nom de colonne que le message
      // aurait pu donner. L'administration est un écran réservé : le détail
      // technique y est utile, pas dangereux.
      console.error('Lecture des dossiers:', error);
      return res.status(500).json({
        error: 'Lecture impossible : ' + (error.message || 'cause inconnue'),
        details: error.details || null,
        indice: error.hint || null
      });
    }

    const proIds = [...new Set((documents || []).map(d => d.pro_id).filter(Boolean))];
    if (!proIds.length) return res.json({ dossiers: [], compteurs: { a_traiter: 0, complets: 0, incomplets: 0 } });

    const { data: pros } = await supabase.from('users')
      .select('id, prenom, nom, email, telephone, siret, siret_statut, siret_doublon, created_at, disponible')
      .in('id', proIds);
    const parId = {};
    (pros || []).forEach(p => { parId[p.id] = p; });

    // Les types exigés pour qu'un dossier soit complet. Ils viennent de la
    // même table que le reste : une seule source, pas deux listes à tenir.
    const typesRequis = Object.keys(TYPES_DOCUMENTS).filter(t => (TYPES_DOCUMENTS[t] || {}).requis !== false);

    const dossiers = proIds.map(id => {
      const pro = parId[id] || {};
      const siens = (documents || []).filter(d => d.pro_id === id);

      // La clé est le type ET LA FACE. Une pièce d'identité demande un recto et
      // un verso : les regrouper sous « identite » ferait passer pour complet
      // un dossier où le recto manque — et un prestataire serait validé sur la
      // moitié de sa pièce.
      const parType = {};
      siens.forEach(d => {
        const cle = d.type + '|' + (d.face || 'unique');
        // Le plus récent de chaque pièce fait foi : un prestataire qui redépose
        // après un refus ne doit pas rester bloqué par l'ancien fichier.
        if (!parType[cle] || new Date(d.created_at) > new Date(parType[cle].created_at)) {
          parType[cle] = d;
        }
      });

      // Chaque type exige ses faces. TYPES_DOCUMENTS les déclare déjà :
      // l'identité en demande deux, les autres une seule.
      const piecesRequises = [];
      typesRequis.forEach(t => {
        const faces = (TYPES_DOCUMENTS[t] || {}).faces || ['unique'];
        faces.forEach(f => piecesRequises.push({ type: t, face: f, cle: t + '|' + f }));
      });

      const manquants = piecesRequises
        .filter(p => !parType[p.cle])
        .map(p => (TYPES_DOCUMENTS[p.type] || {}).libelle || p.type);
      const enAttente = Object.values(parType).filter(d => d.statut === 'en_attente');
      const refuses = Object.values(parType).filter(d => d.statut === 'refuse');
      const valides = Object.values(parType).filter(d => d.statut === 'valide');

      // Un document expiré vaut un document absent : la RC Pro d'il y a deux
      // ans ne couvre pas l'intervention de demain.
      const maintenant = Date.now();
      const expires = Object.values(parType).filter(
        d => d.statut === 'valide' && d.date_expiration && new Date(d.date_expiration).getTime() < maintenant
      );

      const complet = manquants.length === 0 && !expires.length;

      return {
        pro_id: id,
        prenom: pro.prenom || '',
        nom: pro.nom || '',
        email: pro.email || '',
        telephone: pro.telephone || '',
        siret: pro.siret || null,
        siret_statut: pro.siret_statut || null,
        siret_doublon: !!pro.siret_doublon,
        inscrit_le: pro.created_at || null,
        disponible: !!pro.disponible,
        documents: siens.length,
        types_fournis: Object.keys(parType),
        manquants,
        nb_en_attente: enAttente.length,
        nb_refuses: refuses.length,
        nb_valides: valides.length,
        nb_expires: expires.length,
        complet,
        // Depuis quand le prestataire attend une décision. C'est ce qui doit
        // remonter en tête : quelqu'un qui patiente depuis six jours passe
        // avant celui qui a déposé ce matin.
        attend_depuis: enAttente.length
          ? Math.min(...enAttente.map(d => new Date(d.created_at).getTime()))
          : null
      };
    });

    const aTraiter = dossiers.filter(d => d.nb_en_attente > 0);
    const complets = aTraiter.filter(d => d.complet);
    const incomplets = aTraiter.filter(d => !d.complet);

    let liste;
    if (filtre === 'complets') liste = complets;
    else if (filtre === 'incomplets') liste = incomplets;
    else if (filtre === 'tous') liste = dossiers;
    else liste = aTraiter;   // par défaut : ce sur quoi il y a quelque chose à faire

    // Les complets d'abord, puis le plus ancien en attente. Une décision sur un
    // dossier complet libère un prestataire ; sur un incomplet, elle ne fait
    // qu'avancer d'un cran.
    liste.sort((a, b) => {
      if (a.complet !== b.complet) return a.complet ? -1 : 1;
      return (a.attend_depuis || Infinity) - (b.attend_depuis || Infinity);
    });

    res.json({
      dossiers: liste.slice(0, 200),
      compteurs: {
        a_traiter: aTraiter.length,
        complets: complets.length,
        incomplets: incomplets.length,
        total: dossiers.length
      }
    });
  } catch (e) {
    erreurServeur(res, 'GET /api/admin/dossiers', e);
  }
});

// Valider tous les documents en attente d'un prestataire, en une fois.
//
// Un administrateur qui a ouvert le dossier a regardé les cinq pièces. Lui
// demander cinq clics pour dire ce qu'il a déjà décidé une fois, c'est cinq
// occasions de se tromper de bouton.
//
// Le refus reste UNITAIRE : on refuse une pièce précise, avec un motif. Refuser
// un dossier entier ne dit pas au prestataire ce qu'il doit refaire.
app.patch('/api/admin/dossiers/:proId/valider', adminAuth, async (req, res) => {
  try {
    const { data: enAttente } = await supabase.from('documents_pro')
      .select('id, type')
      .eq('pro_id', req.params.proId)
      .eq('statut', 'en_attente');

    if (!enAttente || !enAttente.length) {
      return res.status(400).json({ error: 'Aucun document en attente pour ce prestataire.' });
    }

    const { error } = await supabase.from('documents_pro')
      .update({ statut: 'valide', motif_refus: null, verifie_le: new Date().toISOString() })
      .eq('pro_id', req.params.proId)
      .eq('statut', 'en_attente');
    if (error) return res.status(500).json({ error: 'Validation impossible.' });

    // Le prestataire est prévenu une seule fois, pas cinq.
    try {
      const { data: pro } = await supabase.from('users')
        .select('id, prenom, email').eq('id', req.params.proId).maybeSingle();
      if (pro) {
        envoyerNotificationPush(pro.id, {
          titre: 'Vos documents sont validés',
          corps: 'Votre dossier est complet. Vous pouvez recevoir des demandes.',
          url: '/#profil'
        }).catch(() => {});
      }
    } catch (e) { console.error('Notification validation dossier:', e.message); }

    res.json({ message: enAttente.length + ' document(s) validé(s).', valides: enAttente.length });
  } catch (e) {
    erreurServeur(res, 'PATCH /api/admin/dossiers/:proId/valider', e);
  }
});

app.get('/api/admin/documents', adminAuth, async (req, res) => {
  try {
    let requete = supabase.from('documents_pro')
      .select('*, pro:users!documents_pro_pro_id_fkey(id, prenom, nom, email, telephone, siret, siret_statut, siret_doublon, siret_donnees)');

    if (req.query.pro_id) {
      // Dossier d'un prestataire : historique compris, expirés inclus.
      requete = requete.eq('pro_id', req.query.pro_id).order('created_at', { ascending: false });
    } else {
      requete = requete.eq('statut', req.query.statut || 'en_attente')
        .order('created_at', { ascending: true }).limit(100);
    }

    const { data, error } = await requete;
    if (error) return res.status(500).json({ error: 'Lecture impossible.' });

    const enrichis = (data || []).map(d => ({
      ...d,
      type_libelle: (TYPES_DOCUMENTS[d.type] || {}).libelle || d.type,
      face_libelle: LIBELLES_FACE[d.face || 'unique'] || ''
    }));

    // Compteurs affichés en tête de file, pour savoir où l'on en est.
    const { count: enAttente } = await supabase.from('documents_pro')
      .select('id', { count: 'exact', head: true }).eq('statut', 'en_attente');

    res.json({ documents: enrichis, en_attente: enAttente || 0, motifs_refus: MOTIFS_REFUS });
  } catch (e) {
    erreurServeur(res, 'GET /api/admin/documents', e);
  }
});

// URL signée pour consulter un document. Cinq minutes, régénérée à chaque
// demande : aucune adresse permanente ne circule.
app.get('/api/admin/documents/:id/fichier', adminAuth, async (req, res) => {
  try {
    const { data: doc } = await supabase.from('documents_pro')
      .select('chemin_fichier, type_mime').eq('id', req.params.id).single();
    if (!doc) return res.status(404).json({ error: 'Document introuvable.' });

    const url = await signerDocument(doc.chemin_fichier);
    if (!url) return res.status(500).json({ error: 'Lien de consultation indisponible.' });
    res.json({ url, type_mime: doc.type_mime });
  } catch (e) {
    erreurServeur(res, 'GET /api/admin/documents/:id/fichier', e);
  }
});

// Valider ou refuser. Le motif est exigé pour un refus : sans lui, le
// prestataire renvoie le même document et deux jours sont perdus.
app.patch('/api/admin/documents/:id', adminAuth, async (req, res) => {
  try {
    const decision = String(req.body.decision || '').trim();
    if (decision !== 'valide' && decision !== 'refuse')
      return res.status(400).json({ error: 'Décision attendue : valide ou refuse.' });

    if (decision === 'refuse' && !MOTIFS_REFUS[String(req.body.motif || '')])
      return res.status(400).json({ error: 'Un motif de refus est requis.' });

    const misAJour = {
      statut: decision,
      verifie_par: 'admin',
      verifie_le: new Date().toISOString(),
      motif_refus: decision === 'refuse' ? req.body.motif : null,
      commentaire: String(req.body.commentaire || '').slice(0, 500) || null
    };
    // L'administrateur corrige au besoin les dates lues sur le document :
    // le prestataire les saisit de mémoire, lui les lit.
    if (req.body.date_emission !== undefined) misAJour.date_emission = req.body.date_emission || null;
    if (req.body.date_expiration !== undefined) misAJour.date_expiration = req.body.date_expiration || null;

    const { data, error } = await supabase.from('documents_pro')
      .update(misAJour).eq('id', req.params.id).select('*, pro:users!documents_pro_pro_id_fkey(email, prenom)').single();
    if (error || !data) return res.status(400).json({ error: 'Mise à jour impossible.' });

    // ═══════════════════════════════════════════════════════════════════
    // LE DOSSIER VIENT-IL DE DEVENIR COMPLET ?
    //
    // Le contrôle d'accès lit la base à chaque appel : dès la validation, le
    // prestataire PEUT voir les demandes. Mais son écran ne se rafraîchit
    // qu'au sondage suivant — jusqu'à soixante secondes — et s'il a fermé
    // l'application, jamais.
    //
    // Sans avertissement, il découvrirait son déblocage par hasard, en
    // rouvrant l'application un jour. On le prévient au moment exact où son
    // dossier devient complet, et une seule fois : c'est le passage de
    // « incomplet » à « complet » qui déclenche, pas chaque validation.
    // ═══════════════════════════════════════════════════════════════════
    if (decision === 'valide' && data.pro_id) {
      try {
        const apres = await prestataireEnRegle(data.pro_id);
        if (apres.enRegle) {
          const pro = data.pro || {};
          if (pro.email) {
            sendEmail('dossier_valide', pro.email, {
              compteId: data.pro_id,
              prenom: pro.prenom || ''
            }).catch(e => console.error('Email dossier validé:', e.message));
          }
          envoyerNotificationPush(data.pro_id, {
            titre: 'Votre dossier est validé',
            corps: 'Vous pouvez maintenant recevoir des demandes et envoyer vos devis.',
            url: '/#accueil'
          }).catch(() => {});
          console.log('🎉 Dossier complet — ' + data.pro_id + ' peut recevoir des demandes.');
        }
      } catch (e) {
        // Un avertissement qui échoue ne doit jamais empêcher la validation
        // elle-même : le prestataire est débloqué de toute façon.
        console.error('Avertissement dossier complet:', e.message);
      }
    }

    const libelle = (TYPES_DOCUMENTS[data.type] || {}).libelle || data.type;
    console.log((decision === 'valide' ? '✅' : '❌') + ' Document ' + decision + ' — ' + libelle +
      ' — ' + (data.pro && data.pro.email));

    res.json({ message: decision === 'valide' ? 'Document validé.' : 'Document refusé.' });
  } catch (e) {
    erreurServeur(res, 'PATCH /api/admin/documents/:id', e);
  }
});

// Les échéances à venir. La vue la plus importante après la file d'attente :
// elle permet d'anticiper au lieu de constater.
app.get('/api/admin/documents/expirations', adminAuth, async (req, res) => {
  try {
    const jours = Math.min(parseInt(req.query.jours, 10) || 60, 365);
    const limite = new Date();
    limite.setDate(limite.getDate() + jours);

    const { data } = await supabase.from('documents_pro')
      .select('id, type, date_expiration, pro:users!documents_pro_pro_id_fkey(prenom, nom, email)')
      .eq('statut', 'valide').not('date_expiration', 'is', null)
      .lte('date_expiration', limite.toISOString().slice(0, 10))
      .order('date_expiration', { ascending: true });

    res.json({
      documents: (data || []).map(d => ({
        ...d,
        type_libelle: (TYPES_DOCUMENTS[d.type] || {}).libelle || d.type,
        jours_restants: Math.ceil((new Date(d.date_expiration) - new Date()) / 86400000)
      }))
    });
  } catch (e) {
    erreurServeur(res, 'GET /api/admin/documents/expirations', e);
  }
});

// ══════════════ TARIFICATION (Vague 2) ══════════════

// Le pro consulte ses propres tarifs de base et prestations proposées
app.get('/api/societes/tarifs', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('type, tarifs_base, tarifs_unitaires, prestations_proposees').eq('id', req.user.id).single();
    if (!user || !isProType(user.type)) return res.status(403).json({ error: 'Cet écran est réservé aux comptes prestataires. Votre compte est un compte client.' });
    res.json({ tarifs: user.tarifs_base || {}, tarifs_unitaires: user.tarifs_unitaires || {}, prestations: user.prestations_proposees || [] });
  } catch (e) {
    erreurServeur(res, 'GET /api/societes/tarifs', e);
  }
});

// Le pro met à jour ses tarifs — pour les catégories structurées, un prix distinct par palier
// (ex: {citadine: 70, suv_4x4: 130, ...}) ; pour "autre", un prix unique.
app.patch('/api/societes/tarifs', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('type').eq('id', req.user.id).single();
    if (!user || !isProType(user.type)) return res.status(403).json({ error: 'Cet écran est réservé aux comptes prestataires. Votre compte est un compte client.' });

    const categoriesValides = Object.keys(PRESTATION_CONFIG);
    const prestationsRecues = Array.isArray(req.body.prestations) ? req.body.prestations : [];
    const prestationsPropres = prestationsRecues.filter(p => categoriesValides.includes(p));

    const tarifsRecus = req.body.tarifs || {};
    const tarifsUnitairesRecus = req.body.tarifs_unitaires || {};
    const tarifsPropres = {};
    const tarifsUnitairesPropres = {};

    for (const cat of categoriesValides) {
      const config = PRESTATION_CONFIG[cat];
      const cible = config.unite ? tarifsUnitairesRecus : tarifsRecus;
      const destination = config.unite ? tarifsUnitairesPropres : tarifsPropres;
      const valBrute = cible[cat];

      if (config.tiers) {
        // Catégorie structurée : on attend un objet { palier: prix, ... }
        if (valBrute === undefined || valBrute === null || typeof valBrute !== 'object') continue;
        const parPalier = {};
        for (const tier of config.tiers) {
          const val = valBrute[tier];
          if (val === undefined || val === null || val === '') continue;
          const num = parseFloat(val);
          if (isNaN(num) || num <= 0) return res.status(400).json({ error: 'Le tarif "' + (config.tierLabels[tier] || tier) + '" pour "' + cat + '" doit être un nombre positif.' });
          parPalier[tier] = num;
        }
        if (Object.keys(parPalier).length) destination[cat] = parPalier;
      } else {
        // Catégorie non structurée (ex: "autre") : un seul prix
        if (valBrute === undefined || valBrute === null || valBrute === '') continue;
        const num = parseFloat(valBrute);
        if (isNaN(num) || num <= 0) return res.status(400).json({ error: 'Le tarif pour "' + cat + '" doit être un nombre positif.' });
        destination[cat] = num;
      }
    }

    const { error } = await supabase.from('users').update({
      tarifs_base: tarifsPropres,
      tarifs_unitaires: tarifsUnitairesPropres,
      prestations_proposees: prestationsPropres
    }).eq('id', req.user.id);
    if (error) { console.error('Erreur Supabase, message technique complet:', error); return res.status(400).json({ error: traduireErreurSupabase(error.message) }); }
    res.json({ message: 'Tarifs mis à jour.', tarifs: tarifsPropres, tarifs_unitaires: tarifsUnitairesPropres, prestations: prestationsPropres });
  } catch (e) {
    erreurServeur(res, 'PATCH /api/societes/tarifs', e);
  }
});

// Le client obtient une estimation de prix avant/après avoir envoyé sa demande
// Volontairement accessible sans compte : ne renvoie que des moyennes de prix agrégées entre pros
// disponibles (jamais d'identité ni de donnée personnelle) — permet à un visiteur de voir une
// estimation avant de créer un compte, cohérent avec le principe de le laisser découvrir avant
// de lui demander un compte.
app.get('/api/tarifs/estimation', publicLimiter, async (req, res) => {
  try {
    const prestation = req.query.prestation;
    const etat = req.query.etat || 'propre';
    const taille = req.query.taille;
    const portee = req.query.portee;
    const matiere = req.query.matiere;
    const intervention = req.query.intervention;
    const typeBien = req.query.type_bien;
    const places = req.query.places;           // voiture (nombre de places, secondaire au type de véhicule)
    const forme = req.query.forme;             // canapé (droit/angle/canapé lit/chauffeuses, secondaire aux places)
    const typeBassin = req.query.type_bassin;  // piscine (enterrée/hors-sol/semi-enterrée/spa, secondaire)
    const quantite = req.query.quantite ? parseInt(req.query.quantite, 10) : null;

    const config = PRESTATION_CONFIG[prestation];
    if (!config) return res.status(400).json({ error: 'Prestation inconnue.' });

    const coefEtat = ETAT_COEF[etat] || 1.0;
    // La valeur de palier envoyée dépend de la dimension principale de cette catégorie
    const tierParams = { taille, portee, matiere, intervention, type_bien: typeBien };
    const tierValue = config.tierKey ? tierParams[config.tierKey] : null;

    if (config.unite) {
      if (!quantite || quantite <= 0) {
        return res.json({
          prestation, etat, quantite: null, prix_min: null, prix_max: null, prix_moyen: null,
          base_sur_donnees_reelles: false, nombre_pros_reference: 0,
          message: 'Indiquez une quantité pour obtenir une estimation.'
        });
      }
      const { data: prosUnit } = await supabase.from('users').select('tarifs_unitaires').eq('type', 'pro').eq('disponible', true)
      // Plafond de sécurité. Cette route est PUBLIQUE et appelée à chaque frappe
      // dans le formulaire d'estimation : elle lit les tarifs de tous les
      // prestataires disponibles pour en calculer une moyenne.
      //
      // Ce n'est pas de la pagination — une moyenne sur mille prestataires est
      // déjà représentative, et un millier de plus ne la déplacerait pas. C'est
      // une garde : si la table grossit, le serveur ne s'écroule pas.
      .limit(1000);
      const { prix: prixUnitaire, reel, nbPros } = prixPourPalier(config, prestation, tierValue, (prosUnit || []).map(p => p.tarifs_unitaires && p.tarifs_unitaires[prestation]));

      const coefMatiereUnite = (config.tierKey !== 'matiere' && config.coefMatiere && matiere && config.coefMatiere.hasOwnProperty(matiere)) ? config.coefMatiere[matiere] : 1.0;
      const coefTailleUnite = (config.tierKey !== 'taille' && config.coefTaille && taille && config.coefTaille.hasOwnProperty(taille)) ? config.coefTaille[taille] : 1.0;
      const surfaceEquivalente = surfaceEquivalentePonderee(quantite);
      const prixCalcule = Math.round(prixUnitaire * surfaceEquivalente * coefEtat * coefMatiereUnite * coefTailleUnite);
      const { prix: prixMoyen, plancher } = appliquerPlancher(prixCalcule);
      // La fourchette se resserre quand le plancher joue : le prix n'est plus le
      // produit d'un calcul, c'est un minimum. Annoncer 60 – 80 € autour d'un
      // plancher de 70 € laisserait croire qu'on peut descendre en dessous.
      const prixMin = plancher ? prixMoyen : Math.round(prixMoyen * 0.85);
      const prixMax = Math.round(prixMoyen * 1.15);

      return res.json({
        prestation, etat, quantite, taille: taille || null, matiere: matiere || null, type_bien: typeBien || null,
        prix_unitaire: Math.round(prixUnitaire * 100) / 100,
        reduction_surface_pourcent: quantite > 0 ? Math.round((1 - surfaceEquivalente / quantite) * 100) : 0,
        prix_min: prixMin, prix_max: prixMax, prix_moyen: prixMoyen,
        minimum_applique: plancher, minimum_intervention: MINIMUM_INTERVENTION,
        base_sur_donnees_reelles: reel, nombre_pros_reference: nbPros
      });
    }

    // Catégories à prix de référence par palier + coefficients secondaires (matière, portée, taille, état)
    let base, reel, nbPros;
    if (config.tierKey) {
      const { data: pros } = await supabase.from('users').select('tarifs_base').eq('type', 'pro').eq('disponible', true);
      const resultat = prixPourPalier(config, prestation, tierValue, (pros || []).map(p => p.tarifs_base && p.tarifs_base[prestation]));
      base = resultat.prix; reel = resultat.reel; nbPros = resultat.nbPros;
    } else {
      const { data: pros } = await supabase.from('users').select('tarifs_base').eq('type', 'pro').eq('disponible', true);
      const prixDeclares = (pros || []).map(p => p.tarifs_base && p.tarifs_base[prestation]).filter(v => typeof v === 'number' && v > 0);
      base = prixDeclares.length ? prixDeclares.reduce((a, b) => a + b, 0) / prixDeclares.length : config.prixReferenceDefaut;
      reel = prixDeclares.length > 0; nbPros = prixDeclares.length;
    }

    // Coefficients secondaires : appliqués seulement s'ils ne sont pas déjà la dimension principale de cette catégorie
    const coefTaille = (config.tierKey !== 'taille' && config.coefTaille && taille && config.coefTaille.hasOwnProperty(taille)) ? config.coefTaille[taille] : 1.0;
    const coefMatiere = (config.tierKey !== 'matiere' && config.coefMatiere && matiere && config.coefMatiere.hasOwnProperty(matiere)) ? config.coefMatiere[matiere] : 1.0;
    const coefPortee = (config.tierKey !== 'portee' && config.coefPortee && portee && config.coefPortee.hasOwnProperty(portee)) ? config.coefPortee[portee] : 1.0;
    const coefIntervention = (config.tierKey !== 'intervention' && config.coefIntervention && intervention && config.coefIntervention.hasOwnProperty(intervention)) ? config.coefIntervention[intervention] : 1.0;
    const coefPlaces = (config.coefPlaces && places && config.coefPlaces.hasOwnProperty(places)) ? config.coefPlaces[places] : 1.0;
    const coefForme = (config.coefForme && forme && config.coefForme.hasOwnProperty(forme)) ? config.coefForme[forme] : 1.0;
    const coefTypeBassin = (config.coefTypeBassin && typeBassin && config.coefTypeBassin.hasOwnProperty(typeBassin)) ? config.coefTypeBassin[typeBassin] : 1.0;
    const coef = coefEtat * coefTaille * coefMatiere * coefPortee * coefIntervention * coefPlaces * coefForme * coefTypeBassin;

    const prixCalcule = Math.round(base * coef);
    const { prix: prixMoyen, plancher } = appliquerPlancher(prixCalcule);
    const prixMin = plancher ? prixMoyen : Math.round(prixMoyen * 0.85);
    const prixMax = Math.round(prixMoyen * 1.15);

    res.json({
      prestation, etat, taille: taille || null, matiere: matiere || null, portee: portee || null, intervention: intervention || null,
      prix_min: prixMin, prix_max: prixMax, prix_moyen: prixMoyen,
      minimum_applique: plancher, minimum_intervention: MINIMUM_INTERVENTION,
      base_sur_donnees_reelles: reel,
      nombre_pros_reference: nbPros
    });
  } catch (e) {
    erreurServeur(res, 'GET /api/tarifs/estimation', e);
  }
});

// ══════════════ ADMINISTRATION ══════════════
// Espace séparé et sécurisé, avec sa propre authentification (voir adminAuth ci-dessus) — ne
// touche jamais aux comptes client/pro, ni à leurs rôles ou permissions.

// Connexion admin — un seul mot de passe partagé (variable d'environnement ADMIN_PASSWORD),
// volontairement simple pour un usage à une seule personne à ce stade. Le token émis est signé
// avec une clé dérivée mais distincte de celle des comptes utilisateurs.
app.post('/api/admin/login', authLimiter, async (req, res) => {
  const { password } = req.body;
  if (!process.env.ADMIN_PASSWORD && !process.env.ADMIN_PASSWORD_HASH)
    return res.status(500).json({ error: 'Accès admin non configuré côté serveur.' });
  if (!motDePasseAdminValide(password)) {
    // Trace horodatée : sans elle, une tentative d'intrusion ne laissait aucune marque.
    console.warn('⚠️  Tentative de connexion admin refusée — ' + new Date().toISOString() + ' — IP ' + (req.ip || 'inconnue'));
    return res.status(401).json({ error: 'Mot de passe incorrect.' });
  }
  console.log('🔑 Connexion admin — ' + new Date().toISOString() + ' — IP ' + (req.ip || 'inconnue'));
  const token = jwt.sign({ admin: true }, SECRET_ADMIN, { expiresIn: '12h' });
  res.json({ token });
});

// Vue d'ensemble : les chiffres essentiels pour superviser l'activité en un coup d'œil.
app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const { count: nbClients } = await supabase.from('users').select('id', { count: 'exact', head: true }).eq('type', 'client');
    const { count: nbEntreprises } = await supabase.from('users').select('id', { count: 'exact', head: true }).eq('type', 'entreprise');
    const { count: nbPros } = await supabase.from('users').select('id', { count: 'exact', head: true }).in('type', ['pro', 'societe', 'professionnel']);
    const { count: nbDemandesActives } = await supabase.from('demandes').select('id', { count: 'exact', head: true }).in('statut', ['en_attente', 'devis_recus', 'acceptee', 'en_cours']);
    const { count: nbSignalementsOuverts } = await supabase.from('signalements').select('id', { count: 'exact', head: true }).eq('statut', 'nouveau');
    const { data: paiementsLiberes } = await supabase.from('paiements').select('montant_ttc, commission').in('statut', ['libere', 'paye']);
    const revenuTotal = (paiementsLiberes || []).reduce((s, p) => s + parseFloat(p.montant_ttc || 0), 0);
    const commissionTotale = (paiementsLiberes || []).reduce((s, p) => s + parseFloat(p.commission || 0), 0);

    res.json({
      nb_clients: nbClients || 0,
      nb_entreprises: nbEntreprises || 0,
      nb_pros: nbPros || 0,
      nb_demandes_actives: nbDemandesActives || 0,
      nb_signalements_ouverts: nbSignalementsOuverts || 0,
      revenu_total: Math.round(revenuTotal * 100) / 100,
      commission_totale: Math.round(commissionTotale * 100) / 100
    });
  } catch (e) {
    erreurServeur(res, 'GET /api/admin/stats', e);
  }
});

// Liste des signalements, du plus récent au plus ancien, avec les infos essentielles pour traiter
// chaque cas sans avoir à ouvrir Supabase manuellement.
app.get('/api/admin/signalements', adminAuth, async (req, res) => {
  try {
    const { data } = await supabase.from('signalements').select('*').order('created_at', { ascending: false }).limit(200);
    const signalements = data || [];
    const idsUtilisateurs = [...new Set(signalements.flatMap(s => [s.reporter_id, s.signale_id].filter(Boolean)))];
    const { data: usersInfo } = idsUtilisateurs.length
      ? await supabase.from('users').select('id, prenom, nom, email').in('id', idsUtilisateurs)
      : { data: [] };
    const usersMap = Object.fromEntries((usersInfo || []).map(u => [u.id, u]));
    res.json(signalements.map(s => ({
      ...s,
      rapporteur: usersMap[s.reporter_id] || null,
      signale: usersMap[s.signale_id] || null
    })));
  } catch (e) {
    erreurServeur(res, 'GET /api/admin/signalements', e);
  }
});

// Marque un signalement comme traité — simple bascule de statut, l'essentiel pour ne plus le voir
// remonter dans la liste des cas encore ouverts.
app.patch('/api/admin/signalements/:id', adminAuth, async (req, res) => {
  try {
    // ── CE STATUT COMMANDE UN PAIEMENT ──────────────────────────────────
    // Depuis la clôture automatique, un signalement ouvert SUSPEND le
    // versement au prestataire. Le refermer ici, c'est autoriser le paiement.
    //
    // Trois valeurs, pour que la décision soit lisible dans six mois :
    //   nouveau  le litige est ouvert, le paiement attend
    //   traite   vous avez tranché, le paiement peut partir
    //   rejete   le signalement n'était pas fondé, le paiement peut partir
    //
    // Un remboursement éventuel se fait dans Stripe : l'application ne décide
    // pas de rendre l'argent, elle décide seulement de ne pas le bloquer.
    const { statut } = req.body;
    if (!['nouveau', 'traite', 'rejete'].includes(statut)) {
      return res.status(400).json({ error: 'Statut invalide.' });
    }
    await supabase.from('signalements').update({ statut }).eq('id', req.params.id);

    // La clôture automatique ne repasse qu'à la prochaine lecture de liste.
    // On la déclenche tout de suite : un prestataire dont le litige vient
    // d'être clos ne doit pas attendre qu'un autre utilisateur ouvre
    // l'application pour être payé.
    if (statut !== 'nouveau' && typeof cloturerPrestationsOubliees === 'function') {
      cloturerPrestationsOubliees().catch(e => console.error('Clôture après arbitrage:', e.message));
    }

    res.json({ message: 'Signalement mis à jour.' });
  } catch (e) {
    erreurServeur(res, 'PATCH /api/admin/signalements/:id', e);
  }
});

// Liste des utilisateurs, avec recherche simple par email/nom — pour retrouver rapidement un
// compte à superviser sans avoir à ouvrir Supabase.
app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const recherche = (req.query.q || '').trim();
    // Le téléphone manquait. C'est pourtant l'information la plus utile de cet
    // écran : quand un dossier coince, un appel règle en trente secondes ce que
    // trois échanges d'emails n'ont pas réglé.
    let requete = supabase.from('users').select('id, prenom, nom, email, telephone, type, disponible, compte_supprime, created_at, note_moyenne, taux_fiabilite, siret, siret_statut, siret_doublon').order('created_at', { ascending: false }).limit(100);
    if (recherche) requete = requete.or(`email.ilike.%${recherche}%,prenom.ilike.%${recherche}%,nom.ilike.%${recherche}%`);
    const { data } = await requete;
    res.json(data || []);
  } catch (e) {
    erreurServeur(res, 'GET /api/admin/users', e);
  }
});

// Suspend ou réactive un compte pro (bascule sa disponibilité à false, comme le fait déjà le
// système anti-fraude automatique en cas d'annulations répétées) — n'affecte jamais les comptes
// client, qui n'ont pas cette notion de disponibilité.
app.patch('/api/admin/users/:id/disponibilite', adminAuth, async (req, res) => {
  try {
    const { disponible } = req.body;
    await supabase.from('users').update({ disponible: !!disponible }).eq('id', req.params.id);
    res.json({ message: disponible ? 'Compte réactivé.' : 'Compte suspendu.' });
  } catch (e) {
    erreurServeur(res, 'PATCH /api/admin/users/:id/disponibilite', e);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// SERVIR L'APPLICATION DEPUIS CE SERVEUR
//
// Jusqu'ici, index.html était hébergé sur Netlify pendant que l'API tournait
// ici. Deux déploiements, donc deux occasions d'oublier — et le site public
// est resté figé au 10 août pendant NEUF JOURS sans que personne le voie.
//
// Un seul déploiement met désormais tout à jour : le décalage devient
// impossible.
//
// L'ORDRE COMPTE, DEUX FOIS.
//
// APRÈS les routes d'API : placé avant, express.static intercepterait des
// chemins « /api/… » et rendrait ces routes inaccessibles.
//
// AVANT le 404 générique : Express traite les intergiciels dans l'ordre de
// déclaration. Le « Route introuvable » posé plus bas répondait à la racine du
// site avant que les fichiers n'aient une chance d'être servis — la page
// d'accueil renvoyait donc une erreur JSON. C'est ce qui vient d'arriver.
const chemin = require('path');

// ═══════════════════════════════════════════════════════════════════════════
// SEULS LES FICHIERS PUBLICS SONT SERVIS
//
// `express.static(__dirname)` exposait la RACINE DU PROJET. N'importe qui
// pouvait télécharger :
//
//     /server.js        toute la logique métier, les noms de tables
//     /email.js         les gabarits et la configuration SendGrid
//     /package.json     les dépendances et leurs versions
//     /.env.example     les noms des variables d'environnement
//
// Les clés elles-mêmes vivent dans les variables Railway, pas dans un fichier.
// Mais le code d'un serveur n'a aucune raison d'être téléchargeable : il
// révèle la structure de la base, les contrôles en place — et ceux qui
// manquent.
//
// LA LISTE BLANCHE PLUTÔT QUE LA LISTE NOIRE
//
// Interdire server.js et email.js aurait laissé passer le prochain fichier
// ajouté. On énumère ce qui DOIT être servi, et rien d'autre.
const FICHIERS_PUBLICS = new Set([
  '/index.html', '/sw.js', '/manifest.json', '/manifest.webmanifest',
  '/favicon.ico', '/apple-touch-icon.png', '/robots.txt'
]);

function estPublic(url) {
  let propre;
  try { propre = decodeURIComponent(String(url || '').split('?')[0]); }
  catch (e) { return false; }          // adresse mal encodée : on refuse
  if (FICHIERS_PUBLICS.has(propre)) return true;
  // Les ressources d'un dossier dédié — images, polices — restent servies.
  return /^\/(assets|icons|images|img|fonts)\//.test(propre);
}

app.use((req, res, suivant) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') return suivant();
  if (req.path === '/' || estPublic(req.path)) return suivant();

  // Un fichier non public ne doit pas répondre « 404 » : cela confirmerait son
  // existence. On rend l'application, comme pour toute adresse inconnue.
  //
  // TOUT CE QUI N'EST PAS EXPLICITEMENT PUBLIC EST REFUSÉ.
  //
  // J'avais d'abord énuméré les extensions à bloquer. Deux fichiers passaient
  // à travers : « .env.example » — dont l'extension est « .example » — et
  // « test.html », qui contenait des identifiants en clair.
  //
  // Une liste d'interdits laisse toujours passer ce qu'on n'a pas prévu. Seule
  // la liste blanche tient dans le temps.
  return res.sendFile(chemin.join(__dirname, 'index.html'));
});

app.use(express.static(__dirname, {
  setHeaders: (res, fichier) => {
    // index.html porte le numéro de version, et sw.js pilote le cache : les
    // laisser en cache quelques heures suffit à faire croire qu'un
    // déploiement n'a pas pris. C'est exactement ce qui vient d'arriver.
    if (fichier.endsWith('index.html') || fichier.endsWith('sw.js')) {
      res.set('Cache-Control', 'no-cache, must-revalidate');
    }
  }
}));

// Toute adresse inconnue rend l'application, qui gère ses propres ancres.
// Les chemins d'API absents répondent en revanche 404 : sinon un appel mal
// orthographié recevrait du HTML et échouerait de façon incompréhensible.
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/webhooks/')) {
    return res.status(404).json({ error: 'Route inconnue.' });
  }
  res.sendFile(chemin.join(__dirname, 'index.html'));
});


// Filet de sécurité : toute erreur non interceptée par un try/catch de route
// renvoie une réponse JSON propre plutôt qu'une page d'erreur HTML illisible par le frontend.
app.use((err, req, res, next) => {
  console.error('Erreur non interceptée :', err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Erreur serveur inattendue.' });
});

// Route 404 générique pour les chemins inconnus (renvoie du JSON, pas du HTML)
app.use((req, res) => {
  res.status(404).json({ error: 'Route introuvable.' });
});

// Remonte à Sentry toute erreur non gérée survenue dans une route — doit être ajouté après toutes
// les routes, mais avant le démarrage du serveur. Protégé de la même façon que l'initialisation :
// si Sentry n'est pas configuré, cette ligne ne fait tout simplement rien.
if (process.env.SENTRY_DSN && Sentry.setupExpressErrorHandler) {
  Sentry.setupExpressErrorHandler(app);
}


// ─────────────────────────────────────────────────────────────────────────
// Balayage périodique des demandes expirées
//
// Jusqu'ici l'expiration n'était déclenchée que par la lecture, sur le lot que
// l'appelant venait de charger. Trois conséquences : une requête GET modifiait
// la base, le périmètre dépendait de qui regardait, et une demande que personne
// ne consultait ne expirait jamais. Ce balayage couvre toute la table,
// indépendamment du trafic.
//
// Les relances à 24 h et 48 h sont désormais traitées par
// relancerDemandesSansDevis(), sur son propre minuteur.
// ─────────────────────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════
// OUVRIR LES DEMANDES DONT L'EXCLUSIVITÉ EST ÉCHUE
//
// Le filtre de lecture suffit techniquement : passé la date, les autres
// prestataires voient la demande. Mais personne n'est PRÉVENU — ni le client,
// qui croit toujours attendre son favori, ni les prestataires de la zone, qui
// ne consultent pas la liste toutes les heures.
//
// Ce balayage efface le favori désigné et notifie. C'est ce qui transforme un
// changement de visibilité en chance réelle de recevoir un devis.
// ═══════════════════════════════════════════════════════════════════════════
async function ouvrirExclusivitesEchues() {
  try {
    const { data, error } = await supabase.from('demandes')
      .select('id, client_id, prestation, pro_prefere_id, exclusivite_jusqu_a')
      .in('statut', ['en_attente', 'devis_recus'])
      .not('pro_prefere_id', 'is', null)
      .not('exclusivite_jusqu_a', 'is', null)
      .lt('exclusivite_jusqu_a', new Date().toISOString())
      .limit(100);

    if (error) {
      // On remonte l'erreur au lieu de la taire : une lecture qui échoue en
      // silence, c'est le défaut qui a bloqué la clôture pendant des jours.
      console.error('Ouverture des exclusivités — lecture :', error.message);
      return 0;
    }
    if (!data || !data.length) return 0;

    for (const d of data) {
      // On efface le favori : la demande redevient ordinaire. Le favori la
      // voit toujours — il n'est pas écarté, il cesse d'être seul.
      const { error: majErr } = await supabase.from('demandes')
        .update({ pro_prefere_id: null, exclusivite_jusqu_a: null })
        .eq('id', d.id)
        .not('pro_prefere_id', 'is', null);   // évite d'écraser une réouverture manuelle

      if (majErr) {
        console.error('Ouverture ' + d.id + ' :', majErr.message);
        continue;
      }

      envoyerNotificationPush(d.client_id, {
        titre: 'Votre demande est ouverte à tous',
        corps: 'Sans réponse de votre prestataire favori, elle est maintenant visible par les professionnels de votre zone.',
        url: '/#accueil'
      }).catch(() => {});
    }
    return data.length;
  } catch (e) {
    console.error('Ouverture des exclusivités :', e.message);
    return 0;
  }
}

async function balayerDemandesExpirees() {
  try {
    const { data, error } = await supabase
      .from('demandes')
      .select('id, statut, creneau')
      .in('statut', ['en_attente', 'devis_recus', 'acceptee']);
    if (error) return console.error('Balayage expiration — lecture:', error.message);
    if (!data || !data.length) return;

    const avant = data.filter(d => d.statut !== 'expiree').length;
    await expirerDemandesEnRetard(data);
    const expirees = data.filter(d => d.statut === 'expiree').length;
    if (expirees) console.log('🧹 Balayage : ' + expirees + ' demande(s) expirée(s) sur ' + avant + ' ouverte(s).');
  } catch (e) {
    console.error('Balayage expiration:', e.message);
  }
}

// Toutes les 15 minutes, et une première fois 30 secondes après le démarrage —
// le temps que la connexion à la base soit établie.
setInterval(balayerDemandesExpirees, 15 * 60 * 1000);
setTimeout(balayerDemandesExpirees, 30 * 1000);

// Les relances suivent le même rythme, décalées de 30 secondes pour ne pas
// solliciter la base en même temps que le balayage des expirations.
setInterval(relancerDemandesSansDevis, 15 * 60 * 1000);
setTimeout(relancerDemandesSansDevis, 60 * 1000);

// ═══════════════════════════════════════════════════════════════════════════
// LA CLÔTURE AUTOMATIQUE, ENFIN PLANIFIÉE
//
// Elle existait, elle fonctionnait, et elle ne tournait jamais.
//
// Son seul déclencheur était la CRÉATION d'une demande — un événement qui
// survient une fois tous les quelques jours. Trois prestations sont donc
// restées « en cours » pendant 307, 262 et 222 heures, sans le moindre litige,
// avec l'argent du client bloqué chez Stripe et le prestataire impayé.
//
// Les deux autres balayages étaient bien planifiés. Celui-ci avait été
// raccroché à une route, et personne ne s'en est aperçu tant qu'aucune
// prestation n'avait dépassé 48 heures.
//
// Même rythme que les autres, décalé de 30 secondes de plus pour ne pas
// solliciter la base en même temps.
// ═══════════════════════════════════════════════════════════════════════════
// Le dernier passage de la clôture, exposé à l'administration.
//
// Sans cette trace, impossible de distinguer trois situations qui se
// ressemblent de l'extérieur : le serveur n'est pas déployé, la minuterie ne
// tourne pas, ou elle tourne et ne trouve rien à faire. On a perdu deux
// échanges là-dessus.
let CLOTURE_DERNIER_PASSAGE = null;
let CLOTURE_DERNIER_RESULTAT = 'jamais exécutée';

async function balayerPrestationsAValider() {
  CLOTURE_DERNIER_PASSAGE = new Date().toISOString();
  try {
    // L'ouverture des exclusivités échues suit le même rythme : quinze
    // minutes de retard sur une demande de trois jours ne changent rien, et
    // cela évite une quatrième minuterie.
    const ouvertes = await ouvrirExclusivitesEchues();
    if (ouvertes) console.log('🔓 ' + ouvertes + ' demande(s) ouverte(s) à tous.');

    // Le rappel d'arrivée suit le même rythme. Quinze minutes de battement sur
    // une fenêtre de trente conviennent : chaque prestation est vue au moins
    // une fois dans sa fenêtre.
    const rappels = await rappelerDeclarationArrivee();
    if (rappels) console.log('🔔 ' + rappels + ' rappel(s) d\'arrivée envoyé(s).');

    const virements = await reprendreVirementsEchoues();
    if (virements) console.log('💸 ' + virements + ' virement(s) repris.');

    const liberes = await traiterEcheancesPaiement();
    if (liberes) console.log('⏱ ' + liberes + ' devis libéré(s) faute de paiement.');
    const closes = await cloturerPrestationsOubliees();
    await avertirValidationProche();
    CLOTURE_DERNIER_RESULTAT = (typeof closes === 'number')
      ? closes + ' prestation(s) clôturée(s)'
      : 'passage sans erreur';
    console.log('⏱️  Clôture automatique : ' + CLOTURE_DERNIER_RESULTAT);
  } catch (e) {
    CLOTURE_DERNIER_RESULTAT = 'erreur : ' + e.message;
    console.error('Balayage clôture automatique:', e.message);
  }
}
setInterval(balayerPrestationsAValider, 15 * 60 * 1000);
setTimeout(balayerPrestationsAValider, 90 * 1000);

const PORT = process.env.PORT || 3000;
// ── FILETS DE SÉCURITÉ DU PROCESSUS ─────────────────────────────────────────
// Express 4 n'attrape PAS les rejets d'une route asynchrone : une promesse
// rejetée dans un `async (req, res) => {}` ne passe jamais par le gestionnaire
// d'erreur. Et depuis Node 15, un rejet non géré TERMINE le processus.
//
// Neuf routes de ce serveur sont asynchrones sans try/catch. Si Supabase ne
// répond pas sur l'une d'elles, le serveur s'arrête — et tous les utilisateurs
// en cours perdent leur session, pas seulement celui qui a déclenché l'appel.
//
// Railway redémarre, mais un redémarrage prend plusieurs secondes et se
// reproduit à chaque occurrence. On journalise et on continue de servir.
process.on('unhandledRejection', function(raison) {
  console.error('⚠️  Promesse rejetée sans gestionnaire :', raison);
  if (typeof Sentry !== 'undefined' && Sentry.captureException) {
    try { Sentry.captureException(raison); } catch (e) {}
  }
});

// Une exception synchrone non attrapée laisse le processus dans un état
// incertain : on journalise, puis on s'arrête proprement plutôt que de servir
// des réponses imprévisibles. Railway redémarrera.
// Déclaré ICI, avant le gestionnaire d'exception qui doit fermer le serveur.
// Plus bas, `typeof serveurHttp` aurait levé une ReferenceError : contrairement
// à `var`, un `let` non encore initialisé est en « zone morte temporelle », et
// même `typeof` y échoue.
//
// Le gestionnaire d'erreur aurait donc planté à son tour — en pleine gestion
// d'une erreur.
let serveurHttp = null;

process.on('uncaughtException', function(err) {
  console.error('🔴 Exception non attrapée :', err);
  if (typeof Sentry !== 'undefined' && Sentry.captureException) {
    try { Sentry.captureException(err); } catch (e) {}
  }
  // ── UNE SECONDE ÉVALUATION NE DOIT PAS TUER LA PREMIÈRE ───────────────
  // `server.js` est évalué deux fois dans le même processus — deux chemins
  // différents vers le même fichier produisent deux entrées de cache Node.
  //
  // La seconde tentait d'ouvrir un port déjà pris, et ce gestionnaire tuait
  // TOUT LE PROCESSUS — y compris le serveur de la première évaluation, qui
  // fonctionnait parfaitement.
  //
  // J'avais d'abord posé un verrou qui interrompait la seconde évaluation par
  // un `return`. Erreur : ce return coupait AVANT `require('./email')`, et la
  // copie ainsi tronquée n'avait plus de `sendEmail`. Chaque validation de
  // prestation échouait sur « sendEmail is not a function ».
  //
  // On laisse donc la seconde évaluation se dérouler ENTIÈREMENT — toutes les
  // fonctions sont définies — et on ignore seulement son échec d'ouverture de
  // port, qui est sans conséquence : la première écoute déjà.
  if (err && err.code === 'EADDRINUSE') {
    console.warn('⚠️ Port déjà ouvert par une première évaluation de server.js — '
      + 'ce second démarrage est ignoré, le service continue de fonctionner.');
    return;
  }

  // ── LE PORT DOIT ÊTRE LIBÉRÉ AVANT DE SORTIR ──────────────────────────
  // On attendait une seconde avant de quitter, pour laisser aux journaux le
  // temps de partir. Mais pendant cette seconde, le processus TENAIT ENCORE
  // le port 3000.
  //
  // Railway relançait immédiatement, le nouveau processus trouvait le port
  // occupé par l'ancien qui agonisait, et plantait à son tour. La boucle
  // tournait toutes les deux secondes — le service n'a jamais pu servir une
  // seule requête.
  //
  // Fermer d'abord, sortir ensuite : le port est rendu en quelques
  // millisecondes, et le processus suivant le trouve libre.
  try {
    if (typeof serveurHttp !== 'undefined' && serveurHttp) serveurHttp.close();
  } catch (e) { /* déjà fermé, ou jamais ouvert */ }

  setTimeout(function() { process.exit(1); }, 1000);
});

// ═══════════════════════════════════════════════════════════════════════════
// LE PORT PEUT ÊTRE ENCORE OCCUPÉ AU DÉMARRAGE
//
// Trois déploiements en trente-six secondes se sont chevauchés : le processus
// précédent tenait encore le port 3000 quand le nouveau a voulu l'ouvrir.
//
// L'échec remontait dans `uncaughtException`, qui attend une seconde avant de
// sortir — juste le temps que Railway relance et retrouve le port occupé. Le
// service tournait en boucle, et personne ne pouvait se connecter.
//
// La cause est connue : une dépendance circulaire entre server.js et email.js
// fait évaluer ce fichier DEUX FOIS dans le même processus. La seconde
// évaluation trouve le port ouvert par la première.
//
// Il ne faut ni réessayer — aucune tentative n'aboutira, la première écoute
// pour de bon — ni mourir, ce qui tuerait le serveur qui fonctionne.

function demarrerServeur() {
  serveurHttp = app.listen(PORT, function() {
    console.log('✨ Gleam API démarrée sur le port ' + PORT);
    console.log('   Environnement : ' + (process.env.NODE_ENV || 'development'));
  });

  serveurHttp.on('error', function(err) {
    if (err.code !== 'EADDRINUSE') {
      console.error('🔴 Impossible d\'ouvrir le port ' + PORT + ' :', err.message);
      process.exit(1);
    }
    // ── NE PAS RÉESSAYER, NE PAS MOURIR ─────────────────────────────────
    // Le port est occupé par la PREMIÈRE évaluation de ce même fichier, dans
    // ce même processus. Elle écoute déjà, et elle écoutera toujours : aucune
    // tentative ne réussira jamais.
    //
    // Réessayer six fois puis appeler process.exit(1) revenait à tuer le
    // serveur qui fonctionne, une minute après son démarrage. Les journaux le
    // montraient : « tentative 1/6 », « 2/6 »… puis l'arrêt.
    //
    // On constate, on le dit une fois, et on laisse tourner.
    console.warn('⚠️ Port ' + PORT + ' déjà ouvert par une première évaluation '
      + 'de server.js — ce second démarrage est ignoré. Le service fonctionne.');
  });
}

demarrerServeur();

// Railway envoie SIGTERM avant de couper le conteneur. Sans arrêt propre, les
// requêtes en cours sont interrompues net — y compris un paiement au milieu de
// sa confirmation.
process.on('SIGTERM', function() {
  console.log('SIGTERM reçu — arrêt en cours, les requêtes en cours sont servies.');
  // `serveurHttp` peut être null si SIGTERM arrive pendant une tentative de
  // réouverture du port : le service n'écoute alors rien, il n'y a rien à
  // fermer, et sortir tout de suite est le comportement juste.
  if (!serveurHttp) {
    console.log('Aucun serveur à fermer — arrêt immédiat.');
    process.exit(0);
    return;
  }
  serveurHttp.close(function() {
    console.log('Serveur arrêté proprement.');
    process.exit(0);
  });
  // Si une requête traîne au-delà de dix secondes, on n'attend pas davantage.
  setTimeout(function() { process.exit(0); }, 10000);
});
// END FINAL
