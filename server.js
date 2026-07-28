require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const jwt = require('jsonwebtoken');
const { sendEmail } = require('./email');

const app = express();
app.set('trust proxy', 1);

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

app.use(helmet());
app.use(cors());
app.options('*', cors());

app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    return res.status(400).send('Webhook Error: ' + e.message);
  }
  if (event.type === 'payment_intent.succeeded') {
    await supabase.from('paiements').update({ statut: 'bloque' }).eq('stripe_payment_intent_id', event.data.object.id);
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
    return res.status(400).json({ error: 'Requête invalide.' });
  }
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Requête invalide.' });
  }
  next(err);
});

const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 900, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });
app.use('/api/', globalLimiter);

const auth = async (req, res, next) => {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Non autorisé' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Token invalide' });
  }
};

const isProType = (t) => t === 'pro' || t === 'societe' || t === 'professionnel';

// Vérifie qu'une date (et éventuellement une heure) de créneau n'est pas dans le passé.
// Retourne un message d'erreur (string) si invalide, ou null si tout va bien.
function validerCreneauFutur(date, time) {
  if (!date) return null;
  const dateDemandee = new Date(date + 'T00:00:00');
  if (isNaN(dateDemandee.getTime())) return 'Date invalide.';
  const aujourdhui = new Date();
  aujourdhui.setHours(0, 0, 0, 0);
  if (dateDemandee < aujourdhui) return 'La date choisie ne peut pas être dans le passé.';
  if (dateDemandee.getTime() === aujourdhui.getTime() && time) {
    const match = /(\d{1,2})h(\d{2})/.exec(time);
    if (match) {
      const heureChoisie = new Date();
      heureChoisie.setHours(+match[1], +match[2], 0, 0);
      if (heureChoisie < new Date()) return 'Cette heure est déjà passée aujourd\'hui. Choisissez un autre créneau.';
    }
  }
  return null;
}

// ══════════════ TARIFICATION (Vague 2/3) — calibrée sur des prix de marché réels ══════════════
// Coefficient d'état, universel à toutes les prestations
const ETAT_COEF = { propre: 1.0, moyen: 1.15, sale: 1.3, tres_sale: 1.5 };

// Configuration complète par prestation. Chaque catégorie a une "dimension principale" (tierKey)
// pour laquelle le PRO SAISIT DIRECTEMENT UN PRIX PAR CAS CONCRET (ex: un prix pour "Citadine",
// un autre pour "SUV/4x4"...), plutôt qu'un coefficient invisible appliqué à un prix unique.
// Une dimension secondaire (matière, portée...) reste un coefficient multiplicatif simple.
// Chiffres calibrés à partir d'une recherche de prix pratiqués par des professionnels en France
// (voir tableau-reference-prix-marche.md pour le détail des sources et du raisonnement).
const PRESTATION_CONFIG = {
  voiture: {
    tierKey: 'taille', // le pro saisit un prix par type de véhicule
    tiers: ['citadine', 'suv_4x4', 'monospace', 'utilitaire'],
    tierLabels: { citadine: 'Citadine', suv_4x4: 'SUV / 4x4', monospace: 'Monospace', utilitaire: 'Utilitaire / Van' },
    tierDefaults: { citadine: 85, suv_4x4: 128, monospace: 132, utilitaire: 153 }, // intérieur+extérieur, propre
    coefPortee: { interieur: 0.70, exterieur: 0.55, complet: 1.0 },
    // Le nombre de places est un facteur secondaire : à type de véhicule identique, plus de places
    // signifie plus de surface à nettoyer (ex: un SUV 5 places vs un SUV 7 places).
    coefPlaces: { A: 0.90, B: 1.0, C: 1.15, D: 1.35 } // 2, 5, 7, 9+ places
  },
  canape: {
    tierKey: 'taille', // le pro saisit un prix par nombre de places
    tiers: ['A', 'B', 'C', 'D'],
    tierLabels: { A: '2 places', B: '3 places', C: '4 places', D: '5+ places / angle' },
    tierDefaults: { A: 80, B: 92, C: 108, D: 128 }, // tissu, propre
    coefMatiere: { tissu: 1.0, cuir: 1.15, velours: 1.05, microfibre: 1.0 },
    // La forme influence le temps de travail à nombre de places égal (un angle est plus complexe qu'un droit).
    coefForme: { droit: 1.0, angle: 1.2, canape_lit: 1.15, chauffeuses: 0.85 }
  },
  matelas: {
    unite: true,
    tierKey: 'taille', // le pro saisit un prix unitaire par taille de matelas
    tiers: ['A', 'B', 'C', 'D'],
    tierLabels: { A: '90x190 cm', B: '140x190 cm', C: '160x200 cm', D: '180x200 cm+' },
    tierDefaults: { A: 45, B: 60, C: 72, D: 90 } // propre
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
    tierDefaults: { entretien: 65, complet: 130, eau_verte: 585 }, // bassin moyen, propre
    coefTaille: { A: 0.7, B: 1.0, C: 1.4, D: 1.9 },
    // Un spa/jacuzzi est nettement plus petit qu'un bassin classique ; le hors-sol est aussi souvent plus simple.
    coefTypeBassin: { enterree: 1.0, semi_enterree: 0.95, hors_sol: 0.8, spa_jacuzzi: 0.35 }
  },
  toiture: {
    unite: true,
    uniteLabel: 'm²', // le pro fixe un prix par m² réel, le client indique la surface exacte
    prixReferenceDefaut: 20, // €/m², tuiles, démoussage + hydrofuge, état propre (marché observé : 9 à 40€/m²)
    coefMatiere: { tuiles: 1.0, ardoises: 0.75, fibrociment: 0.9, zinc_metal: 1.1 }
  },
  vitres: {
    unite: true,
    uniteLabel: 'm²', // le pro fixe un prix par m² de surface vitrée réelle
    tierKey: 'type_bien', // le type de bien reste pertinent : accès et vitrages souvent plus complexes en commerce/bureaux
    tiers: ['maison', 'appartement', 'commerce', 'bureaux'],
    tierLabels: { maison: 'Maison', appartement: 'Appartement', commerce: 'Commerce', bureaux: 'Bureaux' },
    tierDefaults: { maison: 4, appartement: 4, commerce: 4.8, bureaux: 5.2 } // €/m², propre (marché observé : 1 à 5€/m²)
  },
  tapis: {
    unite: true,
    uniteLabel: 'm²', // le pro fixe un prix par m² réel, le client indique la surface exacte
    prixReferenceDefaut: 20, // €/m², synthétique, état propre (marché observé : 15 à 35€/m² synthétique)
    // Écart de prix très marqué selon la matière (jusqu'à x4 entre synthétique et soie) — recherche de marché à l'appui.
    coefMatiere: { synthetique: 1.0, coton: 1.2, jute_sisal: 1.3, berbere: 1.4, laine: 1.6, soie: 3.5 }
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
// Détecte un numéro de téléphone français (mobile ou fixe), même écrit avec espaces/points/tirets
// entre les groupes de chiffres (ex: "06 12 34 56 78", "06.12.34.56.78"), pas seulement collé.
// Détecte une tentative de partage de coordonnées avant paiement : numéro français (fixe/mobile,
// collé ou avec séparateurs), numéro au format international (+33/0033), email (y compris légèrement
// déguisé avec "at"/"point"), ou mention d'une messagerie externe couramment utilisée pour contourner
// la plateforme. Reste volontairement prudent sur les mots ambigus (ex: "signal", "snap") pour éviter
// de bloquer des messages innocents.
const BLOCK_REGEX = /(\b0[1-9](?:[\s.-]?\d{2}){4}\b|(?:\+33|0033)[\s.-]?[1-9](?:[\s.-]?\d{2}){4}\b|[\w.+-]+\s?(?:@|\(at\)|arobase)\s?[\w-]+\s?(?:\.|\(dot\)|\bpoint\b)\s?[a-z]{2,}|whatsapp|telegram|instagram|messenger|snapchat|tiktok|facebook|viber|\bsms\b)/i;

app.get('/health', (req, res) => {
  res.json({ status: 'ok', app: 'Gleam API', version: '2.2.0', timestamp: new Date().toISOString() });
});

// ══════════════ AUTH ══════════════

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
    if (isProType(type) && !assuranceRcPro)
      return res.status(400).json({ error: 'L\'attestation d\'assurance RC Pro est requise pour créer un compte professionnel.' });
    if (isProType(type) && !/^\d{14}$/.test(siret))
      return res.status(400).json({ error: 'Numéro SIRET invalide (14 chiffres attendus).' });
    if (type === 'entreprise') {
      if (!raisonSociale) return res.status(400).json({ error: 'Raison sociale requise.' });
      if (!/^\d{14}$/.test(siret)) return res.status(400).json({ error: 'Numéro SIRET invalide (14 chiffres attendus).' });
      if (!adresseFacturation) return res.status(400).json({ error: 'Adresse de facturation requise.' });
    }

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
    if (authError) return res.status(400).json({ error: authError.message });

    // Génère un code de parrainage unique pour ce nouveau compte (quelques essais suffisent presque
    // toujours vu le grand nombre de combinaisons possibles)
    let codeParrainage = null;
    for (let essai = 0; essai < 5 && !codeParrainage; essai++) {
      const candidat = (prenom.trim().slice(0, 4) + Math.floor(1000 + Math.random() * 9000)).toUpperCase().replace(/[^A-Z0-9]/g, '');
      const { data: dejaUtilise } = await supabase.from('users').select('id').eq('code_parrainage', candidat).maybeSingle();
      if (!dejaUtilise) codeParrainage = candidat;
    }

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
      parraine_par: parrainId
    }).select().single();

    if (error) {
      // Le compte de connexion a été créé mais le profil a échoué : on annule tout plutôt que
      // de laisser un compte "orphelin" (connexion possible, mais aucune donnée de profil).
      await supabase.auth.admin.deleteUser(authData.user.id).catch(e => console.error('Rollback inscription:', e));
      return res.status(400).json({ error: error.message });
    }

    const token = jwt.sign({ id: data.id, email: data.email, type: data.type }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ message: 'Compte Gleam créé !', token, user: { ...data, firstName: data.prenom, lastName: data.nom } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email et mot de passe requis.' });

    const { data, error } = await supabase.auth.signInWithPassword({
      email: email.toLowerCase().trim(),
      password: password
    });
    if (error) return res.status(401).json({ error: 'Identifiants incorrects.' });

    let { data: user } = await supabase.from('users').select('*').eq('id', data.user.id).single();
    if (!user) {
      const { data: newUser } = await supabase.from('users').insert({
        id: data.user.id, email: data.user.email, prenom: data.user.email.split('@')[0], nom: '', type: 'client', disponible: true
      }).select().single();
      user = newUser;
    }
    if (!user) return res.status(500).json({ error: 'Utilisateur introuvable.' });

    const token = jwt.sign({ id: user.id, email: user.email, type: user.type }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { ...user, firstName: user.prenom, lastName: user.nom } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erreur serveur.' });
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

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expiration = new Date(Date.now() + 30 * 60 * 1000).toISOString(); // valable 30 minutes
    await supabase.from('users').update({ reset_code: code, reset_code_expire: expiration }).eq('id', user.id);

    sendEmail('reinitialisation_mot_de_passe', user.email, { prenom: user.prenom || '', code }).catch(e => console.error('Email réinitialisation:', e));

    res.json({ message: 'Si ce compte existe, un email a été envoyé.' });
  } catch (e) {
    console.error('Erreur mot de passe oublié:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.post('/api/auth/reset-password', authLimiter, async (req, res) => {
  try {
    const { email, code, new_password } = req.body;
    if (!email || !code || !new_password) return res.status(400).json({ error: 'Informations manquantes.' });
    if (new_password.length < 8) return res.status(400).json({ error: 'Mot de passe : 8 caractères minimum.' });

    const { data: user } = await supabase.from('users').select('id, reset_code, reset_code_expire').eq('email', email.toLowerCase().trim()).maybeSingle();
    if (!user || !user.reset_code || user.reset_code !== String(code).trim())
      return res.status(400).json({ error: 'Code incorrect.' });
    if (!user.reset_code_expire || new Date(user.reset_code_expire) < new Date())
      return res.status(400).json({ error: 'Ce code a expiré. Refaites une demande de "mot de passe oublié".' });

    const { error: erreurMaj } = await supabase.auth.admin.updateUserById(user.id, { password: new_password });
    if (erreurMaj) return res.status(400).json({ error: erreurMaj.message });

    await supabase.from('users').update({ reset_code: null, reset_code_expire: null }).eq('id', user.id);

    res.json({ message: 'Mot de passe mis à jour avec succès !' });
  } catch (e) {
    console.error('Erreur réinitialisation mot de passe:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  const { data } = await supabase.from('users').select('*').eq('id', req.user.id).single();
  if (!data) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  res.json({ ...data, firstName: data.prenom, lastName: data.nom });
});

// Met à jour la photo de profil (client ou pro) — reçoit une image compressée en base64 (data URL)
app.patch('/api/users/photo', auth, async (req, res) => {
  try {
    const { photo } = req.body;
    if (!photo || typeof photo !== 'string' || !/^data:image\/(jpeg|jpg|png|webp);base64,/.test(photo)) {
      return res.status(400).json({ error: 'Format d\'image non supporté (JPEG, PNG ou WEBP uniquement).' });
    }
    if (photo.length > 600 * 1024) {
      return res.status(413).json({ error: 'Photo trop volumineuse. Réessayez avec une image plus légère.' });
    }
    const { error } = await supabase.from('users').update({ photo }).eq('id', req.user.id);
    if (error) return res.status(400).json({ error: error.message });
    res.json({ message: 'Photo mise à jour.', photo });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Suppression de compte (droit à l'effacement RGPD) : anonymise les données personnelles
// identifiantes plutôt qu'une suppression brute, pour préserver l'historique des transactions
// (nécessaire pour la comptabilité, le suivi de fiabilité, et les litiges éventuels), tout en
// révoquant définitivement l'accès de connexion — cohérent avec l'approche "archiver plutôt
// que supprimer" déjà retenue ailleurs dans l'app.
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
    if (error) return res.status(400).json({ error: error.message });

    // Révoque l'accès de connexion (best-effort : n'empêche pas la suppression si ça échoue)
    try { await supabase.auth.admin.deleteUser(req.user.id); } catch (e) { console.error('Suppression auth:', e); }

    res.json({ message: 'Compte supprimé.' });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// ══════════════ DEMANDES ══════════════

app.post('/api/demandes', auth, async (req, res) => {
  try {
    const { type, prestations, address, date, time, flexibility, description, details, photos, pro_prefere_id, latitude, longitude } = req.body;
    if (!address) return res.status(400).json({ error: 'Adresse requise.' });
    const erreurCreneau = validerCreneauFutur(date, time);
    if (erreurCreneau) return res.status(400).json({ error: erreurCreneau });
    if (photos && Array.isArray(photos)) {
      if (photos.length > 5) return res.status(400).json({ error: 'Maximum 5 photos par demande.' });
      for (const p of photos) {
        if (typeof p !== 'string' || !/^data:image\/(jpeg|jpg|png|webp);base64,/.test(p)) {
          return res.status(400).json({ error: 'Format de photo non supporté (JPEG, PNG ou WEBP uniquement).' });
        }
        if (p.length > 3 * 1024 * 1024) {
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
    const notes = JSON.stringify({ flexibility: flexibility || '', prestations: listePrestations, photos: photos || [] });

    const { data, error } = await supabase.from('demandes').insert({
      client_id: req.user.id,
      prestation: prestationLabel,
      adresse: address,
      creneau: creneau,
      notes: notes,
      numero_anonyme: numero,
      pro_prefere_id: proPrefereValide,
      latitude: (typeof latitude === 'number' && !isNaN(latitude)) ? latitude : null,
      longitude: (typeof longitude === 'number' && !isNaN(longitude)) ? longitude : null,
      statut: 'en_attente'
    }).select().single();

    if (error) return res.status(400).json({ error: error.message });

    // 📧 Email "nouvelle demande" désactivé pour l'instant (risque de spam pour les pros).
    // Pour le réactiver, décommentez le bloc ci-dessous :
    // supabase.from('users').select('email, prenom').eq('type', 'pro').eq('disponible', true)
    //   .then(({ data: pros }) => {
    //     (pros || []).forEach((pro) => {
    //       sendEmail('nouvelle_demande', pro.email, {
    //         prenom: pro.prenom,
    //         prestation: prestationLabel,
    //         ville: address
    //       });
    //     });
    //   });

    res.status(201).json(data);
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
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
async function expirerDemandesEnRetard(demandes) {
  const maintenant = new Date();
  const aExpirer = [];
  const aExpirerAcceptees = [];
  for (const d of (demandes || [])) {
    if ((d.statut === 'en_attente' || d.statut === 'devis_recus' || d.statut === 'acceptee') && d.creneau) {
      const match = /(\d{4})-(\d{2})-(\d{2})\s*à\s*(\d{1,2})[h:](\d{2})/.exec(d.creneau);
      if (match) {
        const dateCreneau = new Date(+match[1], +match[2] - 1, +match[3], +match[4], +match[5]);
        const heuresDepassement = (maintenant - dateCreneau) / (1000 * 60 * 60);
        if (heuresDepassement > 3) {
          aExpirer.push(d.id);
          if (d.statut === 'acceptee') aExpirerAcceptees.push(d.id);
        }
      }
    }
  }
  if (aExpirer.length) {
    await supabase.from('demandes').update({ statut: 'expiree' }).in('id', aExpirer);
    demandes.forEach(d => { if (aExpirer.includes(d.id)) d.statut = 'expiree'; });
  }
  if (aExpirerAcceptees.length) {
    // Annule le(s) devis "accepté" resté(s) sans paiement, pour ne pas laisser un devis "accepté"
    // pointer vers une demande désormais expirée — incohérence qui perturberait l'affichage côté pro.
    await supabase.from('devis').update({ statut: 'annule_client' }).in('demande_id', aExpirerAcceptees).eq('statut', 'accepte');
  }
  return demandes;
}

app.get('/api/demandes', auth, async (req, res) => {
  const { data } = await supabase.from('demandes').select('*').eq('client_id', req.user.id).order('created_at', { ascending: false });
  const dataAJour = await expirerDemandesEnRetard(data || []);
  res.json(dataAJour);
});

// Demandes disponibles pour les pros (en attente, pas encore acceptées) — DOIT être déclarée avant /api/demandes/:id
app.get('/api/demandes/all', auth, async (req, res) => {
  try {
    const { data: user, error: userErr } = await supabase.from('users').select('type, prestations_proposees').eq('id', req.user.id).single();
    if (userErr) return res.status(500).json({ error: 'Erreur utilisateur: ' + userErr.message });
    if (!user || !isProType(user.type))
      return res.status(403).json({ error: 'Accès réservé aux professionnels.' });

    const { data: demandes, error: demErr } = await supabase
      .from('demandes')
      .select('*')
      .or('statut.eq.en_attente,statut.eq.devis_recus')
      .order('created_at', { ascending: false });

    if (demErr) return res.status(500).json({ error: 'Erreur demandes: ' + demErr.message });

    // Marque les demandes en retard comme expirées, puis les exclut immédiatement de la liste —
    // un pro ne doit jamais voir une demande dont le créneau est déjà largement dépassé.
    const demandesAJour = await expirerDemandesEnRetard(demandes || []);
    const demandesEncoreValides = demandesAJour.filter(d => d.statut !== 'expiree');

    const { data: mesDevis } = await supabase.from('devis').select('demande_id, statut').eq('societe_id', req.user.id);
    const idsRepondues = new Set((mesDevis || []).filter(d => d.statut === 'envoye' || d.statut === 'accepte').map(d => d.demande_id));
    let filtered = demandesEncoreValides.filter(d => !idsRepondues.has(d.id));

    // Ne montrer que les demandes correspondant aux prestations que le pro a déclaré savoir faire
    // (si le pro n'a configuré aucune préférence dans "Mes tarifs", on continue à tout lui montrer
    // pour ne pas casser l'expérience des pros n'ayant pas encore configuré cet écran).
    const prestationsPro = user.prestations_proposees;
    if (Array.isArray(prestationsPro) && prestationsPro.length > 0) {
      const prestationsProSet = new Set(prestationsPro);
      filtered = filtered.filter(d => {
        const typesDemande = extractPrestationTypes(d);
        return typesDemande.some(t => prestationsProSet.has(t));
      });
    }

    // Une demande adressée en priorité à un prestataire favori n'est visible que pour lui —
    // les autres pros ne la voient pas tant que le client ne l'a pas rouverte à tout le monde.
    filtered = filtered.filter(d => !d.pro_prefere_id || d.pro_prefere_id === req.user.id);

    res.json(filtered);
  } catch (e) {
    console.error('Erreur /api/demandes/all:', e);
    res.status(500).json({ error: 'Erreur serveur: ' + e.message });
  }
});

app.get('/api/demandes/:id', auth, async (req, res) => {
  const { data } = await supabase.from('demandes').select('*').eq('id', req.params.id).single();
  if (!data) return res.status(404).json({ error: 'Demande introuvable.' });
  if (data.client_id === req.user.id) return res.json(data);
  const { data: monDevis } = await supabase.from('devis').select('id').eq('demande_id', req.params.id).eq('societe_id', req.user.id).maybeSingle();
  if (monDevis) return res.json(data);
  return res.status(403).json({ error: 'Accès refusé.' });
});

// Modifier une demande (uniquement si aucun devis n'a été accepté)
app.patch('/api/demandes/:id', auth, async (req, res) => {
  try {
    const { data: demande } = await supabase.from('demandes').select('*').eq('id', req.params.id).single();
    if (!demande) return res.status(404).json({ error: 'Demande introuvable.' });
    if (demande.client_id !== req.user.id) return res.status(403).json({ error: 'Accès refusé.' });
    if (demande.statut === 'acceptee' || demande.statut === 'en_cours' || demande.statut === 'terminee' || demande.statut === 'annulee_client')
      return res.status(400).json({ error: 'Impossible de modifier : un devis a déjà été accepté pour cette demande.' });

    const { prestations, address, date, time, flexibility } = req.body;
    if (!address) return res.status(400).json({ error: 'Adresse requise.' });
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
    if (error) return res.status(400).json({ error: error.message });

    await supabase.from('devis').update({ demande_modifiee: true }).eq('demande_id', req.params.id).eq('statut', 'envoye');

    res.json(data);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Reprogrammer une prestation déjà acceptée, sans avoir à tout annuler — nécessite l'accord de
// l'autre partie avant que le créneau ne change réellement, pour éviter qu'une personne décale
// unilatéralement un rendez-vous déjà convenu.
app.post('/api/demandes/:id/proposer-creneau', auth, async (req, res) => {
  try {
    const { date, time } = req.body;
    const erreurCreneau = validerCreneauFutur(date, time);
    if (erreurCreneau) return res.status(400).json({ error: erreurCreneau });

    const { data: demande } = await supabase.from('demandes').select('*').eq('id', req.params.id).single();
    if (!demande) return res.status(404).json({ error: 'Demande introuvable.' });
    if (!['acceptee', 'en_cours'].includes(demande.statut))
      return res.status(400).json({ error: 'La reprogrammation n\'est possible que pour une prestation acceptée ou en cours.' });

    const { data: devisAccepte } = await supabase.from('devis').select('societe_id').eq('demande_id', demande.id).eq('statut', 'accepte').maybeSingle();
    const estClient = demande.client_id === req.user.id;
    const estPro = devisAccepte && devisAccepte.societe_id === req.user.id;
    if (!estClient && !estPro) return res.status(403).json({ error: 'Accès refusé.' });

    const nouveauCreneau = date + ' à ' + time;
    await supabase.from('demandes').update({ creneau_propose: nouveauCreneau, creneau_propose_par: req.user.id }).eq('id', req.params.id);

    res.json({ message: 'Nouveau créneau proposé, en attente de confirmation de l\'autre partie.' });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.post('/api/demandes/:id/repondre-creneau', auth, async (req, res) => {
  try {
    const { accepter } = req.body;
    const { data: demande } = await supabase.from('demandes').select('*').eq('id', req.params.id).single();
    if (!demande) return res.status(404).json({ error: 'Demande introuvable.' });
    if (!demande.creneau_propose) return res.status(400).json({ error: 'Aucune proposition de créneau en attente.' });
    if (demande.creneau_propose_par === req.user.id) return res.status(403).json({ error: 'Vous ne pouvez pas répondre à votre propre proposition.' });

    const { data: devisAccepte } = await supabase.from('devis').select('societe_id').eq('demande_id', demande.id).eq('statut', 'accepte').maybeSingle();
    const estClient = demande.client_id === req.user.id;
    const estPro = devisAccepte && devisAccepte.societe_id === req.user.id;
    if (!estClient && !estPro) return res.status(403).json({ error: 'Accès refusé.' });

    if (accepter) {
      await supabase.from('demandes').update({ creneau: demande.creneau_propose, creneau_propose: null, creneau_propose_par: null }).eq('id', req.params.id);
      res.json({ message: 'Nouveau créneau confirmé ✨' });
    } else {
      await supabase.from('demandes').update({ creneau_propose: null, creneau_propose_par: null }).eq('id', req.params.id);
      res.json({ message: 'Proposition refusée. L\'ancien créneau reste valable.' });
    }
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
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

  let pourcentage = 1;
  if (typeof heuresRestantes === 'number') {
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
    if (!demande) return res.status(404).json({ error: 'Demande introuvable.' });
    if (demande.client_id !== req.user.id) return res.status(403).json({ error: 'Accès refusé.' });
    if (demande.statut === 'terminee')
      return res.status(400).json({ error: 'Cette prestation est déjà terminée, elle ne peut plus être annulée.' });
    if (demande.statut !== 'acceptee' && demande.statut !== 'en_cours')
      return res.status(400).json({ error: 'Utilisez la suppression classique pour une demande pas encore acceptée.' });

    // Calcule précisément les heures restantes avant le créneau prévu, pour déterminer le palier
    // de frais applicable (voir rembourserPaiementSiPaye) — heuresRestantes reste `null` si aucun
    // créneau n'est renseigné, auquel cas le remboursement intégral s'applique par défaut.
    let heuresRestantes = null;
    if (demande.creneau) {
      const match = /(\d{4})-(\d{2})-(\d{2})\s*à\s*(\d{1,2})[h:](\d{2})/.exec(demande.creneau);
      if (match) {
        const dateCreneau = new Date(+match[1], +match[2] - 1, +match[3], +match[4], +match[5]);
        heuresRestantes = (dateCreneau - new Date()) / (1000 * 60 * 60);
      }
    }
    const tardive = heuresRestantes !== null && heuresRestantes < 24;

    const { data: devisAccepte } = await supabase.from('devis').select('*').eq('demande_id', demande.id).eq('statut', 'accepte').maybeSingle();

    // Si la prestation était déjà payée (en cours), applique le barème de frais avant d'annuler
    const remboursement = demande.statut === 'en_cours' ? await rembourserPaiementSiPaye(demande.id, heuresRestantes) : { rembourse: false };

    await supabase.from('demandes').update({ statut: 'annulee_client' }).eq('id', demande.id);
    if (devisAccepte) await supabase.from('devis').update({ statut: 'annule_client' }).eq('id', devisAccepte.id);

    // 📧 Notifie immédiatement le prestataire concerné
    if (devisAccepte) {
      const { data: pro } = await supabase.from('users').select('email, prenom').eq('id', devisAccepte.societe_id).single();
      if (pro) {
        sendEmail('annulation_client', pro.email, {
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
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Supprimer une demande (uniquement si aucun devis n'a été accepté)
// Le client "range" une demande définitivement close (annulée ou terminée) de sa vue,
// sans jamais la supprimer réellement — l'historique reste intact pour le suivi de fiabilité
// et en cas de litige. Utilisable à tout moment, contrairement à la suppression.
app.patch('/api/demandes/:id/archiver', auth, async (req, res) => {
  try {
    const { data: demande } = await supabase.from('demandes').select('client_id, statut').eq('id', req.params.id).single();
    if (!demande) return res.status(404).json({ error: 'Demande introuvable.' });
    if (demande.client_id !== req.user.id) return res.status(403).json({ error: 'Accès refusé.' });

    const { error } = await supabase.from('demandes').update({ archivee_client: true }).eq('id', req.params.id);
    if (error) return res.status(400).json({ error: error.message });
    res.json({ message: 'Demande archivée.' });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.delete('/api/demandes/:id', auth, async (req, res) => {
  try {
    const { data: demande } = await supabase.from('demandes').select('*').eq('id', req.params.id).single();
    if (!demande) return res.status(404).json({ error: 'Demande introuvable.' });
    if (demande.client_id !== req.user.id) return res.status(403).json({ error: 'Accès refusé.' });
    if (demande.statut === 'acceptee' || demande.statut === 'en_cours' || demande.statut === 'terminee')
      return res.status(400).json({ error: 'Impossible de supprimer : un devis a déjà été accepté. Utilisez le bouton "Annuler cette prestation" à la place.' });
    if (demande.statut === 'annulee_client')
      return res.status(400).json({ error: 'Cette demande est déjà annulée.' });

    await supabase.from('devis').delete().eq('demande_id', req.params.id);
    await supabase.from('messages').delete().eq('demande_id', req.params.id);
    await supabase.from('paiements').delete().eq('demande_id', req.params.id);
    await supabase.from('evaluations').delete().eq('demande_id', req.params.id);
    const { error } = await supabase.from('demandes').delete().eq('id', req.params.id);
    if (error) return res.status(400).json({ error: error.message });

    res.json({ message: 'Demande supprimée.' });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// ══════════════ DEVIS ══════════════

app.post('/api/devis', auth, async (req, res) => {
  try {
    const { demande_id, prix_ttc, description, creneau_propose } = req.body;
    if (!demande_id || !prix_ttc)
      return res.status(400).json({ error: 'Demande et prix requis.' });
    if (parseFloat(prix_ttc) <= 0)
      return res.status(400).json({ error: 'Le prix doit être positif.' });

    const { data: demande } = await supabase.from('demandes').select('*').eq('id', demande_id).single();
    if (!demande) return res.status(404).json({ error: 'Demande introuvable.' });
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

    if (error) return res.status(400).json({ error: error.message });
    await supabase.from('demandes').update({ statut: 'devis_recus' }).eq('id', demande_id);

    // 📧 Email 2/8 : nouveau devis reçu → client
    const { data: client } = await supabase.from('users').select('email, prenom').eq('id', demande.client_id).single();
    if (client) {
      sendEmail('nouveau_devis', client.email, {
        prenom: client.prenom,
        prestation: demande.prestation,
        prix: parseFloat(prix_ttc),
        demandeId: demande_id
      });
    }

    res.status(201).json(data);
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Devis reçus par un client pour une demande (avec infos pro)
app.get('/api/devis/demande/:id', auth, async (req, res) => {
  const { data: demande } = await supabase.from('demandes').select('client_id, statut').eq('id', req.params.id).single();
  if (!demande) return res.status(404).json({ error: 'Demande introuvable.' });
  if (demande.client_id !== req.user.id) return res.status(403).json({ error: 'Accès refusé.' });

  const { data: devis } = await supabase.from('devis').select('*').eq('demande_id', req.params.id).order('prix_ttc', { ascending: true });
  if (!devis || !devis.length) return res.json([]);

  const proIds = [...new Set(devis.map(d => d.societe_id))];
  const { data: pros } = await supabase.from('users').select('id, prenom, nom, note_moyenne, taux_fiabilite, photo').in('id', proIds);
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
    const { data: demandes } = await supabase.from('demandes').select('id, prestation, statut, photos_avant, photos_apres, prestation_demarree_le, creneau, creneau_propose, creneau_propose_par')
      .eq('client_id', req.user.id).in('statut', ['devis_recus', 'acceptee', 'en_cours', 'terminee']);
    if (!demandes || !demandes.length) return res.json([]);

    const demandeIds = demandes.map(d => d.id);
    const demandeMap = {};
    demandes.forEach(d => demandeMap[d.id] = d);

    const { data: devis } = await supabase.from('devis').select('*').in('demande_id', demandeIds);
    if (!devis || !devis.length) return res.json([]);

    const proIds = [...new Set(devis.map(d => d.societe_id))];
    const { data: pros } = await supabase.from('users').select('id, prenom, nom, note_moyenne, taux_fiabilite, photo').in('id', proIds);
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

    res.json(enriched);
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
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
    res.json(enriched);
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.post('/api/devis/:id/accepter', auth, async (req, res) => {
  try {
    const { data: devis } = await supabase.from('devis').select('*').eq('id', req.params.id).single();
    if (!devis) return res.status(404).json({ error: 'Devis introuvable.' });

    const { data: demande } = await supabase.from('demandes').select('*').eq('id', devis.demande_id).single();
    if (!demande || demande.client_id !== req.user.id) return res.status(403).json({ error: 'Accès refusé.' });
    if (demande.statut === 'acceptee') return res.status(400).json({ error: 'Une demande a déjà été acceptée pour cette prestation.' });

    await supabase.from('devis').update({ statut: 'accepte' }).eq('id', req.params.id);
    await supabase.from('demandes').update({ statut: 'acceptee' }).eq('id', devis.demande_id);
    await supabase.from('devis').update({ statut: 'refuse' }).eq('demande_id', devis.demande_id).neq('id', req.params.id);

    // 📧 Email 3/8 : devis accepté → pro gagnant
    const { data: proAccepte } = await supabase.from('users').select('email, prenom').eq('id', devis.societe_id).single();
    if (proAccepte) {
      sendEmail('devis_accepte', proAccepte.email, {
        prenom: proAccepte.prenom,
        prestation: demande.prestation,
        creneau: devis.creneau_propose || demande.creneau,
        demandeId: devis.demande_id
      });
    }

    // 📧 Email "devis refusé" désactivé pour l'instant (peu actionnable, peut être mal vécu par les pros).
    // Pour le réactiver, décommentez le bloc ci-dessous :
    // const { data: devisRefuses } = await supabase.from('devis').select('societe_id').eq('demande_id', devis.demande_id).eq('statut', 'refuse');
    // if (devisRefuses && devisRefuses.length) {
    //   const idsRefuses = [...new Set(devisRefuses.map(d => d.societe_id))];
    //   const { data: prosRefuses } = await supabase.from('users').select('email, prenom').in('id', idsRefuses);
    //   (prosRefuses || []).forEach((pro) => {
    //     sendEmail('devis_refuse', pro.email, { prenom: pro.prenom, prestation: demande.prestation });
    //   });
    // }

    res.json({ message: 'Devis accepté !', demande_id: devis.demande_id, societe_id: devis.societe_id });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.post('/api/devis/:id/refuser', auth, async (req, res) => {
  try {
    const { data: devis } = await supabase.from('devis').select('*').eq('id', req.params.id).single();
    if (!devis) return res.status(404).json({ error: 'Devis introuvable.' });

    const { data: demande } = await supabase.from('demandes').select('*').eq('id', devis.demande_id).single();
    if (!demande || demande.client_id !== req.user.id) return res.status(403).json({ error: 'Accès refusé.' });

    await supabase.from('devis').update({ statut: 'refuse' }).eq('id', req.params.id);

    // 📧 Email "devis refusé" désactivé pour l'instant (peu actionnable, peut être mal vécu par les pros).
    // Pour le réactiver, décommentez le bloc ci-dessous :
    // const { data: proRefuse } = await supabase.from('users').select('email, prenom').eq('id', devis.societe_id).single();
    // if (proRefuse) {
    //   sendEmail('devis_refuse', proRefuse.email, { prenom: proRefuse.prenom, prestation: demande.prestation });
    // }

    res.json({ message: 'Devis refusé.' });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Le pro annule un devis qu'il avait fait accepter par le client
app.post('/api/devis/:id/annuler-pro', auth, async (req, res) => {
  try {
    const { data: devis } = await supabase.from('devis').select('*').eq('id', req.params.id).single();
    if (!devis) return res.status(404).json({ error: 'Devis introuvable.' });
    if (devis.societe_id !== req.user.id) return res.status(403).json({ error: 'Accès refusé.' });
    if (devis.statut !== 'accepte') return res.status(400).json({ error: 'Ce devis n\'est pas accepté.' });

    const { data: demande } = await supabase.from('demandes').select('*').eq('id', devis.demande_id).single();
    if (!demande) return res.status(404).json({ error: 'Demande introuvable.' });

    // Vérifie le délai de 24h avant le créneau (signalé, mais jamais bloquant — cohérent avec l'annulation côté client)
    let tardive = false;
    if (demande.creneau) {
      const match = /(\d{4})-(\d{2})-(\d{2})\s*à\s*(\d{1,2})[h:](\d{2})/.exec(demande.creneau);
      if (match) {
        const dateCreneau = new Date(+match[1], +match[2] - 1, +match[3], +match[4], +match[5]);
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
      sendEmail('compte_suspendu', proActuel.email, { prenom: proActuel.prenom || '' }).catch(e => console.error('Email compte_suspendu:', e));
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
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// ══════════════ MESSAGES ══════════════

// Vérifie que l'utilisateur connecté a le droit de participer à la conversation de cette demande
// (le client propriétaire, ou le pro dont le devis a été accepté) — protège la confidentialité des échanges.
async function peutAccederConversation(demandeId, userId) {
  const { data: demande } = await supabase.from('demandes').select('client_id').eq('id', demandeId).single();
  if (!demande) return false;
  if (demande.client_id === userId) return true;
  const { data: devisAccepte } = await supabase.from('devis').select('societe_id').eq('demande_id', demandeId).eq('statut', 'accepte').maybeSingle();
  return !!(devisAccepte && devisAccepte.societe_id === userId);
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

    if (BLOCK_REGEX.test(contenu) || contientNumeroReconstitue(contenuRecent))
      return res.status(400).json({ error: 'Gleam bloque les coordonnées avant paiement.', blocked: true });

    const { data: demande } = await supabase.from('demandes').select('*').eq('id', demande_id).single();
    if (!demande) return res.status(404).json({ error: 'Demande introuvable.' });
    if (!(await peutAccederConversation(demande_id, req.user.id)))
      return res.status(403).json({ error: 'Accès refusé.' });

    const { data, error } = await supabase.from('messages').insert({
      demande_id: demande_id,
      expediteur_id: req.user.id,
      contenu: contenu.trim(),
      type: 'texte'
    }).select().single();

    if (error) return res.status(400).json({ error: error.message });

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
          prenom: destinataire.prenom,
          expediteurNom: (expediteur && expediteur.prenom) || 'Un utilisateur',
          prestation: demande.prestation,
          apercu: contenu.trim().slice(0, 100),
          demandeId: demande_id
        });
      }
    }

    res.status(201).json(data);
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.get('/api/messages/:demande_id', auth, async (req, res) => {
  if (!(await peutAccederConversation(req.params.demande_id, req.user.id)))
    return res.status(403).json({ error: 'Accès refusé.' });
  const { data } = await supabase.from('messages').select('*').eq('demande_id', req.params.demande_id).order('created_at', { ascending: true });
  res.json(data || []);
});

// Liste des conversations actives pour l'utilisateur connecté (client ou pro)
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
      const { data: clients } = await supabase.from('users').select('id, prenom, nom, photo, note_moyenne').in('id', clientIds);
      const clientMap = {};
      (clients || []).forEach(c => clientMap[c.id] = c);
      (demandes || []).forEach(d => { autrePartieParDemande[d.id] = clientMap[d.client_id] || null; });
    } else {
      const { data: devisAcceptes } = await supabase.from('devis').select('demande_id, societe_id').in('demande_id', demandeIds).eq('statut', 'accepte');
      const proIdParDemande = {};
      (devisAcceptes || []).forEach(dv => { proIdParDemande[dv.demande_id] = dv.societe_id; });
      const proIds = [...new Set(Object.values(proIdParDemande))];
      const { data: pros } = await supabase.from('users').select('id, prenom, nom, photo, note_moyenne').in('id', proIds);
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
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// ══════════════ PAIEMENTS ══════════════

// Crée (si besoin) le compte Stripe Connect du pro, puis renvoie un lien d'inscription hébergé
// par Stripe lui-même — Gleam ne collecte ni ne stocke jamais l'IBAN ou l'identité du pro,
// tout se passe directement chez Stripe, qui gère la conformité (DSP2, vérification d'identité...).
app.post('/api/paiements/connect/onboarding', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('type, stripe_account_id, email').eq('id', req.user.id).single();
    if (!user || !isProType(user.type)) return res.status(403).json({ error: 'Réservé aux professionnels.' });

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

app.post('/api/paiements/intent', auth, async (req, res) => {
  try {
    const { devis_id } = req.body;
    if (!devis_id) return res.status(400).json({ error: 'Devis requis.' });

    const { data: devis } = await supabase.from('devis').select('*').eq('id', devis_id).single();
    if (!devis) return res.status(404).json({ error: 'Devis introuvable.' });

    const { data: demandePourPaiement } = await supabase.from('demandes').select('client_id').eq('id', devis.demande_id).single();
    if (!demandePourPaiement || demandePourPaiement.client_id !== req.user.id)
      return res.status(403).json({ error: 'Accès refusé.' });

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

    const montantPro = devis.prix_ttc * 0.85;
    const montantFacture = parrainageApplique ? devis.prix_ttc * 0.90 : devis.prix_ttc;
    const commissionGleam = montantFacture - montantPro;
    const montant = Math.round(montantFacture * 100);
    const commission = Math.round(commissionGleam * 100);

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
      proConfigure = Boolean(proPourPaiement && proPourPaiement.stripe_account_id);
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
    console.error('Erreur création intention de paiement:', e);
    res.status(500).json({ error: 'Impossible de démarrer le paiement pour l\'instant. Réessayez dans un instant ou contactez le support si le problème persiste.' });
  }
});

app.post('/api/paiements/confirmer', auth, async (req, res) => {
  try {
    const { payment_intent_id } = req.body;
    const intent = await stripe.paymentIntents.retrieve(payment_intent_id, { expand: ['latest_charge'] });
    if (intent.status !== 'succeeded')
      return res.status(400).json({ error: 'Paiement non confirmé par Stripe.' });

    // Génère le code à 6 chiffres que le client devra donner au prestataire à la fin de la
    // prestation (comme un code de livraison Uber Eats) — preuve que les deux parties étaient
    // bien en contact au moment de la finalisation, plutôt qu'une simple confirmation unilatérale.
    const codeValidation = String(Math.floor(100000 + Math.random() * 900000));
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

    if (paiement) {
      await supabase.from('demandes').update({ statut: 'en_cours' }).eq('id', paiement.demande_id);

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
          prenom: pro.prenom,
          prestation: demandeInfo ? demandeInfo.prestation : '',
          montantTotal: paiement.montant_ttc,
          commission: paiement.commission,
          montantPro: paiement.montant_societe,
          demandeId: paiement.demande_id
        });
      }
    }

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
      return { erreur: 'Le virement vers le prestataire a échoué (' + (stripeErr.message || 'compte Stripe non prêt') + '). Réessayez plus tard ou contactez le support.' };
    }
  }

  await supabase.from('paiements').update({ statut: 'libere' }).eq('id', paiement.id);
  await supabase.from('demandes').update({ statut: 'terminee' }).eq('id', paiement.demande_id);

  const { data: demandeInfo } = await supabase.from('demandes').select('prestation').eq('id', paiement.demande_id).single();
  const { data: client } = await supabase.from('users').select('email, prenom').eq('id', paiement.client_id).single();
  if (client) {
    sendEmail('prestation_confirmee', client.email, {
      prenom: client.prenom, role: 'client', prestation: demandeInfo ? demandeInfo.prestation : '', demandeId: paiement.demande_id
    }).catch(e => console.error('Email prestation_confirmee client:', e));
  }
  if (pro) {
    sendEmail('prestation_confirmee', pro.email, {
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
    if (p.length > 3 * 1024 * 1024) {
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
    const { photos_avant, latitude_pro, longitude_pro } = req.body;
    const { data: demande } = await supabase.from('demandes').select('*').eq('id', req.params.id).single();
    if (!demande) return res.status(404).json({ error: 'Demande introuvable.' });
    if (demande.statut !== 'en_cours') return res.status(400).json({ error: 'Cette prestation n\'est pas en cours.' });

    const { data: devisAccepte } = await supabase.from('devis').select('societe_id').eq('demande_id', req.params.id).eq('statut', 'accepte').maybeSingle();
    if (!devisAccepte || devisAccepte.societe_id !== req.user.id) return res.status(403).json({ error: 'Accès refusé.' });

    const erreurPhotos = validerPhotos(photos_avant, 5);
    if (erreurPhotos) return res.status(400).json({ error: erreurPhotos });

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

    await supabase.from('demandes').update({
      photos_avant: photos_avant && photos_avant.length ? JSON.stringify(photos_avant) : null,
      prestation_demarree_le: new Date().toISOString(),
      distance_gps_arrivee: distanceGpsMetres
    }).eq('id', req.params.id);

    res.json({ message: 'Arrivée confirmée. Bonne prestation !' });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Le PRESTATAIRE saisit le code à 6 chiffres que le client lui a donné en personne, à la fin de
// la prestation (même logique qu'un code de livraison Uber Eats) — remplace la confirmation
// unilatérale par le client seul, et prouve que les deux parties étaient bien en contact.
app.post('/api/paiements/valider-code', auth, async (req, res) => {
  try {
    const { demande_id, code, photos_apres } = req.body;
    if (!demande_id || !code) return res.status(400).json({ error: 'Code requis.' });

    const { data: paiement } = await supabase.from('paiements').select('*').eq('demande_id', demande_id).eq('statut', 'paye').maybeSingle();
    if (!paiement) return res.status(404).json({ error: 'Aucun paiement en attente pour cette prestation.' });
    if (paiement.societe_id !== req.user.id) return res.status(403).json({ error: 'Accès refusé.' });
    if (String(code).trim() !== paiement.code_validation) return res.status(400).json({ error: 'Code incorrect. Vérifiez le code donné par le client.' });

    const erreurPhotos = validerPhotos(photos_apres, 5);
    if (erreurPhotos) return res.status(400).json({ error: erreurPhotos });
    if (photos_apres && photos_apres.length) {
      await supabase.from('demandes').update({ photos_apres: JSON.stringify(photos_apres) }).eq('id', demande_id);
    }

    const resultat = await finaliserPrestation(paiement);
    if (resultat.erreur) return res.status(400).json({ error: resultat.erreur });

    res.json({ message: 'Prestation validée, paiement transféré ✨' });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
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
    res.status(500).json({ error: 'Erreur serveur.' });
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
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Génère les données d'une facture pour une prestation terminée — accessible au client (ou à
// l'entreprise) et au prestataire concernés. Le document lui-même (mise en forme imprimable)
// est construit côté app à partir de ces données ; rien n'est stocké en double ici.
// Construit une description complète de la prestation (matière, surface/quantité, état) à partir
// des notes structurées de la demande — plutôt que d'afficher juste le nom brut de la catégorie
// sur la facture, ce qui serait trop pauvre pour un usage comptable ou professionnel sérieux.
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
    if (!demande) return res.status(404).json({ error: 'Demande introuvable.' });
    if (demande.statut !== 'terminee') return res.status(400).json({ error: 'La facture n\'est disponible qu\'une fois la prestation terminée.' });

    const { data: devisAccepte } = await supabase.from('devis').select('*').eq('demande_id', demande.id).eq('statut', 'accepte').maybeSingle();
    if (!devisAccepte) return res.status(404).json({ error: 'Devis introuvable.' });

    const estClient = demande.client_id === req.user.id;
    const estPro = devisAccepte.societe_id === req.user.id;
    if (!estClient && !estPro) return res.status(403).json({ error: 'Accès refusé.' });

    const { data: client } = await supabase.from('users').select('prenom, nom, email, type, raison_sociale, siret, tva_intracom, adresse_facturation').eq('id', demande.client_id).single();
    const { data: pro } = await supabase.from('users').select('prenom, nom, email, siret').eq('id', devisAccepte.societe_id).single();
    const { data: paiement } = await supabase.from('paiements').select('*').eq('demande_id', demande.id).maybeSingle();

    const montantTtc = parseFloat(devisAccepte.prix_ttc);
    const commission = paiement ? parseFloat(paiement.commission) : Math.round(montantTtc * 0.15 * 100) / 100;
    const montantPro = paiement ? parseFloat(paiement.montant_societe) : Math.round((montantTtc - commission) * 100) / 100;

    res.json({
      numero: 'GLEAM-' + demande.id.slice(0, 8).toUpperCase(),
      date: demande.updated_at || demande.created_at,
      prestation: construireDescriptionPrestation(demande.notes, demande.prestation),
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
      montant_pro: montantPro
    });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
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
    if (error) return res.status(400).json({ error: error.message });
    res.status(201).json({ message: 'Ajouté à vos favoris ✨' });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.delete('/api/favoris/:proId', auth, async (req, res) => {
  try {
    await supabase.from('favoris').delete().eq('client_id', req.user.id).eq('pro_id', req.params.proId);
    res.json({ message: 'Retiré de vos favoris.' });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.get('/api/favoris', auth, async (req, res) => {
  try {
    const { data: favoris } = await supabase.from('favoris').select('pro_id, created_at').eq('client_id', req.user.id).order('created_at', { ascending: false });
    if (!favoris || !favoris.length) return res.json([]);
    const proIds = favoris.map(f => f.pro_id);
    const { data: pros } = await supabase.from('users').select('id, prenom, nom, photo, note_moyenne, prestations_proposees, disponible').in('id', proIds);
    const proMap = {};
    (pros || []).forEach(p => proMap[p.id] = p);
    res.json(favoris.map(f => proMap[f.pro_id]).filter(Boolean));
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
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
    res.status(500).json({ error: 'Erreur serveur.' });
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
    if (!demande) return res.status(404).json({ error: 'Demande introuvable.' });
    if (demande.statut !== 'terminee') return res.status(400).json({ error: 'Vous ne pouvez noter qu\'une prestation terminée.' });

    const { data: devisAccepte } = await supabase.from('devis').select('societe_id').eq('demande_id', demande_id).eq('statut', 'accepte').maybeSingle();
    const estClient = demande.client_id === req.user.id;
    const estPro = devisAccepte && devisAccepte.societe_id === req.user.id;
    if (!estClient && !estPro) return res.status(403).json({ error: 'Accès refusé.' });

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
    if (error) return res.status(400).json({ error: error.message });

    const { data: notes } = await supabase.from('evaluations').select('note').eq('evalue_id', evalue_id);
    const moyenne = notes.reduce(function(a, b) { return a + b.note; }, 0) / notes.length;
    await supabase.from('users').update({ note_moyenne: Math.round(moyenne * 100) / 100 }).eq('id', evalue_id);

    res.status(201).json(data);
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
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
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Liste des identifiants de demandes déjà notées par l'utilisateur connecté (pour cacher le
// bouton "Noter" une fois l'avis déjà donné, plutôt que de compter uniquement sur le refus serveur)
app.get('/api/evaluations/mes-notes-donnees', auth, async (req, res) => {
  try {
    const { data } = await supabase.from('evaluations').select('demande_id').eq('evaluateur_id', req.user.id);
    res.json((data || []).map(e => e.demande_id));
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
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

// ══════════════ TARIFICATION (Vague 2) ══════════════

// Le pro consulte ses propres tarifs de base et prestations proposées
app.get('/api/societes/tarifs', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('type, tarifs_base, tarifs_unitaires, prestations_proposees').eq('id', req.user.id).single();
    if (!user || !isProType(user.type)) return res.status(403).json({ error: 'Accès réservé aux professionnels.' });
    res.json({ tarifs: user.tarifs_base || {}, tarifs_unitaires: user.tarifs_unitaires || {}, prestations: user.prestations_proposees || [] });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Le pro met à jour ses tarifs — pour les catégories structurées, un prix distinct par palier
// (ex: {citadine: 70, suv_4x4: 130, ...}) ; pour "autre", un prix unique.
app.patch('/api/societes/tarifs', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('type').eq('id', req.user.id).single();
    if (!user || !isProType(user.type)) return res.status(403).json({ error: 'Accès réservé aux professionnels.' });

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
    if (error) return res.status(400).json({ error: error.message });
    res.json({ message: 'Tarifs mis à jour.', tarifs: tarifsPropres, tarifs_unitaires: tarifsUnitairesPropres, prestations: prestationsPropres });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Le client obtient une estimation de prix avant/après avoir envoyé sa demande
app.get('/api/tarifs/estimation', auth, async (req, res) => {
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
      const { data: prosUnit } = await supabase.from('users').select('tarifs_unitaires').eq('type', 'pro').eq('disponible', true);
      const { prix: prixUnitaire, reel, nbPros } = prixPourPalier(config, prestation, tierValue, (prosUnit || []).map(p => p.tarifs_unitaires && p.tarifs_unitaires[prestation]));

      const coefMatiereUnite = (config.tierKey !== 'matiere' && config.coefMatiere && matiere && config.coefMatiere.hasOwnProperty(matiere)) ? config.coefMatiere[matiere] : 1.0;
      const coefTailleUnite = (config.tierKey !== 'taille' && config.coefTaille && taille && config.coefTaille.hasOwnProperty(taille)) ? config.coefTaille[taille] : 1.0;
      const prixMoyen = Math.round(prixUnitaire * quantite * coefEtat * coefMatiereUnite * coefTailleUnite);
      const prixMin = Math.round(prixMoyen * 0.85);
      const prixMax = Math.round(prixMoyen * 1.15);

      return res.json({
        prestation, etat, quantite, taille: taille || null, matiere: matiere || null, type_bien: typeBien || null,
        prix_unitaire: Math.round(prixUnitaire * 100) / 100,
        prix_min: prixMin, prix_max: prixMax, prix_moyen: prixMoyen,
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

    const prixMoyen = Math.round(base * coef);
    const prixMin = Math.round(prixMoyen * 0.85);
    const prixMax = Math.round(prixMoyen * 1.15);

    res.json({
      prestation, etat, taille: taille || null, matiere: matiere || null, portee: portee || null, intervention: intervention || null,
      prix_min: prixMin, prix_max: prixMax, prix_moyen: prixMoyen,
      base_sur_donnees_reelles: reel,
      nombre_pros_reference: nbPros
    });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log('✨ Gleam API démarrée sur le port ' + PORT);
  console.log('   Environnement : ' + (process.env.NODE_ENV || 'development'));
});
// END FINAL
