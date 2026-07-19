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

const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300, standardHeaders: true, legacyHeaders: false });
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

// ══════════════ TARIFICATION (Vague 2) ══════════════
// Coefficients multiplicateurs selon l'état du bien déclaré par le client
const ETAT_COEF = { propre: 1.0, moyen: 1.15, sale: 1.3, tres_sale: 1.5 };
// Tarifs de base par défaut (utilisés tant qu'aucun pro n'a renseigné son propre tarif pour la catégorie)
const DEFAULT_TARIFS = { voiture: 60, canape: 70, matelas: 40, terrasse: 90, piscine: 120, toiture: 150, vitres: 50, autre: 60 };

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
const BLOCK_REGEX = /(\b0[67]\d{8}\b|[\w.+-]+@[\w-]+\.[a-z]{2,}|whatsapp|telegram|instagram)/i;

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

    if (!email || !password || !prenom || !nom)
      return res.status(400).json({ error: 'Tous les champs sont requis.' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Mot de passe : 8 caractères minimum.' });
    if (isProType(type) && !assuranceRcPro)
      return res.status(400).json({ error: 'L\'attestation d\'assurance RC Pro est requise pour créer un compte professionnel.' });

    const { data: authData, error: authError } = await supabase.auth.admin.createUser({
      email: email.toLowerCase().trim(),
      password: password,
      email_confirm: true
    });
    if (authError) return res.status(400).json({ error: authError.message });

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
      assurance_police: isProType(type) ? assurancePolice : null
    }).select().single();

    if (error) return res.status(400).json({ error: error.message });

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

app.post('/api/auth/forgot-password', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email requis.' });
    await supabase.auth.resetPasswordForEmail(email.toLowerCase().trim(), {
      redirectTo: 'https://niakate1.github.io/Gleam/public/'
    });
    res.json({ message: 'Email de réinitialisation envoyé !' });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  const { data } = await supabase.from('users').select('*').eq('id', req.user.id).single();
  if (!data) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  res.json({ ...data, firstName: data.prenom, lastName: data.nom });
});

// ══════════════ DEMANDES ══════════════

app.post('/api/demandes', auth, async (req, res) => {
  try {
    const { type, prestations, address, date, time, flexibility, description, details, photos } = req.body;
    if (!address) return res.status(400).json({ error: 'Adresse requise.' });
    if (photos && Array.isArray(photos)) {
      if (photos.length > 5) return res.status(400).json({ error: 'Maximum 5 photos par demande.' });
      for (const p of photos) {
        if (typeof p === 'string' && p.length > 3 * 1024 * 1024) {
          return res.status(400).json({ error: 'Une photo est trop volumineuse. Réessayez avec une photo plus légère.' });
        }
      }
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

app.get('/api/demandes', auth, async (req, res) => {
  const { data } = await supabase.from('demandes').select('*').eq('client_id', req.user.id).order('created_at', { ascending: false });
  res.json(data || []);
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

    const { data: mesDevis } = await supabase.from('devis').select('demande_id, statut').eq('societe_id', req.user.id);
    const idsRepondues = new Set((mesDevis || []).filter(d => d.statut === 'envoye' || d.statut === 'accepte').map(d => d.demande_id));
    let filtered = (demandes || []).filter(d => !idsRepondues.has(d.id));

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

    res.json(filtered);
  } catch (e) {
    console.error('Erreur /api/demandes/all:', e);
    res.status(500).json({ error: 'Erreur serveur: ' + e.message });
  }
});

app.get('/api/demandes/:id', auth, async (req, res) => {
  const { data } = await supabase.from('demandes').select('*').eq('id', req.params.id).single();
  if (!data) return res.status(404).json({ error: 'Demande introuvable.' });
  res.json(data);
});

// Modifier une demande (uniquement si aucun devis n'a été accepté)
app.patch('/api/demandes/:id', auth, async (req, res) => {
  try {
    const { data: demande } = await supabase.from('demandes').select('*').eq('id', req.params.id).single();
    if (!demande) return res.status(404).json({ error: 'Demande introuvable.' });
    if (demande.client_id !== req.user.id) return res.status(403).json({ error: 'Accès refusé.' });
    if (demande.statut === 'acceptee' || demande.statut === 'terminee')
      return res.status(400).json({ error: 'Impossible de modifier : un devis a déjà été accepté pour cette demande.' });

    const { prestations, address, date, time, flexibility } = req.body;
    if (!address) return res.status(400).json({ error: 'Adresse requise.' });

    const creneau = date && time ? date + ' à ' + time : demande.creneau;
    const listePrestations = prestations && Array.isArray(prestations) && prestations.length ? prestations : null;

    const updateData = { adresse: address, creneau: creneau };
    if (listePrestations) {
      updateData.prestation = listePrestations.map(p => p.type).join(' + ');
      updateData.notes = JSON.stringify({ flexibility: flexibility || '', prestations: listePrestations, modifiee: true });
    }

    const { data, error } = await supabase.from('demandes').update(updateData).eq('id', req.params.id).select().single();
    if (error) return res.status(400).json({ error: error.message });

    await supabase.from('devis').update({ demande_modifiee: true }).eq('demande_id', req.params.id).eq('statut', 'envoye');

    res.json(data);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Supprimer une demande (uniquement si aucun devis n'a été accepté)
app.delete('/api/demandes/:id', auth, async (req, res) => {
  try {
    const { data: demande } = await supabase.from('demandes').select('*').eq('id', req.params.id).single();
    if (!demande) return res.status(404).json({ error: 'Demande introuvable.' });
    if (demande.client_id !== req.user.id) return res.status(403).json({ error: 'Accès refusé.' });
    if (demande.statut === 'acceptee' || demande.statut === 'terminee')
      return res.status(400).json({ error: 'Impossible d\'annuler : un devis a déjà été accepté. Des pénalités peuvent s\'appliquer.' });

    await supabase.from('devis').delete().eq('demande_id', req.params.id);
    await supabase.from('messages').delete().eq('demande_id', req.params.id);
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
    if (demande.statut === 'acceptee' || demande.statut === 'terminee')
      return res.status(400).json({ error: 'Cette demande n\'est plus disponible.' });

    const { data: existing } = await supabase.from('devis').select('id').eq('demande_id', demande_id).eq('societe_id', req.user.id).maybeSingle();
    if (existing) return res.status(400).json({ error: 'Vous avez déjà envoyé un devis pour cette demande.' });

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
  const { data: devis } = await supabase.from('devis').select('*').eq('demande_id', req.params.id).order('prix_ttc', { ascending: true });
  if (!devis || !devis.length) return res.json([]);

  const proIds = [...new Set(devis.map(d => d.societe_id))];
  const { data: pros } = await supabase.from('users').select('id, prenom, nom, note_moyenne, taux_fiabilite').in('id', proIds);
  const proMap = {};
  (pros || []).forEach(p => proMap[p.id] = p);

  const enriched = devis.map(d => ({ ...d, pro: proMap[d.societe_id] || null }));
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

// Tous les devis envoyés par le pro connecté
app.get('/api/devis/mes-devis', auth, async (req, res) => {
  try {
    const { data: devis } = await supabase.from('devis').select('*').eq('societe_id', req.user.id).order('created_at', { ascending: false });
    if (!devis || !devis.length) return res.json([]);

    const demandeIds = [...new Set(devis.map(d => d.demande_id))];
    const { data: demandes } = await supabase.from('demandes').select('id, prestation, adresse, statut, numero_anonyme, client_id').in('id', demandeIds);
    const demandeMap = {};
    (demandes || []).forEach(d => demandeMap[d.id] = d);

    const enriched = devis.map(d => ({ ...d, demande: demandeMap[d.demande_id] || null }));
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

    // Vérifie le délai de 24h avant le créneau
    let penalite = false;
    if (demande.creneau) {
      // creneau format "YYYY-MM-DD à HhMM" -> on extrait juste la date pour estimer le délai
      const dateMatch = demande.creneau.match(/(\d{4}-\d{2}-\d{2})/);
      if (dateMatch) {
        const creneauDate = new Date(dateMatch[1]);
        const maintenant = new Date();
        const heuresRestantes = (creneauDate - maintenant) / (1000 * 60 * 60);
        if (heuresRestantes < 24) penalite = true;
      }
    }

    if (penalite) {
      return res.status(400).json({ error: 'Annulation impossible : le créneau est dans moins de 24h. Contactez le support si vous avez un empêchement majeur.' });
    }

    // Annule le devis et remet la demande disponible pour d'autres pros
    await supabase.from('devis').update({ statut: 'annule_pro' }).eq('id', req.params.id);
    await supabase.from('demandes').update({ statut: 'devis_recus' }).eq('id', devis.demande_id);

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

    res.json({ message: 'Devis annulé. Le client a été notifié et peut recevoir d\'autres devis.' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// ══════════════ MESSAGES ══════════════

app.post('/api/messages', auth, async (req, res) => {
  try {
    const { demande_id, contenu } = req.body;
    if (!demande_id || !contenu || !contenu.trim())
      return res.status(400).json({ error: 'Message vide.' });
    if (BLOCK_REGEX.test(contenu))
      return res.status(400).json({ error: 'Gleam bloque les coordonnées avant paiement.', blocked: true });

    const { data: demande } = await supabase.from('demandes').select('*').eq('id', demande_id).single();
    if (!demande) return res.status(404).json({ error: 'Demande introuvable.' });

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
    const conversations = [];

    for (const d of (demandes || [])) {
      const { data: msgs } = await supabase.from('messages').select('*').eq('demande_id', d.id).order('created_at', { ascending: false }).limit(1);
      const lastMsg = msgs && msgs[0] ? msgs[0] : null;

      let autrePartie = null;
      if (isProType(user?.type)) {
        const { data: client } = await supabase.from('users').select('prenom, nom').eq('id', d.client_id).single();
        autrePartie = client;
      } else {
        const { data: devisAcceptes } = await supabase.from('devis').select('societe_id').eq('demande_id', d.id).eq('statut', 'accepte').maybeSingle();
        if (devisAcceptes) {
          const { data: pro } = await supabase.from('users').select('prenom, nom').eq('id', devisAcceptes.societe_id).single();
          autrePartie = pro;
        }
      }

      conversations.push({
        demande_id: d.id,
        prestation: d.prestation,
        statut: d.statut,
        numero_anonyme: d.numero_anonyme,
        dernier_message: lastMsg ? lastMsg.contenu : null,
        dernier_message_date: lastMsg ? lastMsg.created_at : d.created_at,
        dernier_message_expediteur_id: lastMsg ? lastMsg.expediteur_id : null,
        autre_partie: autrePartie
      });
    }

    conversations.sort((a, b) => new Date(b.dernier_message_date) - new Date(a.dernier_message_date));
    res.json(conversations);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// ══════════════ PAIEMENTS ══════════════

app.post('/api/paiements/intent', auth, async (req, res) => {
  try {
    const { devis_id } = req.body;
    if (!devis_id) return res.status(400).json({ error: 'Devis requis.' });

    const { data: devis } = await supabase.from('devis').select('*').eq('id', devis_id).single();
    if (!devis) return res.status(404).json({ error: 'Devis introuvable.' });

    const montant = Math.round(devis.prix_ttc * 100);
    const commission = Math.round(montant * 0.15); // 15% commission Gleam

    const intent = await stripe.paymentIntents.create({
      amount: montant,
      currency: 'eur',
      metadata: { devis_id: devis_id, gleam: 'true' }
    });

    await supabase.from('paiements').insert({
      demande_id: devis.demande_id,
      devis_id: devis_id,
      client_id: req.user.id,
      societe_id: devis.societe_id,
      montant_ttc: devis.prix_ttc,
      commission: devis.prix_ttc * 0.15,
      montant_societe: devis.prix_ttc * 0.85,
      stripe_payment_intent_id: intent.id,
      statut: 'en_attente'
    });

    res.json({ client_secret: intent.client_secret, publishable_key: process.env.STRIPE_PUBLISHABLE_KEY });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/paiements/confirmer', auth, async (req, res) => {
  try {
    const { payment_intent_id } = req.body;
    const intent = await stripe.paymentIntents.retrieve(payment_intent_id);
    if (intent.status !== 'succeeded')
      return res.status(400).json({ error: 'Paiement non confirmé par Stripe.' });

    await supabase.from('paiements').update({ statut: 'paye' }).eq('stripe_payment_intent_id', payment_intent_id);
    const { data: paiement } = await supabase.from('paiements').select('*').eq('stripe_payment_intent_id', payment_intent_id).single();

    if (paiement) {
      await supabase.from('demandes').update({ statut: 'en_cours' }).eq('id', paiement.demande_id);

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
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/paiements/liberer', auth, async (req, res) => {
  try {
    const { paiement_id, demande_id } = req.body;
    let paiement;

    if(paiement_id){
      const { data } = await supabase.from('paiements').select('*').eq('id', paiement_id).single();
      paiement = data;
    } else if(demande_id){
      const { data } = await supabase.from('paiements').select('*').eq('demande_id', demande_id).eq('statut', 'paye').single();
      paiement = data;
    }

    if (!paiement) return res.status(404).json({ error: 'Paiement introuvable.' });
    if (paiement.client_id !== req.user.id) return res.status(403).json({ error: 'Accès refusé.' });

    await supabase.from('paiements').update({ statut: 'libere' }).eq('id', paiement.id);
    await supabase.from('demandes').update({ statut: 'terminee' }).eq('id', paiement.demande_id);

    // 📧 Email "prestation confirmée" désactivé pour l'instant (redondant avec l'app).
    // Pour le réactiver, décommentez le bloc ci-dessous :
    // const { data: demandeInfo } = await supabase.from('demandes').select('prestation').eq('id', paiement.demande_id).single();
    // const { data: client } = await supabase.from('users').select('email, prenom').eq('id', paiement.client_id).single();
    // const { data: pro } = await supabase.from('users').select('email, prenom').eq('id', paiement.societe_id).single();
    // if (client) {
    //   sendEmail('prestation_confirmee', client.email, {
    //     prenom: client.prenom, role: 'client', prestation: demandeInfo ? demandeInfo.prestation : '', demandeId: paiement.demande_id
    //   });
    // }
    // if (pro) {
    //   sendEmail('prestation_confirmee', pro.email, {
    //     prenom: pro.prenom, role: 'pro', prestation: demandeInfo ? demandeInfo.prestation : '', montantPro: paiement.montant_societe, demandeId: paiement.demande_id
    //   });
    // }

    res.json({ message: 'Paiement Gleam libéré ✨' });
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

    const { data } = await supabase.from('evaluations').insert({
      demande_id: demande_id,
      evaluateur_id: req.user.id,
      evalue_id: evalue_id,
      note: parseInt(note),
      commentaire: commentaire || null
    }).select().single();

    const { data: notes } = await supabase.from('evaluations').select('note').eq('evalue_id', evalue_id);
    const moyenne = notes.reduce(function(a, b) { return a + b.note; }, 0) / notes.length;
    await supabase.from('users').update({ note_moyenne: Math.round(moyenne * 10) / 10 }).eq('id', evalue_id);

    res.status(201).json(data);
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
    const { data: user } = await supabase.from('users').select('type, tarifs_base, prestations_proposees').eq('id', req.user.id).single();
    if (!user || !isProType(user.type)) return res.status(403).json({ error: 'Accès réservé aux professionnels.' });
    res.json({ tarifs: user.tarifs_base || {}, prestations: user.prestations_proposees || [] });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Le pro met à jour ses tarifs de base et les prestations qu'il propose réellement
app.patch('/api/societes/tarifs', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('type').eq('id', req.user.id).single();
    if (!user || !isProType(user.type)) return res.status(403).json({ error: 'Accès réservé aux professionnels.' });

    const categoriesValides = Object.keys(DEFAULT_TARIFS);
    const prestationsRecues = Array.isArray(req.body.prestations) ? req.body.prestations : [];
    const prestationsPropres = prestationsRecues.filter(p => categoriesValides.includes(p));

    const tarifsRecus = req.body.tarifs || {};
    const tarifsPropres = {};
    for (const cat of categoriesValides) {
      const val = tarifsRecus[cat];
      if (val === undefined || val === null || val === '') continue;
      const num = parseFloat(val);
      if (isNaN(num) || num <= 0) return res.status(400).json({ error: 'Le tarif pour "' + cat + '" doit être un nombre positif.' });
      tarifsPropres[cat] = num;
    }

    const { error } = await supabase.from('users').update({ tarifs_base: tarifsPropres, prestations_proposees: prestationsPropres }).eq('id', req.user.id);
    if (error) return res.status(400).json({ error: error.message });
    res.json({ message: 'Tarifs mis à jour.', tarifs: tarifsPropres, prestations: prestationsPropres });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Le client obtient une estimation de prix avant/après avoir envoyé sa demande
app.get('/api/tarifs/estimation', auth, async (req, res) => {
  try {
    const prestation = req.query.prestation;
    const etat = req.query.etat || 'propre';
    if (!prestation || !DEFAULT_TARIFS.hasOwnProperty(prestation))
      return res.status(400).json({ error: 'Prestation inconnue.' });
    const coef = ETAT_COEF[etat] || 1.0;

    const { data: pros } = await supabase.from('users').select('tarifs_base').eq('type', 'pro').eq('disponible', true);
    const prixDeclares = (pros || [])
      .map(p => p.tarifs_base && p.tarifs_base[prestation])
      .filter(v => typeof v === 'number' && v > 0);

    let base;
    if (prixDeclares.length) {
      base = prixDeclares.reduce((a, b) => a + b, 0) / prixDeclares.length;
    } else {
      base = DEFAULT_TARIFS[prestation];
    }

    const prixMoyen = Math.round(base * coef);
    const prixMin = Math.round(prixMoyen * 0.85);
    const prixMax = Math.round(prixMoyen * 1.15);

    res.json({
      prestation, etat, prix_min: prixMin, prix_max: prixMax, prix_moyen: prixMoyen,
      base_sur_donnees_reelles: prixDeclares.length > 0,
      nombre_pros_reference: prixDeclares.length
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
