require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const jwt = require('jsonwebtoken');

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

const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });
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
const BLOCK_REGEX = /(\b0[67]\d{8}\b|[\w.+-]+@[\w-]+\.[a-z]{2,}|whatsapp|telegram|instagram)/i;

app.get('/health', (req, res) => {
  res.json({ status: 'ok', app: 'Gleam API', version: '2.0.0', timestamp: new Date().toISOString() });
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

    if (!email || !password || !prenom || !nom)
      return res.status(400).json({ error: 'Tous les champs sont requis.' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Mot de passe : 8 caractères minimum.' });

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
      disponible: true
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

app.get('/api/auth/me', auth, async (req, res) => {
  const { data } = await supabase.from('users').select('*').eq('id', req.user.id).single();
  if (!data) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  res.json({ ...data, firstName: data.prenom, lastName: data.nom });
});

// ══════════════ DEMANDES ══════════════

app.post('/api/demandes', auth, async (req, res) => {
  try {
    const { type, prestations, address, date, time, flexibility, description, details } = req.body;
    if (!address) return res.status(400).json({ error: 'Adresse requise.' });

    const numero = 'Client #' + Math.floor(1000 + Math.random() * 9000);
    const creneau = date && time ? date + ' à ' + time : null;

    // Supporte soit une liste de prestations (nouveau format groupé), soit une seule (ancien format)
    const listePrestations = prestations && Array.isArray(prestations) && prestations.length
      ? prestations
      : [{ type: type || 'autre', description: description || '', details: details || {} }];

    const prestationLabel = listePrestations.map(p => p.type).join(' + ');
    const notes = JSON.stringify({ flexibility: flexibility || '', prestations: listePrestations });

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
    res.status(201).json(data);
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.get('/api/demandes', auth, async (req, res) => {
  const { data } = await supabase.from('demandes').select('*').eq('client_id', req.user.id).order('created_at', { ascending: false });
  res.json(data || []);
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

    // Si la demande avait des devis en attente, on les marque comme "demande modifiée" pour notifier les pros
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

// Demandes disponibles pour les pros (en attente, pas encore acceptées)
app.get('/api/demandes/all', async (req, res) => {
  try {
    const { data: demandes, error: demErr } = await supabase
      .from('demandes')
      .select('*')
      .order('created_at', { ascending: false });
    if (demErr) return res.status(500).json({ error: demErr.message });
    res.json(demandes || []);
  } catch (e) {
    res.status(500).json({ error: e.message });
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
    if (demande.statut !== 'en_attente')
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
    const { data: demandes } = await supabase.from('demandes').select('id, prestation, adresse, statut, numero_anonyme').in('id', demandeIds);
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

    // Recalcule le taux de fiabilité du pro : (acceptés non annulés / acceptés total) * 100
    const { data: tousDevisAcceptes } = await supabase.from('devis').select('statut').eq('societe_id', req.user.id).in('statut', ['accepte', 'annule_pro', 'termine']);
    const totalAcceptes = (tousDevisAcceptes || []).length;
    const totalAnnules = (tousDevisAcceptes || []).filter(d => d.statut === 'annule_pro').length;
    const tauxFiabilite = totalAcceptes > 0 ? Math.round(((totalAcceptes - totalAnnules) / totalAcceptes) * 100) : 100;

    await supabase.from('users').update({ taux_fiabilite: tauxFiabilite }).eq('id', req.user.id);

    let message = 'Devis annulé. Le client a été notifié et peut recevoir d\'autres devis.';
    if (tauxFiabilite < 80) message += ' ⚠️ Votre taux de fiabilité est sous 80% : vos devis seront moins visibles par les clients.';
    else if (tauxFiabilite < 85) message += ' ⚠️ Attention : votre taux de fiabilité a baissé sous 85%.';

    res.json({ message, taux_fiabilite: tauxFiabilite });
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
      const { data: devis } = await supabase.from('devis').select('demande_id').eq('societe_id', req.user.id);
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
    const commission = Math.round(montant * 0.25);

    const intent = await stripe.paymentIntents.create({
      amount: montant,
      currency: 'eur',
      application_fee_amount: commission,
      metadata: { devis_id: devis_id, gleam: 'true' }
    });

    await supabase.from('paiements').insert({
      demande_id: devis.demande_id,
      devis_id: devis_id,
      client_id: req.user.id,
      societe_id: devis.societe_id,
      montant_ttc: devis.prix_ttc,
      commission: devis.prix_ttc * 0.25,
      montant_societe: devis.prix_ttc * 0.75,
      stripe_payment_intent_id: intent.id,
      statut: 'en_attente'
    });

    res.json({ client_secret: intent.client_secret });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/paiements/liberer', auth, async (req, res) => {
  try {
    const { paiement_id } = req.body;
    const { data: paiement } = await supabase.from('paiements').select('*').eq('id', paiement_id).single();
    if (!paiement) return res.status(404).json({ error: 'Paiement introuvable.' });
    if (paiement.client_id !== req.user.id) return res.status(403).json({ error: 'Accès refusé.' });

    await supabase.from('paiements').update({ statut: 'libere' }).eq('id', paiement_id);
    await supabase.from('demandes').update({ statut: 'terminee' }).eq('id', paiement.demande_id);
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log('✨ Gleam API démarrée sur le port ' + PORT);
  console.log('   Environnement : ' + (process.env.NODE_ENV || 'development'));
});
// END FINAL
