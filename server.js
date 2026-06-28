require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();

// ── Connexion Supabase ────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── Sécurité ─────────────────────────────────────────────
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));

// Webhook Stripe AVANT express.json (besoin du raw body)
app.post(
  '/webhooks/stripe',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (e) {
      return res.status(400).send('Webhook Error: ' + e.message);
    }
    if (event.type === 'payment_intent.succeeded') {
      const pi = event.data.object;
      await supabase
        .from('paiements')
        .update({ statut: 'bloque' })
        .eq('stripe_payment_intent_id', pi.id);
    }
    res.json({ received: true });
  }
);

app.use(express.json({ limit: '10mb' }));

// ── Rate limiting ─────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Trop de requêtes, réessayez dans 15 minutes.' }
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Trop de tentatives. Compte bloqué 15 minutes.' }
});
app.use('/api/', globalLimiter);

// ── Middleware auth ───────────────────────────────────────
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Non autorisé' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide ou expiré' });
  }
};

// Blocage coordonnées dans le chat
const BLOCK_REGEX = /(\b0[67]\d{8}\b|\b\+33[67][\d\s]{8,}\b|[\w.+-]+@[\w-]+\.[a-z]{2,}|whatsapp|telegram|instagram|signal|snapchat)/i;

// ── SANTÉ ─────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    app: 'Gleam API',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// ════════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════════

// Inscription
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { email, password, prenom, nom, telephone, type } = req.body;

    // Validations
    if (!email || !password || !prenom || !nom || !type)
      return res.status(400).json({ error: 'Tous les champs sont requis.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'Email invalide.' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Mot de passe : 8 caractères minimum.' });
    if (!['client', 'societe'].includes(type))
      return res.status(400).json({ error: 'Type invalide.' });

    // Créer dans Supabase Auth
    const { data: authData, error: authError } = await supabase.auth.admin.createUser({
      email: email.toLowerCase().trim(),
      password,
      email_confirm: false
    });
    if (authError) return res.status(400).json({ error: authError.message });

    // Créer dans notre table users
    const { data, error } = await supabase.from('users').insert({
      id: authData.user.id,
      email: email.toLowerCase().trim(),
      prenom: prenom.trim(),
      nom: nom.trim(),
      telephone: telephone || null,
      type
    }).select().single();

    if (error) return res.status(400).json({ error: error.message });

    res.status(201).json({
      message: 'Compte Gleam créé avec succès !',
      user: { id: data.id, email: data.email, prenom: data.prenom, type: data.type }
    });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Connexion
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email et mot de passe requis.' });

    const { data, error } = await supabase.auth.signInWithPassword({
      email: email.toLowerCase().trim(),
      password
    });
    if (error) return res.status(401).json({ error: 'Identifiants incorrects.' });

    const { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('id', data.user.id)
      .single();

    const token = jwt.sign(
      { id: user.id, email: user.email, type: user.type },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        prenom: user.prenom,
        nom: user.nom,
        type: user.type,
        note_moyenne: user.note_moyenne
      }
    });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Mon profil
app.get('/api/auth/me', auth, async (req, res) => {
  const { data } = await supabase
    .from('users')
    .select('id, email, prenom, nom, type, note_moyenne, disponible, created_at')
    .eq('id', req.user.id)
    .single();
  res.json(data);
});

// ════════════════════════════════════════════════════════════
// DEMANDES
// ════════════════════════════════════════════════════════════

// Créer une demande
app.post('/api/demandes', auth, async (req, res) => {
  try {
    const { prestation, adresse, creneau, notes } = req.body;
    if (!prestation || !adresse)
      return res.status(400).json({ error: 'Prestation et adresse requis.' });

    const numero = 'Client #' + Math.floor(1000 + Math.random() * 9000);

    const { data, error } = await supabase.from('demandes').insert({
      client_id: req.user.id,
      prestation: prestation.trim(),
      adresse: adresse.trim(),
      creneau: creneau || null,
      notes: notes || null,
      numero_anonyme: numero,
      statut: 'en_attente'
    }).select().single();

    if (error) return res.status(400).json({ error: error.message });
    res.status(201).json(data);
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Mes demandes (client)
app.get('/api/demandes', auth, async (req, res) => {
  const { data } = await supabase
    .from('demandes')
    .select('*, devis(id, prix_ttc, statut, societe_id)')
    .eq('client_id', req.user.id)
    .order('created_at', { ascending: false });
  res.json(data || []);
});

// Détail d'une demande
app.get('/api/demandes/:id', auth, async (req, res) => {
  const { data } = await supabase
    .from('demandes')
    .select('*, devis(*), paiements(*)')
    .eq('id', req.params.id)
    .single();

  if (!data) return res.status(404).json({ error: 'Demande introuvable.' });
  // Vérification propriété (IDOR protection)
  if (data.client_id !== req.user.id)
    return res.status(403).json({ error: 'Accès refusé.' });

  res.json(data);
});

// Annuler une demande
app.patch('/api/demandes/:id/annuler', auth, async (req, res) => {
  const { data } = await supabase
    .from('demandes').select('client_id, statut').eq('id', req.params.id).single();
  if (!data) return res.status(404).json({ error: 'Introuvable.' });
  if (data.client_id !== req.user.id)
    return res.status(403).json({ error: 'Accès refusé.' });
  if (data.statut === 'confirmee')
    return res.status(400).json({ error: 'Impossible d\'annuler une demande confirmée.' });

  await supabase.from('demandes').update({ statut: 'annulee' }).eq('id', req.params.id);
  res.json({ message: 'Demande annulée.' });
});

// ════════════════════════════════════════════════════════════
// DEVIS
// ════════════════════════════════════════════════════════════

// Envoyer un devis (société)
app.post('/api/devis', auth, async (req, res) => {
  try {
    if (req.user.type !== 'societe')
      return res.status(403).json({ error: 'Réservé aux sociétés.' });

    const { demande_id, prix_ttc, description, creneau_propose } = req.body;
    if (!demande_id || !prix_ttc)
      return res.status(400).json({ error: 'Demande et prix requis.' });
    if (prix_ttc <= 0 || prix_ttc > 10000)
      return res.status(400).json({ error: 'Prix invalide.' });

    const { data, error } = await supabase.from('devis').insert({
      demande_id,
      societe_id: req.user.id,
      prix_ttc: parseFloat(prix_ttc),
      description: description?.trim() || null,
      creneau_propose: creneau_propose || null,
      statut: 'envoye'
    }).select().single();

    if (error) return res.status(400).json({ error: error.message });

    // Mettre à jour statut de la demande
    await supabase.from('demandes')
      .update({ statut: 'devis_recus' })
      .eq('id', demande_id);

    res.status(201).json(data);
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Devis d'une demande (client)
app.get('/api/devis/demande/:id', auth, async (req, res) => {
  const { data } = await supabase
    .from('devis')
    .select('*, societe:societe_id(prenom, nom, note_moyenne, disponible)')
    .eq('demande_id', req.params.id)
    .order('prix_ttc', { ascending: true });
  res.json(data || []);
});

// Mes devis envoyés (société)
app.get('/api/devis/societe', auth, async (req, res) => {
  if (req.user.type !== 'societe')
    return res.status(403).json({ error: 'Réservé aux sociétés.' });
  const { data } = await supabase
    .from('devis')
    .select('*, demande:demande_id(prestation, adresse, creneau, numero_anonyme)')
    .eq('societe_id', req.user.id)
    .order('created_at', { ascending: false });
  res.json(data || []);
});

// Accepter un devis
app.patch('/api/devis/:id/accepter', auth, async (req, res) => {
  const { data: devis } = await supabase
    .from('devis').select('*, demande:demande_id(client_id)').eq('id', req.params.id).single();
  if (!devis) return res.status(404).json({ error: 'Devis introuvable.' });
  if (devis.demande.client_id !== req.user.id)
    return res.status(403).json({ error: 'Accès refusé.' });

  await supabase.from('devis').update({ statut: 'accepte' }).eq('id', req.params.id);
  res.json({ message: 'Devis accepté.' });
});

// ════════════════════════════════════════════════════════════
// MESSAGES (Chat sécurisé)
// ════════════════════════════════════════════════════════════

// Envoyer un message
app.post('/api/messages', auth, async (req, res) => {
  try {
    const { demande_id, contenu } = req.body;
    if (!demande_id || !contenu?.trim())
      return res.status(400).json({ error: 'Message vide.' });
    if (contenu.length > 500)
      return res.status(400).json({ error: 'Message trop long (500 max).' });

    // Blocage coordonnées personnelles
    if (BLOCK_REGEX.test(contenu)) {
      return res.status(400).json({
        error: 'Gleam bloque les coordonnées personnelles avant paiement.',
        blocked: true
      });
    }

    const { data, error } = await supabase.from('messages').insert({
      demande_id,
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

// Historique messages d'une demande
app.get('/api/messages/:demande_id', auth, async (req, res) => {
  const { data } = await supabase
    .from('messages')
    .select('*, expediteur:expediteur_id(prenom, type)')
    .eq('demande_id', req.params.demande_id)
    .order('created_at', { ascending: true });
  res.json(data || []);
});

// ════════════════════════════════════════════════════════════
// PAIEMENTS (Stripe)
// ════════════════════════════════════════════════════════════

// Créer un PaymentIntent
app.post('/api/paiements/intent', auth, async (req, res) => {
  try {
    const { devis_id } = req.body;
    if (!devis_id) return res.status(400).json({ error: 'Devis requis.' });

    const { data: devis } = await supabase
      .from('devis')
      .select('*, demande:demande_id(*)')
      .eq('id', devis_id)
      .single();

    if (!devis) return res.status(404).json({ error: 'Devis introuvable.' });

    const montant = Math.round(devis.prix_ttc * 100); // en centimes
    const commission = Math.round(montant * 0.25);    // 25% Gleam

    const intent = await stripe.paymentIntents.create({
      amount: montant,
      currency: 'eur',
      application_fee_amount: commission,
      metadata: {
        devis_id,
        demande_id: devis.demande_id,
        gleam: 'true'
      }
    });

    // Enregistrer en base
    await supabase.from('paiements').insert({
      demande_id: devis.demande_id,
      devis_id,
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
    console.error('Payment intent error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Libérer le paiement (après prestation validée)
app.post('/api/paiements/liberer', auth, async (req, res) => {
  try {
    const { paiement_id } = req.body;
    const { data: paiement } = await supabase
      .from('paiements').select('*').eq('id', paiement_id).single();

    if (!paiement) return res.status(404).json({ error: 'Paiement introuvable.' });
    if (paiement.client_id !== req.user.id)
      return res.status(403).json({ error: 'Accès refusé.' });
    if (paiement.statut !== 'bloque')
      return res.status(400).json({ error: 'Paiement non bloqué.' });

    // Mettre à jour statuts
    await supabase.from('paiements')
      .update({ statut: 'libere' }).eq('id', paiement_id);
    await supabase.from('demandes')
      .update({ statut: 'terminee' }).eq('id', paiement.demande_id);

    res.json({ message: 'Paiement Gleam libéré ✨' });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Historique paiements
app.get('/api/paiements', auth, async (req, res) => {
  const field = req.user.type === 'client' ? 'client_id' : 'societe_id';
  const { data } = await supabase
    .from('paiements')
    .select('*, demande:demande_id(prestation, adresse)')
    .eq(field, req.user.id)
    .order('created_at', { ascending: false });
  res.json(data || []);
});

// ════════════════════════════════════════════════════════════
// ÉVALUATIONS
// ════════════════════════════════════════════════════════════

app.post('/api/evaluations', auth, async (req, res) => {
  try {
    const { demande_id, evalue_id, note, commentaire } = req.body;
    if (!demande_id || !evalue_id || !note)
      return res.status(400).json({ error: 'Champs manquants.' });
    if (note < 1 || note > 5)
      return res.status(400).json({ error: 'Note entre 1 et 5.' });

    const { data } = await supabase.from('evaluations').insert({
      demande_id,
      evaluateur_id: req.user.id,
      evalue_id,
      note: parseInt(note),
      commentaire: commentaire?.trim() || null
    }).select().single();

    // Recalculer la moyenne
    const { data: notes } = await supabase
      .from('evaluations').select('note').eq('evalue_id', evalue_id);
    const moyenne = notes.reduce((a, b) => a + b.note, 0) / notes.length;
    await supabase.from('users')
      .update({ note_moyenne: Math.round(moyenne * 10) / 10 })
      .eq('id', evalue_id);

    res.status(201).json(data);
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// ════════════════════════════════════════════════════════════
// SOCIÉTÉS
// ════════════════════════════════════════════════════════════

// Sociétés disponibles
app.get('/api/societes', auth, async (req, res) => {
  const { data } = await supabase
    .from('users')
    .select('id, prenom, nom, note_moyenne, disponible')
    .eq('type', 'societe')
    .eq('disponible', true)
    .order('note_moyenne', { ascending: false });
  res.json(data || []);
});

// Toggle disponibilité (société)
app.patch('/api/societes/disponibilite', auth, async (req, res) => {
  if (req.user.type !== 'societe')
    return res.status(403).json({ error: 'Réservé aux sociétés.' });
  const { disponible } = req.body;
  await supabase.from('users')
    .update({ disponible: Boolean(disponible) }).eq('id', req.user.id);
  res.json({ message: 'Disponibilité mise à jour.' });
});

// ════════════════════════════════════════════════════════════
// DÉMARRAGE
// ════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✨ Gleam API démarrée sur le port ${PORT}`);
  console.log(`   Environnement : ${process.env.NODE_ENV || 'development'}`);
});
