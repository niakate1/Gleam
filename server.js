require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const jwt = require('jsonwebtoken');

const app = express();

// ✅ FIX 1 — Trust proxy (Railway)
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

const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
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

const BLOCK_REGEX = /(\b0[67]\d{8}\b|[\w.+-]+@[\w-]+\.[a-z]{2,}|whatsapp|telegram|instagram)/i;

app.get('/health', (req, res) => {
  res.json({ status: 'ok', app: 'Gleam API', version: '1.0.0', timestamp: new Date().toISOString() });
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    // ✅ FIX 2 — Accepte firstName/lastName ET prenom/nom
    const email = req.body.email;
    const password = req.body.password;
    const prenom = req.body.firstName || req.body.prenom;
    const nom = req.body.lastName || req.body.nom;
    const telephone = req.body.phone || req.body.telephone;
    const type = req.body.role || req.body.type;

    if (!email || !password || !prenom || !nom || !type)
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
      type: type
    }).select().single();

    if (error) return res.status(400).json({ error: error.message });
    res.status(201).json({ message: 'Compte Gleam créé !', user: { ...data, firstName: data.prenom, lastName: data.nom } });
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

    // Si l'utilisateur n'existe pas dans la table users, on le crée
    if (!user) {
      const { data: newUser } = await supabase.from('users').insert({
        id: data.user.id,
        email: data.user.email,
        prenom: data.user.email.split('@')[0],
        nom: '',
        type: 'client'
      }).select().single();
      user = newUser;
    }

    if (!user) return res.status(500).json({ error: 'Utilisateur introuvable.' });

    const token = jwt.sign(
      { id: user.id, email: user.email, type: user.type },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({ token: token, user: { ...user, firstName: user.prenom, lastName: user.nom } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  const { data } = await supabase.from('users').select('*').eq('id', req.user.id).single();
  res.json({ ...data, firstName: data.prenom, lastName: data.nom });
});

app.post('/api/demandes', auth, async (req, res) => {
  try {
    const { type, address, date, time, flexibility, description, details } = req.body;
    if (!address)
      return res.status(400).json({ error: 'Adresse requise.' });

    const numero = 'Client #' + Math.floor(1000 + Math.random() * 9000);
    const creneau = date && time ? date + ' à ' + time : null;
    const notes = JSON.stringify({ description, details, flexibility });

    const { data, error } = await supabase.from('demandes').insert({
      client_id: req.user.id,
      prestation: type || 'autre',
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

app.post('/api/devis', auth, async (req, res) => {
  try {
    const { demande_id, prix_ttc, description, creneau_propose } = req.body;
    if (!demande_id || !prix_ttc)
      return res.status(400).json({ error: 'Demande et prix requis.' });

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

app.get('/api/devis/demande/:id', auth, async (req, res) => {
  const { data } = await supabase.from('devis').select('*').eq('demande_id', req.params.id).order('prix_ttc', { ascending: true });
  res.json(data || []);
});

app.post('/api/messages', auth, async (req, res) => {
  try {
    const { demande_id, contenu } = req.body;
    if (!demande_id || !contenu)
      return res.status(400).json({ error: 'Message vide.' });
    if (BLOCK_REGEX.test(contenu))
      return res.status(400).json({ error: 'Gleam bloque les coordonnées avant paiement.', blocked: true });

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

app.get('/api/societes', auth, async (req, res) => {
  const { data } = await supabase.from('users').select('id, prenom, nom, note_moyenne, disponible').eq('type', 'societe').eq('disponible', true);
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
