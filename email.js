/**
 * Gleam — Service d'emails transactionnels via SendGrid
 * -------------------------------------------------------
 * Variables d'environnement requises (Railway) :
 *   SENDGRID_API_KEY = clé API SendGrid
 *   FROM_EMAIL        = noreply@gleam-app.fr
 *
 * Installation :
 *   npm install @sendgrid/mail
 *
 * Usage dans server.js :
 *   const { sendEmail } = require('./email');
 *   await sendEmail('nouvelle_demande', pro.email, { prenom: pro.prenom, prestation: 'Canapé', ville: 'Paris' });
 */

const sgMail = require('@sendgrid/mail');

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const FROM_EMAIL = process.env.FROM_EMAIL || 'noreply@gleam-app.fr';
const FROM_NAME = 'Gleam';
const APP_URL = process.env.FRONTEND_URL || 'https://gleam-app.fr/';

// ---------------------------------------------------------------------------
// Gabarit HTML commun (header / footer identiques pour tous les emails)
// ---------------------------------------------------------------------------

function wrapTemplate({ title, body, ctaLabel, ctaUrl }) {
  return `
  <div style="font-family: Arial, Helvetica, sans-serif; max-width: 560px; margin: 0 auto; background: #ffffff;">
    <div style="background: #0f766e; padding: 24px; text-align: center;">
      <h1 style="color: #ffffff; margin: 0; font-size: 22px; letter-spacing: 1px;">Gleam</h1>
    </div>
    <div style="padding: 32px 28px; color: #1f2937; font-size: 15px; line-height: 1.6;">
      <h2 style="font-size: 18px; color: #0f766e; margin-top: 0;">${title}</h2>
      ${body}
      ${
        ctaUrl
          ? `<div style="text-align:center; margin-top: 28px;">
               <a href="${ctaUrl}" style="background:#0f766e; color:#ffffff; text-decoration:none; padding: 12px 28px; border-radius: 6px; font-weight: bold; display:inline-block;">
                 ${ctaLabel}
               </a>
             </div>`
          : ''
      }
    </div>
    <div style="background:#f3f4f6; padding:16px; text-align:center; font-size:12px; color:#6b7280;">
      Gleam · gleam-app.fr · Cet email a été envoyé automatiquement, merci de ne pas y répondre.
    </div>
  </div>`;
}

// ---------------------------------------------------------------------------
// Les 8 templates métier
// ---------------------------------------------------------------------------

const templates = {
  // 1. Nouvelle demande → Pros disponibles
  nouvelle_demande: (d) => ({
    subject: `Nouvelle demande disponible : ${d.prestation}`,
    html: wrapTemplate({
      title: `Bonjour ${d.prenom},`,
      body: `<p>Une nouvelle demande vient d'être publiée près de chez vous.</p>
             <p><strong>Prestation :</strong> ${d.prestation}<br/>
                <strong>Ville :</strong> ${d.ville || 'Non précisée'}</p>
             <p>Connectez-vous pour envoyer votre devis avant les autres prestataires.</p>`,
      ctaLabel: 'Voir la demande',
      ctaUrl: `${APP_URL}#demandes-disponibles`,
    }),
  }),

  // 2. Nouveau devis reçu → Client
  nouveau_devis: (d) => ({
    subject: `Vous avez reçu un nouveau devis`,
    html: wrapTemplate({
      title: `Bonjour ${d.prenom},`,
      body: `<p>Un prestataire vient de répondre à votre demande <strong>${d.prestation}</strong>.</p>
             <p><strong>Prix proposé :</strong> ${d.prix} €</p>
             <p>Consultez le détail et acceptez ou refusez ce devis depuis votre espace.</p>`,
      ctaLabel: 'Voir le devis',
      ctaUrl: `${APP_URL}#demande-${d.demandeId}`,
    }),
  }),

  // 3. Devis accepté → Pro
  devis_accepte: (d) => ({
    subject: `Votre devis a été accepté 🎉`,
    html: wrapTemplate({
      title: `Bonjour ${d.prenom},`,
      body: `<p>Bonne nouvelle : votre devis pour <strong>${d.prestation}</strong> a été accepté par le client.</p>
             <p><strong>Créneau :</strong> ${d.creneau}</p>
             <p>Le paiement du client est en attente. Vous serez notifié dès qu'il sera confirmé.</p>`,
      ctaLabel: 'Voir la demande',
      ctaUrl: `${APP_URL}#demande-${d.demandeId}`,
    }),
  }),

  // 4. Devis refusé → Pro
  devis_refuse: (d) => ({
    subject: `Votre devis n'a pas été retenu`,
    html: wrapTemplate({
      title: `Bonjour ${d.prenom},`,
      body: `<p>Le client a choisi un autre prestataire pour la demande <strong>${d.prestation}</strong>.</p>
             <p>D'autres demandes sont disponibles dès maintenant sur votre tableau de bord.</p>`,
      ctaLabel: 'Voir les demandes disponibles',
      ctaUrl: `${APP_URL}#demandes-disponibles`,
    }),
  }),

  // 5. Paiement confirmé → Pro (montant net après commission)
  paiement_confirme: (d) => ({
    subject: `Paiement confirmé : ${d.montantPro} € vous seront versés`,
    html: wrapTemplate({
      title: `Bonjour ${d.prenom},`,
      body: `<p>Le client a payé la prestation <strong>${d.prestation}</strong>.</p>
             <p><strong>Montant total :</strong> ${d.montantTotal} €<br/>
                <strong>Commission Gleam (15%) :</strong> ${d.commission} €<br/>
                <strong>Vous recevrez :</strong> ${d.montantPro} €</p>
             <p>Le versement est libéré une fois la prestation confirmée par le client.</p>`,
      ctaLabel: 'Voir la demande',
      ctaUrl: `${APP_URL}#demande-${d.demandeId}`,
    }),
  }),

  // 6. Prestation confirmée → Client + Pro
  prestation_confirmee: (d) => ({
    subject: `Prestation confirmée : ${d.prestation}`,
    html: wrapTemplate({
      title: `Bonjour ${d.prenom},`,
      body: d.role === 'pro'
        ? `<p>Le client a confirmé la bonne réalisation de la prestation <strong>${d.prestation}</strong>.</p>
           <p>Votre paiement de <strong>${d.montantPro} €</strong> a été libéré.</p>
           <p>N'hésitez pas à laisser un avis sur votre expérience.</p>`
        : `<p>Merci d'avoir confirmé la prestation <strong>${d.prestation}</strong>.</p>
           <p>Nous espérons que tout s'est bien passé ! Pensez à noter votre prestataire.</p>`,
      ctaLabel: 'Laisser un avis',
      ctaUrl: `${APP_URL}#demande-${d.demandeId}`,
    }),
  }),

  // 7. Annulation pro → Client
  annulation_pro: (d) => ({
    subject: `Votre prestataire a annulé la prestation`,
    html: wrapTemplate({
      title: `Bonjour ${d.prenom},`,
      body: `<p>Le prestataire a annulé la prestation <strong>${d.prestation}</strong> prévue le ${d.creneau}.</p>
             <p>Votre demande a été remise à disposition des autres prestataires. Vous recevrez de nouveaux devis prochainement.</p>`,
      ctaLabel: 'Voir ma demande',
      ctaUrl: `${APP_URL}#demande-${d.demandeId}`,
    }),
  }),

  // Suspension de compte pro suite à des annulations répétées d'un devis déjà accepté
  compte_suspendu: (d) => ({
    subject: `Votre compte Gleam a été suspendu`,
    html: wrapTemplate({
      title: `Bonjour ${d.prenom},`,
      body: `<p>Suite à plusieurs annulations de prestations déjà acceptées, votre compte professionnel Gleam a été temporairement suspendu.</p>
             <p>Vous ne pouvez plus recevoir de nouvelles demandes pour l'instant. Pour être réactivé, merci de contacter le support Gleam.</p>`,
      ctaLabel: 'Contacter le support',
      ctaUrl: `${APP_URL}#aide`,
    }),
  }),

  // Notification immédiate à l'équipe Gleam dès qu'un signalement ou une demande de contact
  // est soumis — sans email, un signalement resterait invisible tant que personne n'irait
  // consulter la base manuellement.
  nouveau_signalement: (d) => ({
    subject: `🚩 Nouveau signalement Gleam — ${d.motif}`,
    html: wrapTemplate({
      title: `Nouveau signalement reçu`,
      body: `<p><strong>De :</strong> ${d.reporterNom}</p>
             <p><strong>Concernant :</strong> ${d.signaleNom}</p>
             <p><strong>Motif :</strong> ${d.motif}</p>
             <p><strong>Description :</strong><br>${d.description}</p>
             <p style="background:#F5F3FF;border-radius:8px;padding:12px"><strong>🔍 Preuves disponibles :</strong><br>${d.preuves}</p>
             <p style="font-size:12px;color:#6B7280">Identifiant du signalement : ${d.signalementId}</p>`,
    }),
  }),

  // Code de réinitialisation du mot de passe — un code à saisir directement dans l'app, plutôt
  // qu'un lien dont le format s'est révélé peu fiable à gérer côté navigateur.
  // Notifie le client qu'une nouvelle occurrence de sa prestation récurrente a été programmée
  // automatiquement — il peut la modifier ou l'annuler comme n'importe quelle autre demande.
  prochaine_prestation_recurrente: (d) => ({
    subject: `Votre prochaine prestation récurrente est programmée`,
    html: wrapTemplate({
      title: `Bonjour ${d.prenom},`,
      body: `<p>Votre prestation récurrente (${d.prestation}) a bien été réalisée — la prochaine est déjà programmée automatiquement :</p>
             <p style="font-size:18px;font-weight:700;color:#7C3AED;text-align:center;margin:20px 0">${d.date} à ${d.heure}</p>
             <p>Vous pouvez la modifier, la mettre en pause, ou l'annuler à tout moment depuis l'application.</p>`,
    }),
  }),

  reinitialisation_mot_de_passe: (d) => ({
    subject: `Votre code de réinitialisation Gleam`,
    html: wrapTemplate({
      title: `Bonjour ${d.prenom},`,
      body: `<p>Voici votre code pour choisir un nouveau mot de passe :</p>
             <p style="font-size:32px;font-weight:800;letter-spacing:4px;color:#7C3AED;text-align:center;margin:20px 0">${d.code}</p>
             <p>Ce code est valable 30 minutes. Si vous n'êtes pas à l'origine de cette demande, ignorez simplement cet email.</p>`,
    }),
  }),

  // Confirmation d'email à l'inscription — envoyé automatiquement, sans jamais bloquer l'accès à
  // l'application en attendant : l'utilisateur peut confirmer à son rythme depuis son profil.
  verification_email: (d) => ({
    subject: `Confirmez votre adresse email Gleam`,
    html: wrapTemplate({
      title: `Bienvenue ${d.prenom} !`,
      body: `<p>Merci de vous être inscrit sur Gleam. Voici votre code pour confirmer votre adresse email :</p>
             <p style="font-size:32px;font-weight:800;letter-spacing:4px;color:#7C3AED;text-align:center;margin:20px 0">${d.code}</p>
             <p>Ce code est valable 24 heures. Vous pouvez le saisir depuis votre profil, dans la rubrique "Confirmer mon email" — pas d'urgence, vous pouvez continuer à utiliser Gleam normalement en attendant.</p>`,
    }),
  }),

  // 7bis. Annulation client → Pro (après acceptation du devis)
  annulation_client: (d) => ({
    subject: `Le client a annulé la prestation`,
    html: wrapTemplate({
      title: `Bonjour ${d.prenom},`,
      body: `<p>Le client a annulé la prestation <strong>${d.prestation}</strong>${d.creneau ? ` prévue le ${d.creneau}` : ''}.</p>
             ${d.tardive ? `<p style="color:#D97706;"><strong>Annulation tardive</strong> (moins de 24h avant le créneau prévu).</p>` : ''}
             <p>Vous n'avez plus besoin de vous rendre à ce rendez-vous.</p>`,
      ctaLabel: 'Voir mes devis',
      ctaUrl: `${APP_URL}#devis`,
    }),
  }),

  // 8. Nouveau message → Destinataire (client ou pro)
  nouveau_message: (d) => ({
    subject: `Nouveau message concernant ${d.prestation}`,
    html: wrapTemplate({
      title: `Bonjour ${d.prenom},`,
      body: `<p>Vous avez reçu un nouveau message de <strong>${d.expediteurNom}</strong> concernant la prestation <strong>${d.prestation}</strong>.</p>
             <p style="background:#f3f4f6; padding:12px 16px; border-radius:6px; font-style:italic;">
               « ${d.apercu} »
             </p>`,
      ctaLabel: 'Répondre',
      ctaUrl: `${APP_URL}#demande-${d.demandeId}`,
    }),
  }),
};

// ---------------------------------------------------------------------------
// Fonction générique d'envoi
// ---------------------------------------------------------------------------

/**
 * Envoie un email transactionnel.
 * @param {string} type - une des 8 clés de `templates`
 * @param {string} to - email du destinataire
 * @param {object} data - données injectées dans le template
 */
async function sendEmail(type, to, data = {}) {
  const builder = templates[type];
  if (!builder) {
    throw new Error(`Type d'email inconnu : "${type}". Types valides : ${Object.keys(templates).join(', ')}`);
  }

  const { subject, html } = builder(data);

  const msg = {
    to,
    from: { email: FROM_EMAIL, name: FROM_NAME },
    subject,
    html,
  };

  try {
    await sgMail.send(msg);
    console.log(`[email] "${type}" envoyé à ${to}`);
  } catch (err) {
    console.error(`[email] Échec d'envoi "${type}" à ${to} :`, err.response?.body || err.message);
    // On ne bloque jamais le flux principal (paiement, acceptation...) si l'email échoue
  }
}

module.exports = { sendEmail, templates };
