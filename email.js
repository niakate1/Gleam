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

// ── LA GOUTTE, EN SVG INLINE ────────────────────────────────────────────────
// Pas une image : Outlook, Gmail et Apple Mail bloquent les images distantes
// tant que le destinataire ne les autorise pas. Un logo en PNG resterait donc
// invisible dans la plupart des boîtes, et le bandeau paraîtrait vide.
//
// Le SVG inline s'affiche sans autorisation et sans requête réseau. Il pèse
// quatre cents octets.
//
// Outlook sur Windows ne le gère pas : il affichera le mot « Gleam » seul, sur
// le bandeau pétrole. La lettre reste lisible, la marque reconnaissable.
const LOGO_EMAIL = `<svg width="26" height="26" viewBox="0 0 100 100" style="vertical-align:middle;margin-right:8px" xmlns="http://www.w3.org/2000/svg">
  <path d="M50 12 C58 26 65 37 68 44 C70 49 71 53 71 57 C71 69 62 78 50 78 C38 78 29 69 29 57 C29 53 30 49 32 44 C35 37 42 26 50 12 Z" fill="#ffffff"/>
  <path d="M50 44 C51 53 52 56 55 58 C52 60 51 63 50 72 C49 63 48 60 45 58 C48 56 49 53 50 44 Z" fill="#0A4750"/>
</svg>`;

// Ajoute le compte destinataire à l'adresse du bouton.
//
// Un lien de courriel ouvre le navigateur, qui restaure la dernière session
// utilisée sur cet appareil. Sur un ordinateur partagé, ce n'est pas forcément
// celle du destinataire — et rien ne le signalait.
//
// L'identifiant n'est pas un secret : il ne donne aucun accès, il sert
// uniquement à comparer. Sans jeton valide, il ne permet rien.
function lienAvecCompte(url, compteId) {
  if (!url || !compteId) return url;
  return url + (url.indexOf('?') >= 0 ? '&' : '?') + 'c=' + encodeURIComponent(compteId);
}

function wrapTemplate({ title, body, ctaLabel, ctaUrl, compteId }) {
  ctaUrl = lienAvecCompte(ctaUrl, compteId);
  return `
  <div style="font-family: Arial, Helvetica, sans-serif; max-width: 560px; margin: 0 auto; background: #ffffff;">
    <!-- Le dégradé reprend celui de l'application. Les clients de messagerie qui
         ne le gèrent pas retombent sur la couleur unie déclarée avant lui. -->
    <div style="background: #0E5A63; background: linear-gradient(160deg, #062E34 0%, #0A4750 62%, #0E5A63 100%); padding: 26px 24px; text-align: center;">
      <h1 style="color: #ffffff; margin: 0; font-size: 22px; letter-spacing: .5px; font-weight: bold;">${LOGO_EMAIL}Gleam</h1>
    </div>
    <div style="padding: 32px 28px; color: #131A1C; font-size: 15px; line-height: 1.6;">
      <h2 style="font-size: 18px; color: #0E5A63; margin-top: 0;">${title}</h2>
      ${body}
      ${
        ctaUrl
          ? `<div style="text-align:center; margin-top: 28px;">
               <a href="${ctaUrl}" style="background:#0E5A63; color:#ffffff; text-decoration:none; padding: 14px 30px; border-radius: 8px; font-weight: bold; display:inline-block;">
                 ${ctaLabel}
               </a>
             </div>`
          : ''
      }
    </div>
    <div style="background:#E9EFEF; padding:18px; text-align:center; font-size:12px; color:#44585C; line-height:1.6;">
      <strong style="color:#0E5A63;">Gleam</strong> · <a href="https://gleam-app.fr" style="color:#44585C;">gleam-app.fr</a><br>
      Message automatique, merci de ne pas y répondre.
    </div>
  </div>`;
}

// ---------------------------------------------------------------------------
// Les gabarits métier
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
      compteId: d.compteId,
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
      compteId: d.compteId,
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
      compteId: d.compteId,
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
      compteId: d.compteId,
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
      compteId: d.compteId,
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
      compteId: d.compteId,
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
      compteId: d.compteId,
      ctaUrl: `${APP_URL}#demande-${d.demandeId}`,
    }),
  }),

  // Le créneau demandé est passé sans qu'aucune prestation n'ait eu lieu. Le
  // client attendait des devis qui ne viendront plus : sans ce message, sa
  // demande disparaît en silence et il n'a aucune raison d'en refaire une.
  //
  // Le message dit la cause, pas seulement le fait. « Votre demande a expiré »
  // laisse croire à un défaut de la plateforme ; « le créneau est passé »
  // explique, et le bouton propose la suite.
  demande_expiree: (d) => ({
    subject: `Votre demande de ${d.prestation} n'a pas trouvé de prestataire`,
    html: wrapTemplate({
      title: `Bonjour ${d.prenom},`,
      body: `<p>Le créneau que vous aviez choisi pour votre demande de <strong>${d.prestation}</strong> — ${d.creneau} — est maintenant passé.</p>
             <p>${d.avaitDevis
               ? `Vous aviez reçu des devis, mais aucun n'a été réglé avant l'heure prévue.`
               : `Aucun prestataire disponible n'a pu répondre à temps sur votre secteur.`}</p>
             <p>Votre demande a été close. Vous pouvez en créer une nouvelle avec une autre date — les mêmes informations vous seront proposées, vous n'aurez qu'à choisir un créneau.</p>`,
      ctaLabel: 'Refaire ma demande',
      compteId: d.compteId,
      ctaUrl: `${APP_URL}#nouvelle-demande`,
    }),
  }),

  // La prestation a été faite, le client n'a jamais donné son code. On l'informe
  // que le paiement est parti — et on lui rappelle qu'il peut encore signaler
  // un problème : la validation solde le paiement, pas le litige.
  prestation_validee_automatiquement: (d) => ({
    subject: `Votre prestation de ${d.prestation} a été validée`,
    html: wrapTemplate({
      title: `Bonjour ${d.prenom},`,
      body: `<p>Votre prestation de <strong>${d.prestation}</strong> a été réalisée il y a plus de 48 heures, sans que le code de validation nous soit transmis.</p>
             <p>Elle a donc été validée automatiquement, et le prestataire a été réglé.</p>
             <p>Si quelque chose ne s'est pas passé comme prévu, vous pouvez encore nous le signaler depuis l'application : nous examinerons la situation.</p>`,
      ctaLabel: 'Voir ma prestation',
      compteId: d.compteId,
      ctaUrl: `${APP_URL}#mes-demandes`,
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
      compteId: d.compteId,
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
             <p style="background:#E3F1F2;border-radius:8px;padding:12px"><strong>🔍 Preuves disponibles :</strong><br>${d.preuves}</p>
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
             <p style="font-size:18px;font-weight:700;color:#0E5A63;text-align:center;margin:20px 0">${d.date} à ${d.heure}</p>
             <p>Vous pouvez la modifier, la mettre en pause, ou l'annuler à tout moment depuis l'application.</p>`,
    }),
  }),

  reinitialisation_mot_de_passe: (d) => ({
    subject: `Votre code de réinitialisation Gleam`,
    html: wrapTemplate({
      title: `Bonjour ${d.prenom},`,
      body: `<p>Voici votre code pour choisir un nouveau mot de passe :</p>
             <p style="font-size:32px;font-weight:800;letter-spacing:4px;color:#0E5A63;text-align:center;margin:20px 0">${d.code}</p>
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
             <p style="font-size:32px;font-weight:800;letter-spacing:4px;color:#0E5A63;text-align:center;margin:20px 0">${d.code}</p>
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
      compteId: d.compteId,
      ctaUrl: `${APP_URL}#devis`,
    }),
  }),

  // Relance aux prestataires de la zone, 24 h après une demande restée sans devis.
  // Distinct de "nouvelle_demande" : le ton change, l'urgence est réelle, et le
  // client attend depuis un jour entier.
  demande_sans_devis_pro: (d) => ({
    subject: `Toujours sans devis : ${d.prestation} à ${d.ville}`,
    html: wrapTemplate({
      title: `Bonjour ${d.prenom},`,
      body: `<p>Une demande publiée il y a 24 heures près de chez vous n'a encore reçu <strong>aucun devis</strong>.</p>
             <p><strong>Prestation :</strong> ${d.prestation}<br/>
                <strong>Ville :</strong> ${d.ville || 'Non précisée'}${d.distance ? `<br/><strong>Distance :</strong> ${d.distance} km` : ''}
                ${d.creneau ? `<br/><strong>Créneau souhaité :</strong> ${d.creneau}` : ''}</p>
             <p>Le client attend. Vous êtes pour l'instant seul à pouvoir y répondre.</p>`,
      ctaLabel: 'Envoyer mon devis',
      compteId: d.compteId,
      ctaUrl: `${APP_URL}#demandes-disponibles`,
    }),
  }),

  // Message au client, 48 h sans devis. Le ton compte particulièrement ici : il
  // s'agit d'expliquer sans se justifier, et de proposer une action concrète
  // plutôt que de laisser la demande mourir en silence.
  demande_sans_devis_client: (d) => ({
    subject: `Votre demande n'a pas encore reçu de devis`,
    html: wrapTemplate({
      title: `Bonjour ${d.prenom},`,
      body: `<p>Votre demande <strong>${d.prestation}</strong> n'a pas encore trouvé de prestataire disponible.</p>
             <p>Cela arrive quand le créneau souhaité est proche, ou quand peu de professionnels
                interviennent encore dans votre secteur.</p>
             <p><strong>Deux choses peuvent aider :</strong></p>
             <ul style="padding-left:18px;margin:8px 0">
               <li>Élargir votre créneau, ou le décaler de quelques jours</li>
               <li>Ajouter des photos : les prestataires répondent plus volontiers à une demande
                   dont ils mesurent précisément le travail</li>
             </ul>
             <p>Votre demande reste active${d.creneau ? ` jusqu'au ${d.creneau}` : ''}. Vous pouvez la
                modifier à tout moment depuis l'application.</p>`,
      ctaLabel: 'Modifier ma demande',
      compteId: d.compteId,
      ctaUrl: `${APP_URL}#demande-${d.demandeId}`,
    }),
  }),

  // 8. Nouveau message → Destinataire (client ou pro)
  nouveau_message: (d) => ({
    subject: `Nouveau message concernant ${d.prestation}`,
    html: wrapTemplate({
      title: `Bonjour ${d.prenom},`,
      body: `<p>Vous avez reçu un nouveau message de <strong>${d.expediteurNom}</strong> concernant la prestation <strong>${d.prestation}</strong>.</p>
             <p style="background:#E9EFEF; padding:12px 16px; border-radius:6px; font-style:italic;">
               « ${d.apercu} »
             </p>`,
      ctaLabel: 'Répondre',
      compteId: d.compteId,
      ctaUrl: `${APP_URL}#demande-${d.demandeId}`,
    }),
  }),
};

// ---------------------------------------------------------------------------
// Fonction générique d'envoi
// ---------------------------------------------------------------------------

/**
 * Envoie un email transactionnel.
 * @param {string} type - une des clés de `templates`
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
