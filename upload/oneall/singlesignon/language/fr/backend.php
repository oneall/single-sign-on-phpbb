<?php
/**
 * @package       OneAll Single Sign On
 * @copyright     Copyright 2011-Present http://www.oneall.com
 * @license       GPL-2.0
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,USA.
 *
 * The "GNU General Public License" (GPL) is available at
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 *
 */

/**
 * French translations by Galixte
 * http://www.galixte.com
 */
if (!defined('IN_PHPBB'))
{
    exit();
}

if (empty($lang) || !is_array($lang))
{
    $lang = array();
}

// Single Sign On Backend.
$lang = array_merge($lang, array(
    // The G_ prefix is not a typo but required
    'G_OA_SINGLE_SIGN_ON_REGISTER' => 'Utilisateurs inscrits via OneAll',

    'OA_SINGLE_SIGN_ON_DEFAULT' => 'Défaut',
    'OA_SINGLE_SIGN_ON_VIEW_CREDENTIALS' => '<a href="https://app.oneall.com/applications/" class="button1 external">Créer et/ou consulter les données API</a>',

    'OA_SINGLE_SIGN_ON_ACP' => 'OneAll Single Sign On',
    'OA_SINGLE_SIGN_ON_ACP_SETTINGS' => 'Paramètres',

    'OA_SINGLE_SIGN_ON_API_AUTODETECT' => 'Détecter automatiquement les paramètres de connexion',
    'OA_SINGLE_SIGN_ON_API_VERIFY' => 'Vérifier les paramètres et la connexion à l’API',

    'OA_SINGLE_SIGN_ON_API_CONNECTION' => 'Connexion à l’API',
    'OA_SINGLE_SIGN_ON_API_CONNECTION_HANDLER' => 'Gestionnaires de connexion',
    'OA_SINGLE_SIGN_ON_API_CONNECTION_HANDLER_DESC' => 'Permet de définir comment votre forum va communiquer avec le service d’intégration de OneAll.',

    'OA_SINGLE_SIGN_ON_API_CREDENTIALS_CHECK_COM' => 'Impossible de se connecter à l’API. Est-ce que la connexion à l’API a été configurée correctement ?',
    'OA_SINGLE_SIGN_ON_API_CREDENTIALS_FILL_OUT' => 'Merci de remplir chacun les champs ci-dessus.',
    'OA_SINGLE_SIGN_ON_API_CREDENTIALS_KEYS_WRONG' => 'Les clés de l’API sont incorrectes, merci de vérifier la clé publique et/ou privée.',
    'OA_SINGLE_SIGN_ON_API_CREDENTIALS_OK' => 'Les paramètres sont corrects - Merci de sauvegarder vos changements !',
    'OA_SINGLE_SIGN_ON_API_CREDENTIALS_SUBDOMAIN_WRONG' => 'Le sous-domaine n’existe pas. A-t-il été saisi correctement ?',
    'OA_SINGLE_SIGN_ON_API_CREDENTIALS_TITLE' => 'Données de l’API - <a href="https://app.oneall.com/applications/" class="external">Cliquer ici pour créer et/ou consulter les données de l’API</a>',
    'OA_SINGLE_SIGN_ON_API_CREDENTIALS_UNKNOW_ERROR' => 'Réponse inconnue - Merci de vous assurer que vous êtes toujours connecté !',
    'OA_SINGLE_SIGN_ON_API_CREDENTIALS_USE_AUTO' => 'Le connexion à l’API ne semble pas fonctionner. Merci d’utiliser la détection automatique.',

    'OA_SINGLE_SIGN_ON_API_DETECT_CURL' => 'CURL a été détecté sur le port %s - Merci de sauvegarder vos changements !',
    'OA_SINGLE_SIGN_ON_API_DETECT_FSOCKOPEN' => 'FSOCKOPEN a été détecté sur le port %s - Merci de sauvegarder vos changements !',
    'OA_SINGLE_SIGN_ON_API_DETECT_NONE' => 'La connexion a échoué ! Votre pare-feu doit autoriser les requêtes sortantes sur le port 80 et/ou 443.',

    'OA_SINGLE_SIGN_ON_API_PORT' => 'Port de connexion',
    'OA_SINGLE_SIGN_ON_API_PORT_DESC' => 'Votre pare-feu doit autoriser les requêtes sortantes sur un le port 80 et/ou 443.',

    'OA_SINGLE_SIGN_ON_API_PRIVATE_KEY' => 'Clé privée de l’API',
    'OA_SINGLE_SIGN_ON_API_PUBLIC_KEY' => 'Clé publique de l’API',
    'OA_SINGLE_SIGN_ON_API_SUBDOMAIN' => 'Sous-domaine de l’API',

    'OA_SINGLE_SIGN_ON_CURL' => 'PHP CURL',
    'OA_SINGLE_SIGN_ON_CURL_DESC' => 'L’utilisation de CURL est recommandée. Notez que CURL n’est pas installé et activé sur tous les serveurs.',
    'OA_SINGLE_SIGN_ON_CURL_DOCS' => '<a href="http://www.php.net/manual/en/book.curl.php" class="external">Manuel de CURL</a>',

    'OA_SINGLE_SIGN_ON_DISPLAY_LOC' => 'Emplacements d’affichage de Single Sign On',

    'OA_SINGLE_SIGN_ON_DO_AVATARS' => 'Envoi d’avatars depuis les réseaux sociaux',
    'OA_SINGLE_SIGN_ON_DO_AVATARS_DESC' => 'Permet de récupérer les avatars des utilisateurs sur les réseaux sociaux afin de les stocker dans le dossier des avatars de phpBB.',
    'OA_SINGLE_SIGN_ON_DO_AVATARS_ENABLE_NO' => 'Non, ne pas utiliser les avatars des réseaux sociaux',
    'OA_SINGLE_SIGN_ON_DO_AVATARS_ENABLE_YES' => 'Oui, utiliser les avatars des réseaux sociaux',

    'OA_SINGLE_SIGN_ON_DO_ENABLE' => 'Activer Single Sign On',
    'OA_SINGLE_SIGN_ON_DO_ENABLE_DESC' => 'Permet de temporairement désactiver Single Sign On sans avoir à supprimer l’extension.',
    'OA_SINGLE_SIGN_ON_DO_ENABLE_NO' => 'Désactiver',
    'OA_SINGLE_SIGN_ON_DO_ENABLE_YES' => 'Activer',

    'OA_SINGLE_SIGN_ON_DO_LINKING' => 'Liaison des comptes avec les réseaux sociaux',
    'OA_SINGLE_SIGN_ON_DO_LINKING_ASK' => 'Lier automatiquement les comptes des réseaux sociaux avec les comptes utilisateurs existants',
    'OA_SINGLE_SIGN_ON_DO_LINKING_DESC' => 'Permet de lier les comptes des réseaux sociaux ayant une adresse e-mail vérifiée avec les comptes utilisateurs phpBB existants ayant la même adresse e-mail.',
    'OA_SINGLE_SIGN_ON_DO_LINKING_NO' => 'Désactiver',
    'OA_SINGLE_SIGN_ON_DO_LINKING_YES' => 'Activer la liaison des comptes',

    'OA_SINGLE_SIGN_ON_DO_REDIRECT' => 'Redirection',
    'OA_SINGLE_SIGN_ON_DO_REDIRECT_ASK' => 'Rediriger les utilisateurs vers une page après leur connexion au moyen de leur compte de réseau social',
    'OA_SINGLE_SIGN_ON_DO_REDIRECT_DESC' => 'Permet de saisir l’adresse URL complète d’une page de son forum. Si aucune adresse n’est renseignée l’utilisateur restera sur la même page.',

    'OA_SINGLE_SIGN_ON_DO_VALIDATION' => 'Confirmation du profil aux nouveaux utilisateurs',
    'OA_SINGLE_SIGN_ON_DO_VALIDATION_ALWAYS' => 'Activer la confirmation',
    'OA_SINGLE_SIGN_ON_DO_VALIDATION_ASK' => 'Demander aux nouveaux utilisateurs de vérifier leur nom d’utilisateur et leur adresse e-mail',
    'OA_SINGLE_SIGN_ON_DO_VALIDATION_DEPENDS' => 'Activer la confirmation uniquement si nécessaire',
    'OA_SINGLE_SIGN_ON_DO_VALIDATION_DESC' => 'Permet de demander aux nouveaux utilisateurs de confirmer le nom d’utilisateur généré par l’extension et de vérifier leur adresse e-mail. Autrement, il est possible de demander confirmation uniquement sur la disponibilité du nom d’utilisateur généré ou de l’adresse e-mail.',
    'OA_SINGLE_SIGN_ON_DO_VALIDATION_NEVER' => 'Désactiver la confirmation',

    'OA_SINGLE_SIGN_ON_ENABLE_NETWORKS' => 'Sélection des réseaux sociaux à activer sur son forum',
    'OA_SINGLE_SIGN_ON_ENABLE_SOCIAL_NETWORK' => 'Il est nécessaire d’activer au moins un réseau social',
    'OA_SINGLE_SIGN_ON_ENTER_CREDENTIALS' => 'Les clés et le sous-domaine de l’API doivent être configurés',

    'OA_SINGLE_SIGN_ON_FSOCKOPEN' => 'PHP FSOCKOPEN',
    'OA_SINGLE_SIGN_ON_FSOCKOPEN_DESC' => 'Utiliser uniquement FSOCKOPEN si des problèmes sont constatés avec CURL.',
    'OA_SINGLE_SIGN_ON_FSOCKOPEN_DOCS' => '<a href="http://www.php.net/manual/en/function.fsockopen.php" class="external">Manuel de FSOCKOPEN</a>',

    'OA_SINGLE_SIGN_ON_INDEX_PAGE' => 'Page de l’index du forum',
    'OA_SINGLE_SIGN_ON_INDEX_PAGE_CAPTION' => 'Afficher la légende',
    'OA_SINGLE_SIGN_ON_INDEX_PAGE_CAPTION_DESC' => 'Permet de saisir le titre qui sera affiché au-dessus des icônes de Single Sign On sur la page de l’index du forum.',
    'OA_SINGLE_SIGN_ON_INDEX_PAGE_ENABLE' => 'Afficher sur la page de l’index du forum',
    'OA_SINGLE_SIGN_ON_INDEX_PAGE_ENABLE_DESC' => 'Permet d’afficher Single Sign On sur la page de l’index du forum.',
    'OA_SINGLE_SIGN_ON_INDEX_PAGE_NO' => 'Masquer',
    'OA_SINGLE_SIGN_ON_INDEX_PAGE_YES' => 'Afficher',

    'OA_SINGLE_SIGN_ON_LOGIN_PAGE' => 'Page de login du forum',
    'OA_SINGLE_SIGN_ON_LOGIN_PAGE_CAPTION' => 'Afficher la légende',
    'OA_SINGLE_SIGN_ON_LOGIN_PAGE_CAPTION_DESC' => 'Permet de saisir le titre qui sera affiché au-dessus des icônes de Single Sign On sur la page de connexion du forum.',
    'OA_SINGLE_SIGN_ON_LOGIN_PAGE_ENABLE' => 'Afficher sur la page de connexion du forum',
    'OA_SINGLE_SIGN_ON_LOGIN_PAGE_ENABLE_DESC' => 'Permet d’afficher Single Sign On sur la page de connexion du forum.',
    'OA_SINGLE_SIGN_ON_LOGIN_PAGE_NO' => 'Masquer',
    'OA_SINGLE_SIGN_ON_LOGIN_PAGE_YES' => 'Afficher',

    'OA_SINGLE_SIGN_ON_INLINE_PAGE' => 'Page de connexion du forum (intégré au formulaire)',
    'OA_SINGLE_SIGN_ON_INLINE_PAGE_CAPTION' => 'Afficher la légende',
    'OA_SINGLE_SIGN_ON_INLINE_PAGE_CAPTION_DESC' => 'Permet de saisir le titre qui sera affiché au-dessus des icônes de Single Sign On intégrés au formulaire de connexion.',
    'OA_SINGLE_SIGN_ON_INLINE_PAGE_ENABLE' => 'Afficher Single Sign On dans le formulaire de connexion du forum',
    'OA_SINGLE_SIGN_ON_INLINE_PAGE_ENABLE_DESC' => 'Permet d’afficher Single Sign On intégré au formulaire de connexion. Il est nécessaire d’utiliser OneAll comme moyen d’authentification dans la page GÉNÉRAL \ COMMUNICATION \ AUTHENTIFICATION.',
    'OA_SINGLE_SIGN_ON_INLINE_PAGE_NO' => 'Masquer',
    'OA_SINGLE_SIGN_ON_INLINE_PAGE_YES' => 'Afficher',

    'OA_SINGLE_SIGN_ON_OTHER_PAGE' => 'Toutes les autres pages du forum',
    'OA_SINGLE_SIGN_ON_OTHER_PAGE_CAPTION' => 'Afficher la légende',
    'OA_SINGLE_SIGN_ON_OTHER_PAGE_CAPTION_DESC' => 'Permet de saisir le titre qui sera affiché au-dessus des icônes de Single Sign On sur les autres pages du forum.',
    'OA_SINGLE_SIGN_ON_OTHER_PAGE_ENABLE' => 'Afficher sur les autres pages du forum',
    'OA_SINGLE_SIGN_ON_OTHER_PAGE_ENABLE_DESC' => 'Permet d’afficher Single Sign On sur les autres pages du forum.',
    'OA_SINGLE_SIGN_ON_OTHER_PAGE_NO' => 'Masquer',
    'OA_SINGLE_SIGN_ON_OTHER_PAGE_YES' => 'Afficher',

    'OA_SINGLE_SIGN_ON_PORT_443' => 'Communication sur le port 443/HTTPS',
    'OA_SINGLE_SIGN_ON_PORT_443_DESC' => 'L’utilisation du port 443 est recommandé, il est possible qu’il soit nécessaire d’installer OpenSSL sur le serveur d’hébergement du forum.',
    'OA_SINGLE_SIGN_ON_PORT_80' => 'Communication sur le port 80/HTTP',
    'OA_SINGLE_SIGN_ON_PORT_80_DESC' => 'L’utilisation du port 80 est un peu plus rapide, ne nécessite pas OpenSSL mais est moins sécurisé.',

    'OA_SINGLE_SIGN_ON_PROFILE_DESC' => 'Lier son compte à un réseau social',
    'OA_SINGLE_SIGN_ON_PROFILE_TITLE' => 'Single Sign On',

    'OA_SINGLE_SIGN_ON_REGISTRATION_PAGE' => 'Page d’enregistrement du forum',
    'OA_SINGLE_SIGN_ON_REGISTRATION_PAGE_CAPTION' => 'Afficher la légende',
    'OA_SINGLE_SIGN_ON_REGISTRATION_PAGE_CAPTION_DESC' => 'Permet de saisir le titre qui sera affiché au-dessus des icônes de Single Sign On sur la page d’enregistrement du forum.',
    'OA_SINGLE_SIGN_ON_REGISTRATION_PAGE_ENABLE' => 'Afficher sur la page d’inscription du forum',
    'OA_SINGLE_SIGN_ON_REGISTRATION_PAGE_ENABLE_DESC' => 'Permet d’afficher Single Sign On sur la page d’enregistrement du forum.',
    'OA_SINGLE_SIGN_ON_REGISTRATION_PAGE_NO' => 'Masquer',
    'OA_SINGLE_SIGN_ON_REGISTRATION_PAGE_YES' => 'Afficher',

    'OA_SINGLE_SIGN_ON_SETTINGS' => 'Paramètres',
    'OA_SINGLE_SIGN_ON_SETTINGS_UPDATED' => 'Paramètres mis à jour avec succès.',
    'OA_SINGLE_SIGN_ON_SETUP_FREE_ACCOUNT' => '<a href="https://app.oneall.com/signup/" class="button1 external">Configurer mon compte gratuit</a>',

    'OA_SINGLE_SIGN_ON_TITLE' => 'OneAll Single Sign On',
    'OA_SINGLE_SIGN_ON_TITLE_HELP' => 'Aide, mises à jour &amp; documentation',

    'OA_SINGLE_SIGN_ON_VALIDATION_FORM_DESC' => 'L’administrateur requiert la saisie de votre nom d’utilisateur et de votre adresse e-mail.',
    'OA_SINGLE_SIGN_ON_VALIDATION_FORM_HEADER' => 'Confirmer son nom d’utilisateur et son adresse e-mail.',
    'OA_SINGLE_SIGN_ON_VALIDATION_SESSION_ERROR' => 'Des informations de la session courante sont manquantes.'
));
