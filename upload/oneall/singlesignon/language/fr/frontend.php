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

// Single Sign On Frontend.
$lang = array_merge($lang, array(
    'OA_SINGLE_SIGN_ON_ENABLE_SOCIAL_NETWORK' => 'Au moins un compte de réseau social doit être lié.',
    'OA_SINGLE_SIGN_ON_ENTER_CREDENTIALS' => 'Configurer ses certificats d’API.',
    'OA_SINGLE_SIGN_ON_ACCOUNT_ALREADY_LINKED' => 'Ce compte de réseau social est déjà lié avec un compte utilisateur du forum.',
    'OA_SINGLE_SIGN_ON_ACCOUNT_LINKED' => 'Le compte de réseau social a été lié.',
    'OA_SINGLE_SIGN_ON_ACCOUNT_UNLINKED' => 'Le compte de réseau social a été délié.',
    'OA_SINGLE_SIGN_ON_ACCOUNT_INACTIVE_OTHER' => 'Le compte a été crée. Cependant, les paramètres du forum nécessitent l’activation du compte.<br />Une clé d’activation a été envoyée à votre adresse e-mail.',
    'OA_SINGLE_SIGN_ON_ACCOUNT_INACTIVE_ADMIN' => 'Le compte a été crée. Cependant, les paramètres du forum nécessitent l’activation du compte par un administrateur.<br />Un e-mail a été envoyé aux administrateurs et vous serez informé par e-mail une fois que votre compte aura été activé.'
));
