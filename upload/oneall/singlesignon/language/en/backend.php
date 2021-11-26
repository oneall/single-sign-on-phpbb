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
 * English translations by OneAll
 * http://www.oneall.com
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
    'G_OA_SINGLE_SIGN_ON_REGISTER' => 'Registered OneAll users',
    'OA_SINGLE_SIGN_ON_DEFAULT' => 'Default',

    'OA_SINGLE_SIGN_ON_TITLE' => 'OneAll Single Sign On',
    'OA_SINGLE_SIGN_ON_VIEW_CREDENTIALS' => '<a href="https://app.oneall.com/applications/" class="button1 external">Create and/or view my API Credentials</a>',
    'OA_SINGLE_SIGN_ON_WIDGET_TITLE' => 'Login with a social network',

    'OA_SINGLE_SIGN_ON_ACP' => 'OneAll Single Sign On',
    'OA_SINGLE_SIGN_ON_ACP_SETTINGS' => 'Settings',

    'OA_SINGLE_SIGN_ON_API_AUTODETECT' => 'Autodetect API Connection',
    'OA_SINGLE_SIGN_ON_API_VERIFY' => 'Verify API Settings',

    'OA_SINGLE_SIGN_ON_API_CONNECTION' => 'API Connection',
    'OA_SINGLE_SIGN_ON_API_CONNECTION_HANDLER' => 'API Connection Handler',
    'OA_SINGLE_SIGN_ON_API_CONNECTION_HANDLER_DESC' => 'This is how your server will communicate with the OneAll social network integration service.',

    'OA_SINGLE_SIGN_ON_API_CREDENTIALS_CHECK_COM' => 'Could not contact API. Is the API connection setup properly?',
    'OA_SINGLE_SIGN_ON_API_CREDENTIALS_FILL_OUT' => 'Please fill out each of the fields above.',
    'OA_SINGLE_SIGN_ON_API_CREDENTIALS_KEYS_WRONG' => 'The API credentials are wrong, please check your public/private key.',
    'OA_SINGLE_SIGN_ON_API_CREDENTIALS_OK' => 'The settings are correct - do not forget to save your changes!',
    'OA_SINGLE_SIGN_ON_API_CREDENTIALS_SUBDOMAIN_WRONG' => 'The subdomain does not exist. Have you filled it out correctly?',
    'OA_SINGLE_SIGN_ON_API_CREDENTIALS_TITLE' => 'API Credentials - <a href="https://app.oneall.com/applications/" class="external">Click here to create or view your API Credentials</a>',
    'OA_SINGLE_SIGN_ON_API_CREDENTIALS_UNKNOW_ERROR' => 'Unknow response - please make sure that you are logged in!',
    'OA_SINGLE_SIGN_ON_API_CREDENTIALS_USE_AUTO' => 'The connection handler does not seem to work. Please use the Autodetection.',

    'OA_SINGLE_SIGN_ON_API_DETECT_CURL' => 'Detected CURL on port %s - do not forget to save your changes!',
    'OA_SINGLE_SIGN_ON_API_DETECT_FSOCKOPEN' => 'Detected FSOCKOPEN on Port %s - do not forget to save your changes!',
    'OA_SINGLE_SIGN_ON_API_DETECT_NONE' => 'Connection failed! Your firewall must allow outbound request on either port 80 or 443.',

    'OA_SINGLE_SIGN_ON_API_PORT' => 'API Connection Port',
    'OA_SINGLE_SIGN_ON_API_PORT_DESC' => 'Your firewall must allow outgoing requests on port 80 and/or 443.',

    'OA_SINGLE_SIGN_ON_API_AUTODETECT' => 'Your firewall must allow outgoing requests on port 80 and/or 443.',

    'OA_SINGLE_SIGN_ON_API_PRIVATE_KEY' => 'API Private Key',
    'OA_SINGLE_SIGN_ON_API_PUBLIC_KEY' => 'API Public Key',
    'OA_SINGLE_SIGN_ON_API_SUBDOMAIN' => 'API Subdomain',

    'OA_SINGLE_SIGN_ON_CURL' => 'PHP CURL',
    'OA_SINGLE_SIGN_ON_CURL_DESC' => 'Using CURL is recommended but it might be disabled on some servers.',
    'OA_SINGLE_SIGN_ON_CURL_DOCS' => '<a href="http://www.php.net/manual/en/book.curl.php" class="external">CURL Manual</a>',

    'OA_SINGLE_SIGN_ON_FSOCKOPEN' => 'PHP FSOCKOPEN',
    'OA_SINGLE_SIGN_ON_FSOCKOPEN_DESC' => 'Only use FSOCKOPEN if you encounter any problems with CURL.',
    'OA_SINGLE_SIGN_ON_FSOCKOPEN_DOCS' => '<a href="http://www.php.net/manual/en/function.fsockopen.php" class="external">FSOCKOPEN Manual</a>',

    'OA_SINGLE_SIGN_ON_PORT_443' => 'Communication on port 443/HTTPS',
    'OA_SINGLE_SIGN_ON_PORT_443_DESC' => 'Using port 443 is recommended but you might have to install OpenSSL on your server.',
    'OA_SINGLE_SIGN_ON_PORT_80' => 'Communication via 80/HTTP',
    'OA_SINGLE_SIGN_ON_PORT_80_DESC' => 'Using port 80 is a bit faster, does not need OpenSSL but is less secure.',

    'OA_SINGLE_SIGN_ON_SETTINGS' => 'Settings',
    'OA_SINGLE_SIGN_ON_SETTINGS_UPDATED' => 'Settings updated successfully.',
    'OA_SINGLE_SIGN_ON_SETUP_FREE_ACCOUNT' => '<a href="https://app.oneall.com/signup/" class="button1 external">Setup my free account</a>',

    'OA_SINGLE_SIGN_ON_DO_ENABLE' => 'Enable Single Sign On ?',
    'OA_SINGLE_SIGN_ON_DO_ENABLE_DESC' => 'Allows you to temporarily disable Single Sign On without having to remove it.',
    'OA_SINGLE_SIGN_ON_DO_ENABLE_NO' => 'Disable',
    'OA_SINGLE_SIGN_ON_DO_ENABLE_YES' => 'Enable',

    'OA_SINGLE_SIGN_ON_SETTINGS' => 'Single Sign On Settings',

    'OA_SINGLE_SIGN_ON_AUTOCREATION' => 'Automatic Account Creation',
    'OA_SINGLE_SIGN_ON_AUTOCREATION_DESC' => 'If enabled, the plugin automatically creates new user accounts for SSO users that visit the website but do not have an account yet. These users are then automatically logged in with the new account.',
    'OA_SINGLE_SIGN_ON_AUTOCREATION_YES' => 'Enable automatic account creation (Default)',
    'OA_SINGLE_SIGN_ON_AUTOCREATION_NO' => 'Disable automatic account creation',

    'OA_SINGLE_SIGN_ON_AUTOLINK_ACCOUNT' => 'Automatic Account Link',
    'OA_SINGLE_SIGN_ON_AUTOLINK_ACCOUNT_DESC' => 'If enabled, the plugin tries to link SSO users that visit the website to already existing user accounts. To link accounts the email address of the SSO user is matched against the email addresses of the existing users.',
    'OA_SINGLE_SIGN_ON_AUTOLINK_ACCOUNT_NO' => 'Disable automatic account link',
    'OA_SINGLE_SIGN_ON_AUTOLINK_ACCOUNT_YES' => 'Enable automatic link for all types of accounts',
    'OA_SINGLE_SIGN_ON_AUTOLINK_ACCOUNT_YES_WITHOUT_ADMIN' => 'Enable automatic link for all types of accounts, except the admin account (Default)',

    'OA_SINGLE_SIGN_ON_AUTOLINK_UNVERIFIED_EMAIL' => 'Link Account with unverified email',
    'OA_SINGLE_SIGN_ON_AUTOLINK_UNVERIFIED_EMAIL_DESC' => 'If enabled, the plugin tries to link SSO users that visit the website to already existing user accounts even if their email is unverified.',
    'OA_SINGLE_SIGN_ON_AUTOLINK_UNVERIFIED_EMAIL_NO' => 'Disable automatic account link if email is unverified',
    'OA_SINGLE_SIGN_ON_AUTOLINK_UNVERIFIED_EMAIL_YES' => 'Enable automatic link if email is unverified',

    'OA_SINGLE_SIGN_ON_REMINDER' => 'Account Reminder',
    'OA_SINGLE_SIGN_ON_REMINDER_DESC' => 'If enabled, the plugin will display a popup reminding the SSO of his account if an existing account has been found, but the user could not be logged in by the plugin (eg. if Automatic Account Link is disabled).',
    'OA_SINGLE_SIGN_ON_REMINDER_YES' => 'Enable account reminder (Default)',
    'OA_SINGLE_SIGN_ON_REMINDER_NO' => 'Disable account reminder',

    'OA_SINGLE_SIGN_ON_DESTROY_SESSION' => 'Destroy Session On Logout',
    'OA_SINGLE_SIGN_ON_DESTROY_SESSION_DESC' => 'If enabled, the plugin destroys the user\'s SSO session whenever he logs out from Drupal. If you disable this setting, then do not use an empty value for the login delay, otherwise the user will be re-logged in instantly.',
    'OA_SINGLE_SIGN_ON_DESTROY_SESSION_YES' => 'Yes. Destroy the SSO session on logout (Default, Recommended)',
    'OA_SINGLE_SIGN_ON_DESTROY_SESSION_NO' => 'No. Keep the SSO session on logout.',

    'OA_SINGLE_SIGN_ON_WAIT_RELOGIN' => 'Re-Login Delay (Seconds)',
    'OA_SINGLE_SIGN_ON_WAIT_RELOGIN_DESC' => 'Whenever a user logs out, the plugin will not retry to login that user for the entered period. Please enter a positive integer or leave empty in order to disable.',

    'OA_SINGLE_SIGN_ON_LOG_SETTINGS' => 'Single Sign On Debugging',

    'OA_SINGLE_SIGN_ON_LOG' => 'Log Single Sign-On actions',
    'OA_SINGLE_SIGN_ON_LOG_DESC' => 'If enabled, the extension will write a debug log that can be viewed under Manage \ Reports \ Recent log messages.',
    'OA_SINGLE_SIGN_ON_LOG_YES' => 'Yes, enable logging',
    'OA_SINGLE_SIGN_ON_LOG_NO' => 'No, disabled logging'

));
