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
namespace oneall\singlesignon\event;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Event listener
 */
class listener implements EventSubscriberInterface
{
    // @var \phpbb\config\config
    protected $config;

    // @var \phpbb\config\db_text
    protected $config_text;

    // @var \phpbb\controller\helper
    protected $controller_helper;

    // @var \phpbb\request\request
    protected $request;

    // @var \phpbb\template\template
    protected $template;

    // @var \phpbb\user
    protected $user;

    // @var string php_root_path
    protected $phpbb_root_path;

    // @var string phpEx
    protected $php_ext;

    // @var \oneall\singlesignon\core\helper
    protected $helper;

    // @var \oneall\singlesignon\core\singleSignOn
    protected $singleSignOn;

    // @var \oneall\singlesignon\core\noticeManager
    protected $noticeManager;

    // Has the current user logged in with Single Sign On
    protected $is_oa_user = null;

    /**
     * Constructor
     */
    public function __construct(\phpbb\config\config $config, \phpbb\config\db_text $config_text, \phpbb\controller\helper $controller_helper, \phpbb\request\request $request, \phpbb\template\template $template, \phpbb\user $user, $phpbb_root_path, $php_ext, \oneall\singlesignon\core\helper $helper, \oneall\singlesignon\core\singlesignon $singleSignOn, \oneall\singlesignon\core\noticeManager $noticeManager)
    {
        $this->config = $config;
        $this->config_text = $config_text;
        $this->controller_helper = $controller_helper;
        $this->request = $request;
        $this->template = $template;
        $this->user = $user;
        $this->phpbb_root_path = $phpbb_root_path;
        $this->php_ext = $php_ext;
        $this->helper = $helper;
        $this->singleSignOn = $singleSignOn;
        $this->noticeManager = $noticeManager;
    }

    /**
     * Assign functions defined in this class to event listeners in the core
     */
    public static function getSubscribedEvents()
    {
        return array(
            'core.page_header_after' => 'init', //page_footer_after possible
            'core.user_setup' => 'add_language',
            'core.ucp_profile_reg_details_data' => 'set_oa_user',
            'core.ucp_profile_reg_details_sql_ary' => 'update_user',
            'core.auth_login_session_create_before' => 'auth_open',
            'core.session_kill_after' => 'user_logout',
            'core.ucp_register_register_after' => 'after_user_register',
            'core.login_box_before' => 'form_user_login_form_alter'

        );
    }

    /**
     * Helper function to check if a user is logged in with Single Sign On.
     * Memorizes the result in attribute to avoid rechecks.
     */
    private function is_oa_user()
    {
        if (is_null($this->is_oa_user))
        {
            $this->is_oa_user = (($this->helper->get_user_token_for_user_id($this->user->data['user_id']) === false) ? false : true);
        }

        return $this->is_oa_user;
    }

    /**
     * Notifies if a user is logged in with Single Sign On, to the UCP template.
     * The UCP template event will disable the cur_password form input.
     */
    public function set_oa_user($event)
    {
        $this->template->assign_var('OA_SINGLE_SIGN_ON_USER', $this->is_oa_user());
    }

    /**
     * Add Single Sign On language file.
     */
    public function add_language($event)
    {
        // Read language settings.
        $lang_set_ext = $event['lang_set_ext'];

        // Add frontend language strings.
        $lang_set_ext[] = array(
            'ext_name' => 'oneall/singlesignon',
            'lang_set' => 'frontend'
        );

        // Add backend language strings.
        $lang_set_ext[] = array(
            'ext_name' => 'oneall/singlesignon',
            'lang_set' => 'backend'
        );

        // Set language settings.
        $event['lang_set_ext'] = $lang_set_ext;
    }

    /**
     * Setup Single Sign On.
     */
    public function init($event)
    {
        // The plugin must be enabled and the API settings must be filled out
        if (empty($this->config['oa_sso_disable']) && !empty($this->config['oa_sso_api_subdomain']))
        {
            // Setup template placeholders
            $this->template->assign_vars(array(
                'OA_SINGLE_SIGN_ON_API_SUBDOMAIN' => $this->config['oa_sso_api_subdomain'],
                'OA_SINGLE_SIGN_ON_CALLBACK_URI' => $this->helper->get_current_url(),
                'OA_SINGLE_SIGN_ON_PROVIDERS' => implode("','", explode(",", $this->config['oa_sso_providers'])),
                'OA_SINGLE_SIGN_ON_RAND' => mt_rand(99999, 9999999),
                'OA_SINGLE_SIGN_ON_AJAX_GET_SSO_TOKEN' => $this->controller_helper->route('oneall_singlesignon_get_sso_token'),
                'OA_SINGLE_SIGN_ON_AJAX_GET_USER_NOTICE' => $this->controller_helper->route('oneall_singlesignon_get_user_notice')
            ));

            // //////////////////////////////////////////////
            // ///////////////  SSO JS   ////////////////////
            // //////////////////////////////////////////////

            // User is logged in
            if (!empty($this->user->data['user_id']) && (int) $this->user->data['user_id'] != ANONYMOUS)
            {
                // Logged in.
                $user_is_logged_in = true;

                // Retrieve his SSO session token.
                $get_sso_session_token = $this->helper->get_local_sso_session_token_for_id($this->user->data['user_id']);

                // SSO session token found
                if ($get_sso_session_token->is_successfull === true)
                {
                    $sso_session_token = $get_sso_session_token->sso_session_token;
                }
            }
            // User is logged out
            else
            {
                // Logged out.
                $user_is_logged_in = false;
            }

            // Either logged out, or logged in and having a token
            if (!$user_is_logged_in || ($user_is_logged_in && !empty($sso_session_token)))
            {
                // Add SSO JavaScript
                $this->template->assign_vars(array(
                    'OA_SINGLE_SIGN_ON_EMBED_SINGLE_SIGN_ON' => true
                ));
            }

            /////////////////////////////////////////////////////////////
            ///////////////  Single sign-on handler  ////////////////////
            /////////////////////////////////////////////////////////////

            // Check the callback.
            $status = $this->singleSignOn->process_callback();

            // Check what needs to be done.
            switch (strtolower($status->action))
            {
                // //////////////////////////////////////////////////////////////////////////
                // No user found and we cannot add users
                // //////////////////////////////////////////////////////////////////////////
                case 'new_user_no_login_autocreate_off':
                    // Grace Period
                    $period = $this->helper->set_login_wait_cookie($this->config['oa_sso_logout_wait_relogin']);

                    // Add log.
                    $this->helper->add_log('[INIT] @' . $status->action . '] Guest detected but account creation is disabled. Blocking automatic SSO re-login for [' . $this->config['oa_sso_logout_wait_relogin'] . '] seconds, until [' . date("d/m/y H:i:s", $period) . ']');

                    break;

                // //////////////////////////////////////////////////////////////////////////
                // User found and logged in
                // //////////////////////////////////////////////////////////////////////////

                // Created a new user.
                case 'new_user_created_login':
                // Logged in using the user_token.
                case 'existing_user_login_user_token':
                // Logged in using a verified email address.
                case 'existing_user_login_email_verified':
                // Logged in using an un-verified email address.
                case 'existing_user_login_email_unverified':
                    // Add log.
                    $this->helper->add_log('[INIT] @' . $status->action . ' - User is logged in');

                    // Remove the cookie.
                    $this->helper->unset_login_wait_cookie();

                    // Log the user in.
                    $this->helper->sso_redirect(null, $status->user_id, array('identity_token' => $status->identity_token));

                    break;

                // //////////////////////////////////////////////////////////////////////////
                // User found, but we cannot log him in
                // //////////////////////////////////////////////////////////////////////////

                // User found, but autolink disabled.
                case 'existing_user_no_login_autolink_off':
                // User found, but autolink not allowed.
                case 'existing_user_no_login_autolink_not_allowed':
                // Customer found, but autolink disabled for unverified emails.
                case 'existing_user_no_login_autolink_off_unverified_emails':
                    // Grace period.
                    $period = $this->helper->set_login_wait_cookie($this->config['oa_sso_logout_wait_relogin']);

                    // // Add a notice for the user.
                    // $this->noticeManager->enable_user_notice($status->user);

                    // Add log.
                    $this->helper->add_log('[INIT] @' . $status->action . '] - Blocking automatic SSO re-login for [' . $this->config['oa_sso_logout_wait_relogin'] . '] seconds, until [' . date("d/m/y H:i:s", $period) . ']');

                    break;

                // //////////////////////////////////////////////////////////////////////////
                // Default
                // //////////////////////////////////////////////////////////////////////////

                // No callback received
                case 'no_callback_data_received':
                default:
                    // The user is logged in.
                    if ((int) $this->user->data['user_id'] != ANONYMOUS)
                    {
                        // Read the user's token.
                        $token = $this->helper->get_user_token_information_for_uid($this->user->data['user_id']);

                        // We have a session token, refresh it.
                        if (!empty($token->sso_session_token))
                        {
                            $this->helper->add_log('[INIT] @' . $status->action . '] [UID' . $this->user->data['user_id'] . '] - User is logged in, refreshing session token [' . $token->sso_session_token . ']');
                        }
                        else
                        {
                            $this->helper->add_log('[INIT] @' . $status->action . '] [UID' . $this->user->data['user_id'] . '] - User is logged in but has no sso session token yet');
                        }
                    }
                    else
                    {
                        // If this value is in the future, we should not try to login the user with SSO.
                        $login_wait = $this->helper->get_login_wait_value_from_cookie();

                        // Wait time exceeded?
                        if ($login_wait < time())
                        {
                            $this->helper->add_log('[INIT] @' . $status->action . ' - User is logged out. Checking for valid SSO session');
                        }
                        else
                        {
                            $this->helper->add_log('[INIT] @' . $status->action . ' - User is logged out. Re-login disabled, ' . ($login_wait - time()) . ' seconds remaining');
                        }
                    }
                    break;
            }
        }
    }

    /**
     * Starts the SSO session when the users logs in.
     */
    public function auth_open($event)
    {
        global $request;

        if (isset($event['login'], $event['login']['status']) && $event['login']['status'] == LOGIN_SUCCESS)
        {
            $user = new \stdClass();
            $user->user_id = $event['login']['user_row']['user_id'];
            $user->user_type = $event['login']['user_row']['user_type'];
            $user->user_email = $event['login']['user_row']['user_email'];
            $user->group_id = $event['login']['user_row']['group_id'];
            $user->username = $event['login']['user_row']['username'];
            $user->username_clean = $event['login']['user_row']['username_clean'];

            // Read the new password.
            if (!empty($request->get_super_global()['password']))
            {
                $password = $request->get_super_global()['password'];
            }
            else
            {
                $password = null;
            }

            // Add log.
            $this->helper->add_log('[LOGIN] [UID' . $user_id . '] User login, starting SSO session');

            $this->singleSignOn->start_session_for_user($user, $password);
        }
    }

    /**
     * Add user to cloud storage on register
     */
    public function after_user_register($event)
    {
        if (isset($event['user_row']) && !empty($event['user_id']))
        {
            $user = new \stdClass();
            $user->user_id = $event['user_id'];
            $user->user_type = $event['user_row']['user_type'];
            $user->group_id = $event['user_row']['group_id'];
            $user->username = $event['user_row']['username'];
            $user->user_email = $event['user_row']['user_email'];

            // Password.
            $password = null;

            // Do we have a password?
            if (isset($_POST) && is_array($_POST))
            {
                if (!empty($_POST['new_password']) && !empty($_POST['password_confirm']))
                {
                    if ($_POST['new_password'] == $_POST['password_confirm'])
                    {
                        $password = $_POST['password_confirm'];
                    }
                }
            }

            // Add log.
            $this->helper->add_log('[USER-ADD] [UID' . $user_id . '] User registration Starting SSO session');

            // Add user to cloud storage.
            $this->singleSignOn->start_session_for_user($user, $password);
        }
    }

    /**
     * Implements hook_user_logout().
     */
    public function user_logout($event)
    {
        // Single Sign-On requires the subdomain.
        if (!empty($this->config['oa_sso_api_subdomain']))
        {
            // Destroy session.
            if (!empty($this->config['oa_sso_destroy_session_on_logout']))
            {
                // Add log.
                $this->helper->add_log('[AUTH CLOSE] [UID' . $event['user_id'] . '] User logout, removing SSO session');

                // // End session.
                $this->singleSignOn->end_session_for_user($event['user_id']);
            }
            else
            {
                // Add log.
                $this->helper->add_log('[AUTH CLOSE] [UID' . $event['user_id'] . '] User logout, keeping SSO session');
            }

            // Wait until relogging in?
            if (!empty($this->config['oa_sso_logout_wait_relogin']) && $this->config['oa_sso_logout_wait_relogin'] > 0)
            {
                // // Grace period.
                $this->helper->set_login_wait_cookie($this->config['oa_sso_logout_wait_relogin']);

                // // Add log.
                $this->helper->add_log('[AUTH CLOSE] [UID' . $event['user_id'] . '] User logout. No automatic SSO re-login for [' . $this->config['oa_sso_logout_wait_relogin'] . '] seconds, until [' . date("d/m/y H:i:s", time() + $this->config['oa_sso_logout_wait_relogin']) . ']');
            }
            // No waiting.
            else
            {
                // Remove the cookie.
                $this->helper->unset_login_wait_cookie();
            }
        }
    }

    /**
     * Implements hook_user_update.
     */
    public function update_user($event)
    {
        $user = new \stdClass();
        $user->user_id = $this->user->data['user_id'];
        $user->user_type = $this->user->data['user_type'];
        $user->user_email = $event['data']['email'];
        $user->group_id = $this->user->data['group_id'];
        $user->username = $event['data']['username'];
        $user->username_clean = $this->user->data['username_clean'];

        // Add log.
        $this->helper->add_log('[PROFILE UPDATE] [UID' . $user->user_id . '] Synchronize cloud storage');

        // Read the new password.
        if (empty($event['error']) && !empty($event['data']['new_password']))
        {
            $password = $event['data']['new_password'];

            // Add user to cloud storage.
            $token = $this->singleSignOn->synchronize_user_to_cloud_storage($user, $password);
        }
    }

    /**
     * Implements hook_form_USER_LOGIN_FORM_alter()
     */
    public function form_user_login_form_alter($event)
    {
        global $request;

        if (!empty($request->get_super_global()['username']) && !empty($request->get_super_global()['password']))
        {
            // Form entries.
            $login = $request->get_super_global()['username'];
            $password = $request->get_super_global()['password'];

            // Lookup credentials in the cloud storage.
            $result = $this->singleSignOn->lookup_user($login, $password);

            // Cloud storage auth was successfull.
            if ($result->is_successfull === true)
            {
                // Log the user in.
                $this->helper->sso_redirect(null, $result->user_id, array('identity_token' => $result->identity_token));
                exit;
            }
        }
    }
}
