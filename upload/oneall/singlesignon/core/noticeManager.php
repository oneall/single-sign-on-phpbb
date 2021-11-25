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
namespace oneall\singlesignon\core;

// Constants.
define('SINGLE_SIGN_ON_LOGIN_WAIT_COOKIE_KEY', 'oa_sso_lw');
define('SINGLE_SIGN_ON_LOGOUT_WAIT_RELOGIN_DEFAULT', 60 * 60);
define('SINGLE_SIGN_ON_COOKIE_DOMAIN', false);
define('SINGLE_SIGN_ON_COOKIEPATH', '/');

/**
 * notices
 */
class noticeManager
{
    // Version
    const USER_AGENT = 'SingleSignOn/1.0.0 phpBB/3.1.x (+http://www.oneall.com/)';

    // @var \phpbb\config\config
    protected $config;

    // @var \phpbb\request\request
    protected $request;

    // @var \phpbb\template\template
    protected $template;

    // @var \phpbb\user
    protected $user;

    // @var \phpbb\log\log
    protected $log;

    // @var \phpbb\auth\auth
    protected $auth;

    // @var \phpbb\db\driver\factory
    protected $db;

    // @var \phpbb\event\dispatcher_interface
    protected $phpbb_dispatcher;

    // @var phpbb\passwords\manager
    protected $passwords_manager;

    // @var string php_root_path
    protected $phpbb_root_path;

    // @var string phpEx
    protected $php_ext;

    // @vat string table_prefix
    protected $table_prefix;

    /**
     * Constructor
     */
    public function __construct(\phpbb\config\config $config, \phpbb\request\request $request, \phpbb\template\template $template, \phpbb\log\log $log, \phpbb\user $user, \phpbb\auth\auth $auth, \phpbb\db\driver\factory $db, \phpbb\event\dispatcher $phpbb_dispatcher, \phpbb\passwords\manager $passwords_manager, $phpbb_root_path, $php_ext, $table_prefix, \oneall\singlesignon\core\helper $helper)
    {
        $this->config = $config;
        $this->request = $request;
        $this->template = $template;
        $this->log = $log;
        $this->user = $user;
        $this->auth = $auth;
        $this->db = $db;
        $this->dispatcher = $phpbb_dispatcher;
        $this->passwords_manager = $passwords_manager;
        $this->phpbb_root_path = $phpbb_root_path;
        $this->php_ext = $php_ext;
        $this->table_prefix = $table_prefix;
        $this->helper = $helper;
    }

    /**
     * Get notices
     */
    public function get_notices()
    {
        // oasl_settings
        $query = Database::getConnection()->select('oasl_settings', 'oasl_s');
        $query->fields('oasl_s')->condition('setting', 'notice', '=');
        $oasl_settings = $query->execute()->fetch();

        return !empty($oasl_settings->value) ? json_decode($oasl_settings->value, true) : [];
    }

    /**
     * Displays a notice if the user is recognized.
     */
    public function display_user_notice()
    {
        // @todo
        return true;

        $notice = '';

        // Make sure it's enabled.
        if (!empty($this->config['account_reminder']))
        {
            // Read user from notice.
            $user = $this->get_user_notice(true);

            var_dump($user);
            die;

            // Verify user object.
            if (is_object($user) && !empty($user->id()))
            {
                // Mark user notice as displayed.
                single_sign_on_mark_user_notice_displayed($user);

                // Are we using HTTPs?
                $is_https = \Drupal::request()->isSecure();

                // Login url.
                $login_url = single_sign_on_get_current_url($is_https, false) . '/user/login';

                $notice = '<div id="oa_single_sign_on_overlay"></div>
                    <div id="oa_single_sign_on_modal">
                        <div class="oa_single_sign_on_modal_outer">
                            <div class="oa_single_sign_on_modal_inner">
                                <div class="oa_single_sign_on_modal_title">
                                       Welcome Back!
                                </div>
                                <div class="oa_single_sign_on_modal_body">
                                    <div class="oa_single_sign_on_modal_notice">
                                        You already seem to have registered an account with the username <span class="oa_single_sign_on_login">' . $user->getUsername() . '</span>. Would you like to login now?
                                    </div>
                                    <div class="oa_single_sign_on_modal_buttons">
                                        <a href="' . $login_url . '" class="oa_single_sign_on_modal_button" id="oa_single_sign_on_modal_button_login">Login</a>
                                        <a onclick="window.location.reload();" class="oa_single_sign_on_modal_button" id="oa_single_sign_on_modal_button_cancel">Cancel</a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>';
            }
        }

        return $notice;
    }

    /**
     * Enables a notice for the user.
     */
    public function enable_user_notice($user, $period = 3600)
    {
        // Verify user object.
        if (is_object($user) && !empty($user->id()))
        {
            // Read notices
            $old_notices = $this->get_notices();
            if (!is_array($old_notices))
            {
                $old_notices = array();
            }

            // Removes duplicates
            $new_notices = array();
            foreach ($old_notices as $notice)
            {
                if (isset($notice['userid']) && $notice['userid'] != $user->id())
                {
                    $new_notices[] = $notice;
                }
            }

            // Generate a hash.
            $hash = single_sign_on_hash_string($user->id() . time());

            // Add notice.
            $notices[] = array(
                'hash' => $hash,
                'userid' => $user->id(),
                'displayed' => 0,
                'expires' => (time() + $period)
            );

            // Save notices.
            single_sign_on_insert_notice($notices);

            // Add cookie.
            setcookie('oa_sso_notice', $hash, (time() + $period), SINGLE_SIGN_ON_COOKIEPATH, SINGLE_SIGN_ON_COOKIE_DOMAIN);
            $_COOKIE['oa_sso_notice'] = $hash;
        }
    }

    /**
     * Remove a user a notice.
     */
    public function remove_user_notice($user)
    {
        // Verify user object.
        if (is_object($user) && !empty($user->id()))
        {
            // Current notices.
            $old_notices = $this->get_notices();
            if (!is_array($old_notices))
            {
                $old_notices = array();
            }

            // New notices.
            $new_notices = array();
            foreach ($old_notices as $notice)
            {
                if (isset($notice['userid']) && $notice['userid'] != $user->id())
                {
                    $new_notices[] = $notice;
                }
            }

            // Save notices.
            single_sign_on_insert_notice($new_notices);
        }
    }

    /**
     * Removes a notice cookie.
     */
    public function remove_user_notice_cookies()
    {
        if (isset($_COOKIE) && is_array($_COOKIE) && isset($_COOKIE['oa_sso_notice']))
        {
            unset($_COOKIE['oa_sso_notice']);
        }

        // Remove Cookie.
        setcookie('oa_sso_notice', '', (time() - (15 * 60)), SINGLE_SIGN_ON_COOKIEPATH, SINGLE_SIGN_ON_COOKIE_DOMAIN);
    }

    /**
     * Removes all notice data for a user.
     */
    public function remove_flush_user_notice($user)
    {
        single_sign_on_remove_user_notice_cookies();
        single_sign_on_remove_user_notice($user);
    }

    /**
     * Marks a notice as having been displayed.
     */
    public function mark_user_notice_displayed($user)
    {
        // Verify user object.
        if (is_object($user) && !empty($user->id()))
        {
            // Current notices.
            $old_notices = $this->get_notices();
            if (!is_array($old_notices))
            {
                $old_notices = array();
            }

            // New notices
            $new_notices = array();
            foreach ($old_notices as $notice)
            {
                if (isset($notice['userid']) && $notice['userid'] == $user->id())
                {
                    $notice['displayed'] = 1;
                }

                // Add
                $new_notices[] = $notice;
            }

            // Save notices
            single_sign_on_insert_notice($new_notices);
        }
    }

    /**
     * Return the current user from the notices.
     */
    public function get_user_notice($only_non_displayed)
    {
        if (isset($_COOKIE) && is_array($_COOKIE) && isset($_COOKIE['oa_sso_notice']))
        {
            // Read notices
            $notices = $this->get_notices();

            // Check format.
            if (is_array($notices))
            {
                // Read hash
                $hash = $_COOKIE['oa_sso_notice'];

                // Lookup
                foreach ($notices as $notice)
                {
                    if (isset($notice['hash']) && $notice['hash'] == $hash)
                    {
                        $user_notice = $notice;
                    }
                }

                // Do we have to display a notice?
                if (isset($user_notice))
                {
                    // Check if it's valid
                    if (is_array($user_notice) && isset($user_notice['userid']) && isset($user_notice['expires']))
                    {
                        // Not  expired and not yet displayed
                        if ($user_notice['expires'] > time())
                        {
                            // Return only non-displayed notices?
                            if (!$only_non_displayed || empty($user_notice['displayed']))
                            {
                                // Read user.
                                $user = \Drupal::service('entity_type.manager')->getStorage('user')->load($user_notice['userid']);

                                // Verify user object.
                                if (is_object($user) && !empty($user->id()))
                                {
                                    return $user;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
