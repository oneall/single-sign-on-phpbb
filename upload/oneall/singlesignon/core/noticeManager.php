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

/**
 * notices
 */
class noticeManager
{
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
     * Displays a notice if the user is recognized.
     */
    public function display_user_notice()
    {
        $notice = '';

        // Make sure it's enabled.
        if (!empty($this->config['oa_sso_use_account_reminder']))
        {
            // Read user from notice.
            $user = $this->get_user_notice(true);

            // Verify user object.
            if (is_object($user) && !empty($user->user_id))
            {
                // Mark user notice as displayed.
                $this->mark_user_notice_displayed($user);

                // Login url.
                $login_url = $this->helper->get_current_url([], [], true, false) . '/ucp.php';

                $notice = '<div id="oa_single_sign_on_overlay"></div>
                    <div id="oa_single_sign_on_modal">
                        <div class="oa_single_sign_on_modal_outer">
                            <div class="oa_single_sign_on_modal_inner">
                                <div class="oa_single_sign_on_modal_title">
                                       Welcome Back!
                                </div>
                                <div class="oa_single_sign_on_modal_body">
                                    <div class="oa_single_sign_on_modal_notice">
                                        You already seem to have registered an account with the username <span class="oa_single_sign_on_login">' . $user->username . '</span>. Would you like to login now?
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
        if (is_object($user) && !empty($user->user_id))
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
                if (isset($notice['userid']) && $notice['userid'] != $user->user_id)
                {
                    $new_notices[] = $notice;
                }
            }

            // Generate a hash.
            $hash = $this->hash_string($user->user_id . time());

            // Add notice.
            $notices[] = array(
                'hash' => $hash,
                'userid' => $user->user_id,
                'displayed' => 0,
                'expires' => (time() + $period)
            );

            // Save notices.
            $this->insert_notice($notices);

            // Add cookie.
            $this->user->set_cookie('oa_sso_notice', $hash, (time() + $period));
        }
    }

    /**
     * Removes a notice cookie.
     */
    public function remove_user_notice_cookies()
    {
        $this->user->set_cookie('oa_sso_notice', '', (time() - (15 * 60)));
    }

    /**
     * Removes all notice data for a user.
     */
    public function remove_flush_user_notice($user)
    {
        $this->remove_user_notice_cookies();
        $this->remove_user_notice($user);
    }

    /**
     * Marks a notice as having been displayed.
     */
    public function mark_user_notice_displayed($user)
    {
        // Verify user object.
        if (is_object($user) && !empty($user->user_id))
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
                if (isset($notice['userid']) && $notice['userid'] == $user->user_id)
                {
                    $notice['displayed'] = 1;
                }

                // Add
                $new_notices[] = $notice;
            }

            // Save notices
            $this->insert_notice($new_notices);
        }
    }

    /**
     * Remove a user a notice.
     */
    public function remove_user_notice($user)
    {
        // Verify user object.
        if (is_object($user) && !empty($user->user_id))
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
                if (isset($notice['userid']) && $notice['userid'] != $user->user_id)
                {
                    $new_notices[] = $notice;
                }
            }

            // Save notices.
            $this->insert_notice($new_notices);
        }
    }

    /**
     * Return the current user from the notices.
     */
    public function get_user_notice($only_non_displayed)
    {
        if (!empty($this->helper->get_cookie_value('oa_sso_notice')))
        {
            // Read notices
            $notices = $this->get_notices();

            // Check format.
            if (is_array($notices))
            {
                // Read hash
                $hash = $this->helper->get_cookie_value('oa_sso_notice');

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
                                $user = (object) $this->helper->get_user_data_by_user_id($user_notice['userid']);

                                // Verify user object.
                                if (is_object($user) && !empty($user->user_id))
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

    /**
     * Hash a password.
     */
    public function hash_string($password)
    {
        // We cannot make a connection without the subdomain.
        if (!empty($this->config['oa_sso_api_subdomain']) && !empty($this->config['oa_sso_api_key']))
        {
            return sha1($this->config['oa_sso_api_key'] . $password . $this->config['oa_sso_api_subdomain']);
        }

        // Error

        return null;
    }

    /**
     * Get notices
     */
    public function get_notices()
    {
        // Make sure that that the user exists.
        $sql = "SELECT notices FROM " . $this->table_prefix . "oasl_notices ";
        $query = $this->db->sql_query_limit($sql, 1);
        $result = $this->db->sql_fetchrow($query);
        $this->db->sql_freeresult($query);

        return (is_array($result) && !empty($result['notices'])) ? json_decode($result['notices'], true) : [];
    }

    /**
     * Add or update a notice
     */
    public function insert_notice(array $notice_data)
    {
        $notices = $this->get_notices();

        // non existing -> create it
        if (!$notices)
        {
            // Add new link.
            $sql_arr = array('notices' => json_encode($notice_data));
            $sql = "INSERT INTO " . $this->table_prefix . "oasl_notices " . $this->db->sql_build_array('INSERT', $sql_arr);
            $this->db->sql_query($sql);
        }
        else
        {
            // Update the counter for the given identity_token.
            $sql = "UPDATE " . $this->table_prefix . "oasl_notices
                    SET notices='" . $this->db->sql_escape(json_encode($notice_data)) . "'";
            $this->db->sql_query($sql);
        }
    }
}
