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
namespace oneall\singlesignon\acp;

class singlesignon_acp_module
{
    /**
     * Main Function
     */
    public function main($id, $mode)
    {
        global $request;

        // Task that needs to be done
        $task = $request->variable('task', '');

        // Tasks
        switch ($task)
        {
            // Verify API settings.
            case 'verify_api_settings':
                return $this->verify_api_settings();

            // Autodetect API connection.
            case 'autodetect_api_connection':
                return $this->autodetect_api_connection();

            // Show Settings.
            default:
                return $this->display_settings();
        }
    }

    /**
     * Admin Settings
     */
    protected function display_settings()
    {
        global $user, $template, $config, $phpbb_admin_path, $phpEx, $request;

        // Add the language file.
        $user->add_lang_ext('oneall/singlesignon', 'backend');

        // Set up the page
        $this->tpl_name = 'singlesignon';
        $this->page_title = $user->lang['OA_SINGLE_SIGN_ON_ACP'];

        // Enable Single Sign On?
        $oa_sso_disable = ((isset($config['oa_sso_disable']) && $config['oa_sso_disable'] == '1') ? '1' : '0');

        // Debug logs.
        $oa_sso_enable_debug_logs = ((isset($config['oa_sso_enable_debug_logs']) && $config['oa_sso_enable_debug_logs'] == '1') ? '1' : '0');

        // API Connection
        $oa_sso_api_connection_handler = ((isset($config['oa_sso_api_connection_handler']) && $config['oa_sso_api_connection_handler'] == 'fsockopen') ? 'fsockopen' : 'curl');
        $oa_sso_api_connection_port = ((isset($config['oa_sso_api_connection_port']) && $config['oa_sso_api_connection_port'] == 80) ? 80 : 443);
        $oa_sso_api_subdomain = (isset($config['oa_sso_api_subdomain']) ? $config['oa_sso_api_subdomain'] : '');
        $oa_sso_api_key = (isset($config['oa_sso_api_key']) ? $config['oa_sso_api_key'] : '');
        $oa_sso_api_secret = (isset($config['oa_sso_api_secret']) ? $config['oa_sso_api_secret'] : '');

        // Grace period after logout.
        $oa_sso_blocked_wait_relogin = 3600;

        // Automatic account link for unverified emails.
        $oa_sso_link_unverified_accounts = (isset($config['oa_sso_link_unverified_accounts']) ? $config['oa_sso_link_unverified_accounts'] : 0);

        // Automatically create accounts.
        $oa_sso_auto_create_accounts = (isset($config['oa_sso_auto_create_accounts']) ? $config['oa_sso_auto_create_accounts'] : 1);

        // Automatically link accounts.
        $oa_sso_auto_link_accounts = (isset($config['oa_sso_auto_link_accounts']) ? $config['oa_sso_auto_link_accounts'] : 2);

        // Destroy the session on logout.
        $oa_sso_destroy_session_on_logout = (isset($config['oa_sso_destroy_session_on_logout']) ? $config['oa_sso_destroy_session_on_logout'] : 1);

        // Account reminder if autolink is not available.
        $oa_sso_use_account_reminder = (isset($config['oa_sso_use_account_reminder']) ? $config['oa_sso_use_account_reminder'] : 1);

        // Disables the login for this period whenever an automatic login fails.
        $oa_sso_logout_wait_relogin = (isset($config['oa_sso_logout_wait_relogin']) ? $config['oa_sso_logout_wait_relogin'] : 0);

        // Triggers a form message.
        $oa_sso_settings_saved = false;

        // Security Check.
        add_form_key('oa_sso');

        // Form submitted.
        if ($request->variable('submit', '') != '')
        {
            // Form Security Check.
            if (!check_form_key('oa_sso'))
            {
                trigger_error($user->lang['FORM_INVALID'] . adm_back_link($this->u_action), E_USER_WARNING);
            }

            // Triggers the settings saved message,
            $oa_sso_settings_saved = true;

            // Gather API Connection details.
            $oa_sso_api_connection_handler = ($request->variable('oa_sso_api_connection_handler', 'curl') == 'fs' ? 'fsockopen' : 'curl');
            $oa_sso_api_connection_port = ($request->variable('oa_sso_api_connection_port', 443) == 80 ? 80 : 443);
            $oa_sso_api_subdomain = $request->variable('oa_sso_api_subdomain', '');
            $oa_sso_api_key = $request->variable('oa_sso_api_key', '');
            $oa_sso_api_secret = $request->variable('oa_sso_api_secret', '');

            // Check for full subdomain.
            if (preg_match("/([a-z0-9\-]+)\.api\.oneall\.com/i", $oa_sso_api_subdomain, $matches))
            {
                $oa_sso_api_subdomain = $matches[1];
            }

            // Other options.
            $oa_sso_disable = (($request->variable('oa_sso_disable', 0) == 1) ? 1 : 0);

            $oa_sso_logout_wait_relogin = $request->variable('oa_sso_logout_wait_relogin', 3600);
            $oa_sso_link_unverified_accounts = $request->variable('oa_sso_link_unverified_accounts', 0);
            $oa_sso_auto_create_accounts = $request->variable('oa_sso_auto_create_accounts', 1);
            $oa_sso_auto_link_accounts = $request->variable('oa_sso_auto_link_accounts', 2);
            $oa_sso_destroy_session_on_logout = $request->variable('oa_sso_destroy_session_on_logout', 1);
            $oa_sso_use_account_reminder = $request->variable('oa_sso_use_account_reminder', 1);
            $oa_sso_blocked_wait_relogin = $request->variable('oa_sso_blocked_wait_relogin', 0);
            $oa_sso_enable_debug_logs = $request->variable('oa_sso_enable_debug_logs', 1);

            // Default value
            $config->set('oa_sso_blocked_wait_relogin', $oa_sso_blocked_wait_relogin);

            // Save configuration.
            $config->set('oa_sso_disable', $oa_sso_disable);
            $config->set('oa_sso_api_subdomain', $oa_sso_api_subdomain);
            $config->set('oa_sso_api_key', $oa_sso_api_key);
            $config->set('oa_sso_api_secret', $oa_sso_api_secret);
            $config->set('oa_sso_api_connection_handler', $oa_sso_api_connection_handler);
            $config->set('oa_sso_api_connection_port', $oa_sso_api_connection_port);

            $config->set('oa_sso_logout_wait_relogin', $oa_sso_logout_wait_relogin);
            $config->set('oa_sso_link_unverified_accounts', $oa_sso_link_unverified_accounts);
            $config->set('oa_sso_auto_create_accounts', $oa_sso_auto_create_accounts);
            $config->set('oa_sso_auto_link_accounts', $oa_sso_auto_link_accounts);
            $config->set('oa_sso_destroy_session_on_logout', $oa_sso_destroy_session_on_logout);
            $config->set('oa_sso_use_account_reminder', $oa_sso_use_account_reminder);
            $config->set('oa_sso_enable_debug_logs', $oa_sso_enable_debug_logs);
        }

        // Setup Vars
        $template->assign_vars(array(
            'U_ACTION' => $this->u_action,
            'CURRENT_SID' => $user->data['session_id'],
            'OA_SINGLE_SIGN_ON_AJAX_URL_AUTODETECT' => append_sid($phpbb_admin_path . "index." . $phpEx, array(
                'i' => '-oneall-singlesignon-acp-singlesignon_acp_module',
                'mode' => 'settings',
                'task' => 'autodetect_api_connection'), false),
            'OA_SINGLE_SIGN_ON_AJAX_URL_VERIFY' => append_sid($phpbb_admin_path . "index." . $phpEx, array(
                'i' => '-oneall-singlesignon-acp-singlesignon_acp_module',
                'mode' => 'settings',
                'task' => 'verify_api_settings'), false),
            'OA_SINGLE_SIGN_ON_SETTINGS_SAVED' => $oa_sso_settings_saved,
            'OA_SINGLE_SIGN_ON_DISABLE' => ($oa_sso_disable == '1'),
            'OA_SINGLE_SIGN_ON_AVATARS_ENABLE' => ($oa_sso_avatars_enable == '1'),
            'OA_SINGLE_SIGN_ON_API_SUBDOMAIN' => $oa_sso_api_subdomain,
            'OA_SINGLE_SIGN_ON_API_KEY' => $oa_sso_api_key,
            'OA_SINGLE_SIGN_ON_API_SECRET' => $oa_sso_api_secret,
            'OA_SINGLE_SIGN_ON_API_CONNECTION_HANDLER' => $oa_sso_api_connection_handler,
            'OA_SINGLE_SIGN_ON_API_CONNECTION_HANDLER_CURL' => ($oa_sso_api_connection_handler != 'fsockopen'),
            'OA_SINGLE_SIGN_ON_API_CONNECTION_HANDLER_FSOCKOPEN' => ($oa_sso_api_connection_handler == 'fsockopen'),
            'OA_SINGLE_SIGN_ON_API_CONNECTION_PORT' => $oa_sso_api_connection_port,
            'OA_SINGLE_SIGN_ON_API_CONNECTION_PORT_443' => ($oa_sso_api_connection_port != '80'),
            'OA_SINGLE_SIGN_ON_API_CONNECTION_PORT_80' => ($oa_sso_api_connection_port == '80'),
            'OA_SINGLE_SIGN_ON_LOGIN_PAGE_DISABLE' => ($oa_sso_login_page_disable == '1'),

            'OA_SINGLE_SIGN_ON_ENABLE_LOGS' => $oa_sso_enable_debug_logs,
            'OA_SINGLE_SIGN_ON_LOGOUT_WAIT_RELOGIN' => $oa_sso_logout_wait_relogin,
            'OA_SINGLE_SIGN_ON_AUTOLINK_UNVERIFIED_EMAIL' => $oa_sso_link_unverified_accounts,
            'OA_SINGLE_SIGN_ON_AUTOCREATE_ACCOUNT' => $oa_sso_auto_create_accounts,
            'OA_SINGLE_SIGN_ON_AUTOLINK_ACCOUNT' => $oa_sso_auto_link_accounts,
            'OA_SINGLE_SIGN_ON_DESTROY_SSO_SESSION' => $oa_sso_destroy_session_on_logout,
            'OA_SINGLE_SIGN_ON_USE_ACCOUNT_REMINDER' => $oa_sso_use_account_reminder,
            'OA_SINGLE_SIGN_ON_BLOCK_WAIT_RELOGIN' => $oa_sso_blocked_wait_relogin));

        // Done

        return true;
    }

    /**
     * AutoDetect API Settings - Ajax Call
     */
    protected function autodetect_api_connection()
    {
        global $user;

        // Add the language file.
        $user->add_lang_ext('oneall/singlesignon', 'backend');

        // Check CURL HTTPS - Port 443.
        if ($this->check_curl(true) === true)
        {
            $response = array(
                'success' => true,
                'handler' => 'curl',
                'port' => 443,
                'message' => sprintf($user->lang['OA_SINGLE_SIGN_ON_API_DETECT_CURL'], 443));
        }
        // Check CURL HTTP - Port 80.
        elseif ($this->check_curl(false) === true)
        {
            $response = array(
                'success' => true,
                'handler' => 'curl',
                'port' => 80,
                'message' => sprintf($user->lang['OA_SINGLE_SIGN_ON_API_DETECT_CURL'], 80));
        }
        // Check FSOCKOPEN HTTPS - Port 443.
        elseif ($this->check_fsockopen(true) == true)
        {
            $response = array(
                'success' => true,
                'handler' => 'fsockopen',
                'port' => 443,
                'message' => sprintf($user->lang['OA_SINGLE_SIGN_ON_API_DETECT_FSOCKOPEN'], 443));
        }
        // Check FSOCKOPEN HTTP - Port 80.
        elseif ($this->check_fsockopen(false) == true)
        {
            $response = array(
                'success' => true,
                'handler' => 'fsockopen',
                'port' => 80,
                'message' => sprintf($user->lang['OA_SINGLE_SIGN_ON_API_DETECT_FSOCKOPEN'], 80));
        }
        // No working handler found.
        else
        {
            $response = array(
                'success' => false,
                'message' => $user->lang['OA_SINGLE_SIGN_ON_API_DETECT_NONE']);
        }

        // Output for Ajax.
        $json_response = new \phpbb\json_response();
        $json_response->send($response);
    }

    /**
     * Verify API Settings - Ajax Call
     */
    protected function verify_api_settings()
    {
        global $user, $request, $phpbb_container, $config;

        // Add the language file.
        $user->add_lang_ext('oneall/singlesignon', 'backend');

        // Read arguments.
        $api_subdomain = trim(strtolower($request->variable('api_subdomain', '')));
        $api_key = trim($request->variable('api_key', ''));
        $api_secret = trim($request->variable('api_secret', ''));
        $api_connection_port = $request->variable('api_connection_port', '');
        $api_connection_handler = $request->variable('api_connection_handler', '');

        // Init status message.
        $status_success = false;
        $status_message = null;

        // Check if all fields have been filled out.
        if (strlen($api_subdomain) == 0 || strlen($api_key) == 0 || strlen($api_secret) == 0)
        {
            $status_message = $user->lang['OA_SINGLE_SIGN_ON_API_CREDENTIALS_FILL_OUT'];
        }
        else
        {
            // Check the handler
            $api_connection_handler = ($api_connection_handler == 'fs' ? 'fsockopen' : 'curl');
            $api_connection_use_https = ($api_connection_port == 443 ? true : false);

            // FSOCKOPEN
            if ($api_connection_handler == 'fsockopen')
            {
                if (!$this->check_fsockopen($api_connection_use_https))
                {
                    $status_message = $user->lang['OA_SINGLE_SIGN_ON_API_CREDENTIALS_USE_AUTO'];
                }
            }
            // CURL
            else
            {
                if (!$this->check_curl($api_connection_use_https))
                {
                    $status_message = $user->lang['OA_SINGLE_SIGN_ON_API_CREDENTIALS_USE_AUTO'];
                }
            }

            // No errors until now.
            if (empty($status_message))
            {
                // The full domain has been entered.
                if (preg_match("/([a-z0-9\-]+)\.api\.oneall\.com/i", $api_subdomain, $matches))
                {
                    $api_subdomain = $matches[1];
                }

                // Check format of the subdomain.
                if (!preg_match("/^[a-z0-9\-]+$/i", $api_subdomain))
                {
                    $status_message = $user->lang['OA_SINGLE_SIGN_ON_API_CREDENTIALS_SUBDOMAIN_WRONG'];
                }
                else
                {
                    // Construct full API Domain.
                    $api_domain = $api_subdomain . '.api.oneall.com';
                    $api_resource_url = ($api_connection_use_https ? 'https' : 'http') . '://' . $api_domain . '/site/allowed-domains.json';

                    // Domain
                    $phpbb_domain = ($config['server_name'] ?: $request->server('SERVER_NAME', 'phpbb.generated'));

                    // API Credentialls.
                    $api_options = array();
                    $api_options['api_key'] = $api_key;
                    $api_options['api_secret'] = $api_secret;
                    $api_options['method'] = 'PUT';
                    $api_options['data'] = json_encode(array(
                        'request' => array(
                            'allowed_domains' => array(
                                $phpbb_domain))));

                    // Try to establish a connection, this will also whitelist the domain.
                    $result = $phpbb_container->get('oneall.singlesignon.helper')->do_api_request($api_connection_handler, $api_resource_url, $api_options);

                    switch ($result->get_code())
                    {
                        // Connection successfull.
                        case 200:
                        case 201:
                            $status_message = $user->lang['OA_SINGLE_SIGN_ON_API_CREDENTIALS_OK'];
                            $status_success = true;
                            break;

                        // Authentication Error.
                        case 401:
                            $status_message = $user->lang['OA_SINGLE_SIGN_ON_API_CREDENTIALS_KEYS_WRONG'];
                            break;

                        // Limit Exceed
                        case 403:
                            $data = json_decode($result->get_data(), true);
                            $error_message = !empty($data['response']['request']['status']['info']) ? $data['response']['request']['status']['info'] : null;

                            if (!empty($error_message) && strpos($error_message, 'exceeded') !== false)
                            {
                                $status_message = $user->lang['OA_SINGLE_SIGN_ON_API_CREDENTIALS_OK'];
                                $status_success = true;
                            }
                            else
                            {
                                $status_message = $user->lang['OA_SINGLE_SIGN_ON_API_CREDENTIALS_CHECK_COM'];
                            }
                            break;

                        // Wrong Subdomain.
                        case 404:
                            $status_message = $user->lang['OA_SINGLE_SIGN_ON_API_CREDENTIALS_SUBDOMAIN_WRONG'];
                            break;

                        // Another error.
                        default:
                            $status_message = $user->lang['OA_SINGLE_SIGN_ON_API_CREDENTIALS_CHECK_COM'];
                            break;
                    }
                }
            }
        }

        // Output for Ajax.
        $json_response = new \phpbb\json_response();
        $json_response->send(array(
            'success' => $status_success,
            'message' => $status_message));
    }

    /**
     * Returns a list of disabled PHP functions.
     */
    protected function get_php_disabled_functions()
    {
        $disabled_functions = trim(ini_get('disable_functions'));
        if (strlen($disabled_functions) == 0)
        {
            $disabled_functions = array();
        }
        else
        {
            $disabled_functions = explode(',', $disabled_functions);
            $disabled_functions = array_map('trim', $disabled_functions);
        }

        return $disabled_functions;
    }

    /**
     * Checks if CURL can be used.
     */
    public function check_curl($secure = true)
    {
        global $phpbb_container;

        if (in_array('curl', get_loaded_extensions()) && function_exists('curl_exec') && !in_array('curl_exec', $this->get_php_disabled_functions()))
        {
            $result = $phpbb_container->get('oneall.singlesignon.helper')->curl_request(($secure ? 'https' : 'http') . '://www.oneall.com/ping.html');
            if ($result->get_code() == 200 && strtolower($result->get_data()) == 'ok')
            {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks if FSOCKOPEN can be used.
     */
    public function check_fsockopen($secure = true)
    {
        global $phpbb_container;

        if (function_exists('fsockopen') && !in_array('fsockopen', $this->get_php_disabled_functions()))
        {
            $result = $phpbb_container->get('oneall.singlesignon.helper')->fsockopen_request(($secure ? 'https' : 'http') . '://www.oneall.com/ping.html');
            if ($result->get_code() == 200 && strtolower($result->get_data()) == 'ok')
            {
                return true;
            }
        }

        return false;
    }
}
