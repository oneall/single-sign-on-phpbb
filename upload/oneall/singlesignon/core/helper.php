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
 * Helper
 */
class helper
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
    public function __construct(\phpbb\config\config $config, \phpbb\request\request $request, \phpbb\template\template $template, \phpbb\log\log $log, \phpbb\user $user, \phpbb\auth\auth $auth, \phpbb\db\driver\factory $db, \phpbb\event\dispatcher $phpbb_dispatcher, \phpbb\passwords\manager $passwords_manager, $phpbb_root_path, $php_ext, $table_prefix)
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
    }

    /**
     * Login the current user with the give $user_id.
     */
    protected function do_login($user_id, $check_admin = false)
    {
        // Grab the list of admins to check if this user is an administrator.
        if ($check_admin === true)
        {
            $admin_user_ids = $this->auth->acl_get_list(false, 'a_user', false);
            $admin_user_ids = (!empty($admin_user_ids[0]['a_user'])) ? $admin_user_ids[0]['a_user'] : array();
            $is_admin = (in_array($user_id, $admin_user_ids) ? true : false);

            // Store the old session id for later use.
            $old_session_id = $this->user->session_id;

            // This user is an administrator.
            if ($is_admin === true)
            {
                global $SID, $_SID;

                // Refresh the cookie.
                $cookie_expire = time() - 31536000;
                $this->user->set_cookie('u', '', $cookie_expire);
                $this->user->set_cookie('sid', '', $cookie_expire);

                // Refresh the session id.
                $SID = '?sid=';
                $this->user->session_id = $_SID = '';
            }
        }
        else
        {
            $is_admin = false;
        }

        // Log the user in.
        $result = $this->user->session_create($user_id, $is_admin);

        // Session created successfully.
        if ($result === true)
        {
            //  For admins remove the old session entry as a new one needs to been created.
            if ($is_admin === true)
            {
                $sql = 'DELETE FROM ' . SESSIONS_TABLE . " WHERE session_id = '" . $this->db->sql_escape($old_session_id) . "' AND session_user_id = " . (int) $user_id;
                $this->db->sql_query($sql);
            }

            // Re-init the auth array to get correct results on login/logout.
            $this->auth->acl($this->user->data);

            //////////////////////////
            // Trigger Login event
            $login = array(
                'status' => LOGIN_SUCCESS,
                'error_msg' => false,
                'user_row' => $this->user->data
            );
            $admin = $is_admin;
            $username = $this->user->data['username'];
            $autologin = false;

            $vars = array(
                'login',
                'admin',
                'username',
                'autologin'
            );
            extract($this->dispatcher->trigger_event('core.auth_login_session_create_before', compact($vars)));

            //////////////////////////

            return true;
        }

        return false;
    }

    /**
     * Complete callback once credentials validated.
     */
    public function sso_redirect($error_message, $user_id, $user_data)
    {
        // Display an error message
        if (!empty($error_message))
        {
            $error_message = $error_message . '<br /><br />' . sprintf($this->user->lang['RETURN_INDEX'], '<a href="' . append_sid($this->phpbb_root_path . 'index.' . $this->php_ext) . '">', '</a>');
            trigger_error($error_message);
        }
        // Process
        else
        {
            if (is_numeric($user_id))
            {
                // Update statistics.
                $this->count_login_identity_token($user_data['identity_token']);

                // Log the user in.
                $this->do_login($user_id);

                // Do not stay on the login/registration page.
                if (in_array($this->request->variable('mode', ''), array('login', 'register')))
                {
                    $this->http_redirect($this->phpbb_root_path . 'index.' . $this->php_ext);
                }

                // Do we have a redirection as argument?
                if (isset($user_data['redirect']))
                {
                    $this->http_redirect($user_data['redirect']);
                }

                // Default: Reload the current page.
                $this->http_redirect($this->get_current_url());
            }
        }
    }

    // Get API url
    public function get_api_url()
    {
        // Helper Settings.
        $base_url = ($this->config['oa_sso_api_subdomain'] . '.api.oneall.com');

        // Extract Protocol
        $request_protocol = ($this->is_https_on() ? 'https' : 'http');
        $api_url = ($request_protocol . '://' . $base_url);

        return $api_url;
    }

    // Get connection handler
    public function get_connection_handler()
    {
        // API Settings.
        $api_connection_handler = ((!empty($this->config['oa_sso_api_connection_handler']) && $this->config['oa_sso_api_connection_handler'] == 'fsockopen') ? 'fsockopen' : 'curl');

        return $api_connection_handler;
    }

    // Redirection
    public function http_redirect($url, $append_sid = true)
    {
        if ($append_sid)
        {
            $url = append_sid($url);
        }

        redirect($url, false, true);
    }

    /**
     * Checks if the current connection is being made over https
     */
    private function is_https_on()
    {
        if ($this->request->server('SERVER_PORT') == 443)
        {
            return true;
        }

        if ($this->request->server('HTTP_X_FORWARDED_PROTO') == 'https')
        {
            return true;
        }

        if (in_array(strtolower(trim($this->request->server('HTTPS'))), array('on', '1')))
        {
            return true;
        }

        return false;
    }

    /**
     * Returns the current url
     */
    public function get_current_url($add_vars = array(), $remove_vars = array(), $remove_extra_vars = true, $full_url = true)
    {
        // Extract Uri
        if (strlen(trim($this->request->server('REQUEST_URI'))) > 0)
        {
            $request_uri = trim($this->request->server('REQUEST_URI'));
        }
        else
        {
            $request_uri = trim($this->request->server('PHP_SELF'));
        }

        // Decode URI
        $request_uri = htmlspecialchars_decode($request_uri);

        // Extract Protocol
        $request_protocol = ($this->is_https_on() ? 'https' : 'http');

        // Extract Host
        if (strlen(trim($this->request->server('HTTP_X_FORWARDED_HOST'))) > 0)
        {
            $request_host = trim($this->request->server('HTTP_X_FORWARDED_HOST'));
        }
        elseif (strlen(trim($this->request->server('HTTP_HOST'))) > 0)
        {
            $request_host = trim($this->request->server('HTTP_HOST'));
        }
        else
        {
            $request_host = trim($this->request->server('SERVER_NAME'));
        }

        // Port of this request
        $request_port = '';

        // We are using a proxy
        if (strlen(trim($this->request->server('HTTP_X_FORWARDED_PORT'))) > 0)
        {
            // SERVER_PORT is usually wrong on proxies, don't use it!
            $request_port = intval($this->request->server('HTTP_X_FORWARDED_PORT'));
        }
        // Does not seem like a proxy
        else
        {
            if (strlen(trim($this->request->server('SERVER_PORT'))) > 0)
            {
                $request_port = intval($this->request->server('SERVER_PORT'));
            }
        }

        // Remove standard ports
        $request_port = (!in_array($request_port, array(80, 443, $this->config['server_port'])) ? $request_port : '');

        // Build url
        $current_url = $request_protocol . '://' . $request_host . (!empty($request_port) ? (':' . $request_port) : '') . ($full_uri ? $request_uri : '');

        // Remove arguments.
        if (!is_array($remove_vars))
        {
            $remove_vars = array();
        }

        // Remove extra arguments.
        if ($remove_extra_vars)
        {
            $remove_vars[] = 'oa_sso_login_token';
            $remove_vars[] = 'sid';
        }

        // Break up url
        list($url_part, $query_part) = array_pad(explode('?', $current_url), 2, '');
        parse_str($query_part, $query_vars);

        // Remove argument.
        if (is_array($query_vars))
        {
            foreach ($remove_vars as $var)
            {
                if (isset($query_vars[$var]))
                {
                    unset($query_vars[$var]);
                }
            }
        }
        else
        {
            $query_vars = array();
        }

        if (is_array($add_vars))
        {
            foreach ($add_vars as $key => $value)
            {
                $query_vars[$key] = $value;
            }
        }

        // Build new url
        $current_url = $url_part . ((is_array($query_vars) && count($query_vars) > 0) ? ('?' . http_build_query($query_vars)) : '');

        // Done

        return $current_url;
    }

    /**
     * Get the default group_id for new users
     */
    public function get_default_group_id()
    {
        // Read the default group.
        $sql = "SELECT group_id FROM " . GROUPS_TABLE . " WHERE group_name = 'REGISTERED' AND group_type = " . GROUP_SPECIAL;
        $query = $this->db->sql_query($sql);
        $result = $this->db->sql_fetchrow($query);
        $this->db->sql_freeresult($query);

        // Group found;
        if (is_array($result) && isset($result['group_id']))
        {
            return $result['group_id'];
        }

        // Not found

        return false;
    }

    /**
     * Inverts CamelCase -> camel_case.
     */
    public function undo_camel_case($input)
    {
        $result = $input;

        if (preg_match_all('!([A-Z][A-Z0-9]*(?=$|[A-Z][a-z0-9])|[A-Za-z][a-z0-9]+)!', $input, $matches))
        {
            $ret = $matches[0];

            foreach ($ret as &$match)
            {
                $match = ($match == strtoupper($match) ? strtolower($match) : lcfirst($match));
            }

            $result = implode('_', $ret);
        }

        return $result;
    }

    /**
     * Get the user_id for a given email address.
     */
    protected function get_user_id_by_email($email)
    {
        // Read the user_id for this email address.
        $sql = "SELECT user_id FROM " . USERS_TABLE . "
                WHERE user_email  = '" . $this->db->sql_escape($email) . "'";
        $query = $this->db->sql_query_limit($sql, 1);
        $result = $this->db->sql_fetchrow($query);
        $this->db->sql_freeresult($query);

        // We have found an user_id.
        if (is_array($result) && !empty($result['user_id']))
        {
            return $result['user_id'];
        }

        // Not found.

        return false;
    }

    /**
     * Get the user data for a user_id
     */
    public function get_user_data_by_user_id($user_id)
    {
        // Read the user_id for this user_id address.
        $sql = "SELECT * FROM " . USERS_TABLE . "
                WHERE user_id  = '" . intval($user_id) . "'";
        $query = $this->db->sql_query_limit($sql, 1);
        $result = $this->db->sql_fetchrow($query);
        $this->db->sql_freeresult($query);

        // The user has been found.
        if (is_array($result))
        {
            unset($result['user_password']);
            unset($result['user_passchg']);
            unset($result['user_form_salt']);

            return $result;
        }

        // Not found.

        return array();
    }

    /**
     * Get the user data for a user_id
     */
    public function get_user_data_by_email($email)
    {
        // Read the user_id for this email address.
        $sql = "SELECT * FROM " . USERS_TABLE . "
                WHERE user_email  = '" . $this->db->sql_escape($email) . "'";
        $query = $this->db->sql_query_limit($sql, 1);
        $result = $this->db->sql_fetchrow($query);
        $this->db->sql_freeresult($query);

        // The user has been found.
        if (is_array($result))
        {
            unset($result['user_password']);
            unset($result['user_passchg']);
            unset($result['user_form_salt']);

            return $result;
        }

        // Not found.

        return array();
    }

    /**
     * Generates a random email address
     */
    public function generate_random_email()
    {
        // User functions
        if (!function_exists('gen_rand_string'))
        {
            require $this->phpbb_root_path . 'includes/functions.' . $this->php_ext;
        }

        do
        {
            $email = strtolower(gen_rand_string(10)) . "@example.com";
        } while ($this->get_user_id_by_email($email) !== false);

        // Done

        return $email;
    }

    /**
     * Sends an API request by using the given handler.
     */
    public function do_api_request($handler, $url, $options = array(), $timeout = 30)
    {
        // FSOCKOPEN
        if ($handler == 'fsockopen')
        {
            return $this->fsockopen_request($url, $options, $timeout);
        }
        // CURL
        else
        {
            return $this->curl_request($url, $options, $timeout);
        }
    }

    /**
     * Sends a CURL request.
     */
    public function curl_request($url, $options = array(), $timeout = 30, $num_redirects = 0)
    {
        // Store the result
        $result = new \stdClass();

        // Send request
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_HEADER, 0);
        curl_setopt($curl, CURLOPT_TIMEOUT, $timeout);
        curl_setopt($curl, CURLOPT_VERBOSE, 0);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($curl, CURLOPT_USERAGENT, self::USER_AGENT);

        // HTTP Method
        switch (strtoupper($options['method']))
        {
            case 'DELETE':
                curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'DELETE');
                break;

            case 'PUT':
                curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'PUT');
                break;

            case 'POST':
                curl_setopt($curl, CURLOPT_POST, 1);
                break;

            default:
                curl_setopt($curl, CURLOPT_HTTPGET, 1);
                break;
        }

        // HTTP AUTH
        if (isset($options['api_key']) and isset($options['api_secret']))
        {
            curl_setopt($curl, CURLOPT_USERPWD, $options['api_key'] . ":" . $options['api_secret']);
        }

        // POST Data
        if (isset($options['api_data']))
        {
            curl_setopt($curl, CURLOPT_POSTFIELDS, $options['api_data']);
        }

        // Make request
        if (($http_data = curl_exec($curl)) !== false)
        {
            $result->http_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            $result->http_data = $http_data;
            $result->http_error = null;
        }
        else
        {
            $result->http_code = -1;
            $result->http_data = null;
            $result->http_error = curl_error($curl);
        }

        // Store the result
        $result = new \oneall\singlesignon\core\api_result();

        // Make request
        if (($response = curl_exec($curl)) !== false)
        {
            // Get Information
            $curl_info = curl_getinfo($curl);

            // Save result
            $result->set_result(array(
                'code' => $curl_info['http_code'],
                'headers' => preg_split('/\r\n|\n|\r/', trim(substr($response, 0, $curl_info['header_size']))),
                'data' => @json_decode($response),
                'status_success' => 'request_success'));

            // Check if we have a redirection header
            if (in_array($result->get_code(), array(301, 302)) && $num_redirects < 4)
            {
                // Header found ?
                $header_found = false;

                // Loop through headers.
                $headers = $result->get_headers();
                while (!$header_found && (list(, $header) = each($headers)))
                {
                    // Try to parse a redirection header.
                    if (preg_match("/(Location:|URI:)[^(\n)]*/i", $header, $matches))
                    {
                        // Sanitize redirection url.
                        $url_tmp = trim(str_replace($matches[1], "", $matches[0]));
                        $url_parsed = parse_url($url_tmp);
                        if (!empty($url_parsed))
                        {
                            // Header found!
                            $header_found = true;

                            // Follow redirection url.
                            $result = $this->curl_request($url_tmp, $options, $timeout, $num_redirects + 1);
                        }
                    }
                }
            }
        }
        // Error
        else
        {
            $result->set_status_error(curl_error($curl));
        }

        return $result;
    }

    /**
     * Sends an fsockopen request.
     */
    public function fsockopen_request($url, $options = array(), $timeout = 30, $num_redirects = 0)
    {
        // Store the result
        $result = new \oneall\singlesignon\core\api_result();

        // Make that this is a valid URL
        if (($uri = parse_url($url)) == false)
        {
            $result->set_status_error('invalid_uri');

            return $result;
        }

        // Make sure we can handle the schema
        switch ($uri['scheme'])
        {
            case 'http':
                $port = (isset($uri['port']) ? $uri['port'] : 80);
                $host = ($uri['host'] . ($port != 80 ? ':' . $port : ''));
                $fp = @fsockopen($uri['host'], $port, $errno, $errstr, $timeout);
                break;

            case 'https':
                $port = (isset($uri['port']) ? $uri['port'] : 443);
                $host = ($uri['host'] . ($port != 443 ? ':' . $port : ''));
                $fp = @fsockopen('ssl://' . $uri['host'], $port, $errno, $errstr, $timeout);
                break;

            default:
                $result->set_status_error('invalid_schema');

                return $result;
                break;
        }

        // Make sure the socket opened properly
        if (!$fp)
        {
            $result->set_status_error($errstr);

            return $result;
        }

        // Construct the path to act on
        $path = (isset($uri['path']) ? $uri['path'] : '/');
        if (isset($uri['query']))
        {
            $path .= '?' . $uri['query'];
        }

        // Create HTTP request
        $request = array();

        // Custom Request
        if (!empty($options['method']))
        {
            $request[] = strtoupper(trim($options['method'])) . " " . $path . " HTTP/1.1";
        }
        // Default GET Request
        else
        {
            $request[] = 'GET ' . $path . " HTTP/1.0";
        }

        $request[] = 'Host: ' . $host;
        $request[] = 'User-Agent: ' . self::USER_AGENT;

        // BASIC AUTH?
        if (isset($options['api_key']) && isset($options['api_secret']))
        {
            $request[] = 'Authorization: Basic ' . base64_encode($options['api_key'] . ":" . $options['api_secret']);
        }

        // Data
        $content = null;

        if (!empty($options['data']))
        {
            if (is_array($options['data']))
            {
                $data_values = array();
                foreach ($options['data'] as $key => $value)
                {
                    $data_values[] = $key . '=' . urlencode($value);
                }
                $content = implode("&", $data_values);
            }
            else
            {
                $content = trim(strval($options['data']));
            }

            // Setup POST Data
            $request[] = "Content-Type: application/json";
            $request[] = "Content-Length: " . strlen($content);
            $request[] = "Connection: Close";
        }

        // Send Headers
        fwrite($fp, (implode("\r\n", $request)) . "\r\n\r\n");

        // Send Content
        if (!empty($content))
        {
            fwrite($fp, $content);
        }

        // Fetch response
        $response = '';
        while (!feof($fp))
        {
            $response .= fread($fp, 1024);
        }

        // Close connection
        fclose($fp);

        // Parse response
        list($response_header, $response_body) = explode("\r\n\r\n", $response, 2);

        // Parse header
        $response_headers = preg_split("/\r\n|\n|\r/", $response_header);
        list($header_protocol, $header_code, $header_status_message) = explode(' ', trim(array_shift($response_headers)), 3);

        // Save result
        $result->set_result(array(
            'code' => $header_code,
            'headers' => $response_headers,
            'data' => $response_body,
            'status_success' => $header_status_message));

        // Make sure we we have a redirection status code
        if (in_array($result->get_code(), array(301, 302)) && $num_redirects <= 4)
        {
            // Header found?
            $header_found = false;

            // Loop through headers.
            $headers = $result->get_headers();
            while (!$header_found && (list(, $header) = each($headers)))
            {
                // Check for location header
                if (preg_match("/(Location:|URI:)[^(\n)]*/i", $header, $matches))
                {
                    // Sanitize redirection url.
                    $url_tmp = trim(str_replace($matches[1], "", $matches[0]));
                    $url_parsed = parse_url($url_tmp);
                    if (!empty($url_parsed))
                    {
                        // Header found!
                        $header_found = true;

                        // Follow redirection url.
                        $result = $this->fsockopen_request($url_tmp, $options, $timeout, $num_redirects + 1);
                    }
                }
            }
        }

        // Done

        return $result;
    }

    /**
     * Write to the phpBB log file.
     */
    public function add_log($message)
    {
        if (!empty($this->config['oa_sso_enable_debug_logs']))
        {
            $this->log->add('user', $this->user->data['user_id'], $this->user->data['user_ip'], 'LOG_SSO_ONEALL', time(), array('message' => $message));
        }
    }

    public function get_cookie_value($cookie_name)
    {
        return $this->request->variable($this->config['cookie_name'] . '_' . $cookie_name, '', false, \phpbb\request\request_interface::COOKIE);
    }

    // ** DRUPAL
    /**
     * Remove the login-wait cookie.
     */
    public function unset_login_wait_cookie()
    {
        // Remove Cookie.
        $this->user->set_cookie(SINGLE_SIGN_ON_LOGIN_WAIT_COOKIE_KEY, '', (time() - (15 * 60)));
    }

    // ** DRUPAL
    /**
     * Get the login-wait value from a cookie.
     */
    public function get_login_wait_value_from_cookie()
    {
        $value = $this->get_cookie_value(SINGLE_SIGN_ON_LOGIN_WAIT_COOKIE_KEY);

        return empty($value) ? 0 : $value;
    }

    // ** DRUPAL
    /**
     * Set the login wait cookie.
     */
    public function set_login_wait_cookie($period)
    {
        // No automatic logins before this time.
        $period = ($period + time());

        // Set cookies.
        $this->user->set_cookie(SINGLE_SIGN_ON_LOGIN_WAIT_COOKIE_KEY, $period, $period);

        return $period;
    }

    // ** DONE
    // ** DRUPAL
    /**
     * links a user_token to a user_id.
     */
    public function link_user_token_to_user_id($user_id, $user_token)
    {
        $oasl_user_id = $this->get_oasl_user_id_for_user_token($user_token);

        // non existing -> create it
        if (!$oasl_user_id)
        {
            // Add new link.
            $sql_arr = array(
                'user_id' => intval($user_id),
                'user_token' => $user_token,
                'date_added' => time());
            $sql = "INSERT INTO " . $this->table_prefix . "oasl_user " . $this->db->sql_build_array('INSERT', $sql_arr);
            $this->db->sql_query($sql);

            // Identifier of the newly created user_token entry.
            $oasl_user_id = $this->db->sql_nextid();
        }

        return $oasl_user_id;
    }

    // ** DONE
    // ** DRUPAL
    /**
     * Return the oasl_user_id for a user_token.
     */
    public function get_oasl_user_id_for_user_token($user_token)
    {
        // Make sure that that the user exists.
        $sql = "SELECT oasl_user_id FROM " . $this->table_prefix . "oasl_user
                WHERE user_token  = '" . $this->db->sql_escape($user_token) . "'";
        $query = $this->db->sql_query_limit($sql, 1);
        $result = $this->db->sql_fetchrow($query);
        $this->db->sql_freeresult($query);

        return (is_array($result) && !empty($result['oasl_user_id'])) ? $result['oasl_user_id'] : null;
    }

    // ** DONE
    // ** DRUPAL
    /**
     * Return the user_id for a user_token.
     */
    public function get_user_id_for_user_token($user_token)
    {
        // Make sure that that the user exists.
        $sql = "SELECT user_id FROM " . $this->table_prefix . "oasl_user
                WHERE user_token  = '" . $this->db->sql_escape($user_token) . "'";
        $query = $this->db->sql_query_limit($sql, 1);
        $result = $this->db->sql_fetchrow($query);
        $this->db->sql_freeresult($query);

        return (is_array($result) && !empty($result['user_id'])) ? $result['user_id'] : null;
    }

    // ** DONE
    // ** DRUPAL
    /**
     * links a user_token to a identity_token.
     */
    public function link_user_to_identity($oasl_user_id, $identity_token, $identity_provider = '')
    {
        $existing_token_user_id = $this->get_userid_for_identity_token($identity_token);

        // non existing -> create it
        if (!$existing_token_user_id)
        {
            // Add new link.
            $sql_arr = array(
                'oasl_user_id' => intval($oasl_user_id),
                'identity_token' => $identity_token,
                'identity_provider' => $identity_provider,
                'num_logins' => 1,
                'date_added' => time(),
                'date_updated' => time());
            $sql = "INSERT INTO " . $this->table_prefix . "oasl_identity " . $this->db->sql_build_array('INSERT', $sql_arr);
            $this->db->sql_query($sql);

            // Identifier of the newly created user_token entry.
            $oasl_identity_id = $this->db->sql_nextid();

            return $oasl_identity_id;
        }
        else
        {
            // Update the counter for the given identity_token.
            $sql = "UPDATE " . $this->table_prefix . "oasl_identity
                    SET num_logins=num_logins+1,
                    date_updated= " . time() . "
                    WHERE oasl_user_id = '" . $this->db->sql_escape($oasl_user_id) . "'";
            $this->db->sql_query($sql);

            // Make sure that that the user exists.
            $sql = "SELECT oasl_identity_id FROM " . $this->table_prefix . "oasl_identity
                WHERE oasl_user_id = '" . $this->db->sql_escape($oasl_user_id) . "'";
            $query = $this->db->sql_query_limit($sql, 1);
            $result = $this->db->sql_fetchrow($query);
            $this->db->sql_freeresult($query);

            return (is_array($result) && !empty($result['oasl_identity_id'])) ? $result['oasl_identity_id'] : null;
        }
    }

    // ** DONE
    // ** DRUPAL
    /**
     * Return the identity_token for a identity_token.
     */
    public function get_userid_for_identity_token($identity_token)
    {
        // Make sure that that the user exists.
        $sql = "SELECT oasl_user_id FROM " . $this->table_prefix . "oasl_identity
                WHERE identity_token  = " . (int) $identity_token;
        $query = $this->db->sql_query_limit($sql, 1);
        $result = $this->db->sql_fetchrow($query);
        $this->db->sql_freeresult($query);

        // The user exists.

        return (is_array($result) && !empty($result['oasl_user_id'])) ? $result['oasl_user_id'] : null;
    }

    // ** DONE
    // ** DRUPAL
    /**
     * Add the cloud storage tokens of a user to the local database.
     */
    public function add_local_storage_tokens_for_uid($uid, $user_token, $identity_token, $provider = '')
    {
        // Add user token to database
        $oasl_user_id = $this->link_user_token_to_user_id($uid, $user_token);

        // Add identity token to database
        $oasl_identityid = $this->link_user_to_identity($oasl_user_id, $identity_token, $provider);

        return [$oasl_user_id, $oasl_identityid];
    }

    // ** DONE
    // ** DRUPAL
    /**
     * Return the oasl_user for a user_token.
     */
    public function get_oasl_user_for_user_id($user_id)
    {
        // Read the user_id for this user_token.
        $sql = "SELECT * FROM " . $this->table_prefix . "oasl_user WHERE user_id = " . (int) $user_id;
        $query = $this->db->sql_query_limit($sql, 1);
        $result = $this->db->sql_fetchrow($query);
        $this->db->sql_freeresult($query);

        // The user_token exists
        if (is_array($result) && !empty($result['user_token']))
        {
            return $result;
        }

        // Not found

        return false;
    }

    // ** DONE
    // ** DRUPAL
    /**
     * Return the oasl_identity for a user_token.
     */
    public function get_oasl_identity_for_user_id($user_id)
    {
        // Read the user_id for this sso_session_token.
        $sql = "SELECT * FROM " . $this->table_prefix . "oasl_identity AS oasli
        INNER JOIN  " . $this->table_prefix . "oasl_user AS oaslu ON oasli.oasl_user_id = oaslu.oasl_user_id
        WHERE user_id = " . (int) $user_id;
        $query = $this->db->sql_query_limit($sql, 1);
        $result = $this->db->sql_fetchrow($query);
        $this->db->sql_freeresult($query);

        // The identity_token exists
        if (is_array($result) && !empty($result['identity_token']))
        {
            return $result;
        }

        // Not found

        return false;
    }

    // ** DONE
    // ** DRUPAL
    /**
     * Return the user_token for a user_id.
     */
    public function get_user_token_information_for_uid($user_id)
    {
        $oasl_user = $this->get_oasl_user_for_user_id($user_id);
        $oasl_identity = $this->get_oasl_identity_for_user_id($user_id);

        $token = new \stdClass();

        if ($oasl_user)
        {
            $token->oasl_user_id = $oasl_user['oasl_user_id'];
            $token->user_id = $oasl_user['user_id'];
            $token->oasl_identity_id = $oasl_user['user_id'];
            $token->user_token = $oasl_user['user_token'];
        }

        if ($oasl_identity)
        {
            $token->identity_token = $oasl_identity['identity_token'];
            $token->identity_provider = $oasl_identity['identity_provider'];
            $token->sso_session_token = $oasl_identity['sso_session_token'];
            $token->sso_session_token_expiration = $oasl_identity['sso_session_token_expiration'];
        }

        return $token;
    }

    /**
     * Get the identity_token from a user_id
     */
    public function get_identity_token_for_user_id($user_id)
    {
        // Read the user_id for this sso_session_token.
        $sql = "SELECT identity_token FROM " . $this->table_prefix . "oasl_identity AS oasli
        INNER JOIN  " . $this->table_prefix . "oasl_user AS oaslu ON oasli.oasl_user_id = oaslu.oasl_user_id
        WHERE user_id = " . (int) $user_id;
        $query = $this->db->sql_query_limit($sql, 1);
        $result = $this->db->sql_fetchrow($query);
        $this->db->sql_freeresult($query);

        // The identity_token exists
        if (is_array($result) && !empty($result['identity_token']))
        {
            return $result['identity_token'];
        }

        // Not found

        return false;
    }

    /**
     * Returns the sso session token of a user from the local database.
     */
    public function get_local_sso_session_token_for_id($user_id)
    {
        // Result container.
        $status = new \stdClass();
        $status->is_successfull = false;

        // Read the user_id for this sso_session_token.
        $sql = "SELECT sso_session_token, sso_session_token_expiration FROM " . $this->table_prefix . "oasl_identity AS oasli
        INNER JOIN  " . $this->table_prefix . "oasl_user AS oaslu ON oasli.oasl_user_id = oaslu.oasl_user_id
        WHERE user_id = " . (int) $user_id;
        $query = $this->db->sql_query_limit($sql, 1);
        $result = $this->db->sql_fetchrow($query);
        $this->db->sql_freeresult($query);

        // The sso_session_token exists
        if (is_array($result) && !empty($result['sso_session_token']))
        {
            // Update Status.
            $status->sso_session_token = $result['sso_session_token'];
            $status->date_expiration = $result['sso_session_token_expiration'];
            $status->is_successfull = true;

            return $status;
        }

        // Not found

        return false;
    }

    /**
     * Add SSO Session to exisitng identity_id
     */
    public function add_sso_session_token_to_oasl_identity_id($oasl_identity_id, $sso_session_token, $date_expiration = null)
    {
        $sql = "UPDATE " . $this->table_prefix . "oasl_identity
                SET sso_session_token='" . $this->db->sql_escape($sso_session_token) . "',
                sso_session_token_expiration='" . $this->db->sql_escape($date_expiration) . "',
                WHERE oasl_identity_id = '" . $this->db->sql_escape($oasl_identity_id) . "'";
        $this->db->sql_query($sql);
    }

    /**
     * Add SSO Session to identity_token
     */
    public function add_sso_session_token_to_identity_token($identity_token, $sso_session_token, $date_expiration = null)
    {
        $sql = "UPDATE " . $this->table_prefix . "oasl_identity
                SET sso_session_token='" . $this->db->sql_escape($sso_session_token) . "',
                sso_session_token_expiration='" . $this->db->sql_escape($date_expiration) . "'
                WHERE identity_token = '" . $this->db->sql_escape($identity_token) . "'";
        $this->db->sql_query($sql);
    }

    /**
     * Delete SSO Session to identity_token
     */
    public function delete_sso_session_token_to_identity_token($identity_token)
    {
        $sql = "UPDATE " . $this->table_prefix . "oasl_identity
                SET sso_session_token='NULL',
                sso_session_token_expiration='NULL'
                WHERE identity_token = '" . $this->db->sql_escape($identity_token) . "'";
        $this->db->sql_query($sql);
    }

    /**
     * Delete SSO Session to uid
     */
    public function delete_sso_session_token_to_oasl_uid($uid)
    {
        $sql = "UPDATE " . $this->table_prefix . "oasl_identity AS oasli
                INNER JOIN " . $this->table_prefix . "oasl_user AS oaslu ON oaslu.oasl_user_id = oasli.oasl_user_id
                SET sso_session_token = NULL, sso_session_token_expiration = NULL
                WHERE user_id = '" . $this->db->sql_escape($uid) . "'";
        $this->db->sql_query($sql);
    }

    /**
     * Delete SSO Session to oasl_identity_id
     */
    public function delete_sso_session_token_to_oasl_identity_id($oasl_identity_id)
    {
        $sql = "UPDATE " . $this->table_prefix . "oasl_identity
                SET sso_session_token='NULL',
                sso_session_token_expiration='NULL'
                WHERE oasl_identity_id = '" . $this->db->sql_escape($oasl_identity_id) . "'";
        $this->db->sql_query($sql);
    }

    /**
     * Counts a login for the identity token
     */
    public function count_login_identity_token($identity_token)
    {
        // Update the counter for the given identity_token.
        $sql = "UPDATE " . $this->table_prefix . "oasl_identity
                SET num_logins=num_logins+1, date_updated= " . time() . "
                WHERE identity_token = '" . $this->db->sql_escape($identity_token) . "'";
        $this->db->sql_query($sql);
    }

    /**
     * Get the user_token from a user_id
     */
    public function get_user_token_for_user_id($user_id)
    {
        // Read the user_id for this user_token.
        $sql = "SELECT user_token FROM " . $this->table_prefix . "oasl_user WHERE user_id = " . (int) $user_id;
        $query = $this->db->sql_query_limit($sql, 1);
        $result = $this->db->sql_fetchrow($query);
        $this->db->sql_freeresult($query);

        // The user_token exists
        if (is_array($result) && !empty($result['user_token']))
        {
            return $result['user_token'];
        }

        // Not found

        return false;
    }

    /**
     * Check if a given v4 UUID is valid.
     */
    public function is_uuid($uuid)
    {
        return preg_match('/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i', trim($uuid));
    }

    /**
     * Generates a v4 UUID.
     */
    public function get_uuid_v4()
    {
        return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x', mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0x0fff) | 0x4000, mt_rand(0, 0x3fff) | 0x8000, mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff));
    }

    /**
     * Extracts the social network data from a result-set returned by the OneAll API.
     */
    public function extract_social_network_profile($result)
    {
        // Decode the social network profile Data.
        $social_data = $result->get_data();

        // Make sure that the data has beeen decoded properly
        if (is_object($social_data))
        {
            // Provider may report an error inside message:
            if (!empty($social_data->response->result->status->flag) && $social_data->response->result->status->code >= 400)
            {
                error_log($social_data->response->result->status->info . ' (' . $social_data->response->result->status->code . ')');

                return false;
            }

            // Container for user data
            $data = array();

            // Parse plugin data.
            if (isset($social_data->response->result->data->plugin))
            {
                // Plugin.
                $plugin = $social_data->response->result->data->plugin;

                // Add plugin data.
                $data['plugin_key'] = $plugin->key;
                $data['plugin_action'] = (isset($plugin->data->action) ? $plugin->data->action : null);
                $data['plugin_operation'] = (isset($plugin->data->operation) ? $plugin->data->operation : null);
                $data['plugin_reason'] = (isset($plugin->data->reason) ? $plugin->data->reason : null);
                $data['plugin_status'] = (isset($plugin->data->status) ? $plugin->data->status : null);
            }

            // Do we have a user?
            if (isset($social_data->response->result->data->user) && is_object($social_data->response->result->data->user))
            {
                // User.
                $oneall_user = $social_data->response->result->data->user;

                // Add user data.
                $data['user_token'] = $oneall_user->user_token;

                // Do we have an identity ?
                if (isset($oneall_user->identity) && is_object($oneall_user->identity))
                {
                    // Identity.
                    $identity = $oneall_user->identity;

                    // Add identity data.
                    $data['identity_token'] = $identity->identity_token;
                    $data['identity_provider'] = !empty($identity->source->name) ? $identity->source->name : '';

                    $data['user_first_name'] = !empty($identity->name->givenName) ? $identity->name->givenName : '';
                    $data['user_last_name'] = !empty($identity->name->familyName) ? $identity->name->familyName : '';
                    $data['user_formatted_name'] = !empty($identity->name->formatted) ? $identity->name->formatted : '';
                    $data['user_location'] = !empty($identity->currentLocation) ? $identity->currentLocation : '';
                    $data['user_constructed_name'] = trim($data['user_first_name'] . ' ' . $data['user_last_name']);
                    $data['user_picture'] = !empty($identity->pictureUrl) ? $identity->pictureUrl : '';
                    $data['user_thumbnail'] = !empty($identity->thumbnailUrl) ? $identity->thumbnailUrl : '';
                    $data['user_current_location'] = !empty($identity->currentLocation) ? $identity->currentLocation : '';
                    $data['user_about_me'] = !empty($identity->aboutMe) ? $identity->aboutMe : '';
                    $data['user_note'] = !empty($identity->note) ? $identity->note : '';

                    // Birthdate - MM/DD/YYYY
                    if (!empty($identity->birthday) && preg_match('/^([0-9]{2})\/([0-9]{2})\/([0-9]{4})$/', $identity->birthday, $matches))
                    {
                        $data['user_birthdate'] = str_pad($matches[2], 2, '0', STR_PAD_LEFT);
                        $data['user_birthdate'] .= '/' . str_pad($matches[1], 2, '0', STR_PAD_LEFT);
                        $data['user_birthdate'] .= '/' . str_pad($matches[3], 4, '0', STR_PAD_LEFT);
                    }
                    else
                    {
                        $data['user_birthdate'] = '';
                    }

                    // Fullname.
                    if (!empty($identity->name->formatted))
                    {
                        $data['user_full_name'] = $identity->name->formatted;
                    }
                    elseif (!empty($identity->name->displayName))
                    {
                        $data['user_full_name'] = $identity->name->displayName;
                    }
                    else
                    {
                        $data['user_full_name'] = $data['user_constructed_name'];
                    }

                    // Preferred Username.
                    if (!empty($identity->preferredUsername))
                    {
                        $data['user_login'] = $identity->preferredUsername;
                    }
                    elseif (!empty($identity->displayName))
                    {
                        $data['user_login'] = $identity->displayName;
                    }
                    else
                    {
                        $data['user_login'] = $data['user_full_name'];
                    }

                    // phpBB does not like spaces here
                    $data['user_login'] = str_replace(' ', '', trim($data['user_login']));

                    // Website/Homepage.
                    $data['user_website'] = '';
                    if (!empty($identity->profileUrl))
                    {
                        $data['user_website'] = $identity->profileUrl;
                    }
                    elseif (!empty($identity->urls[0]->value))
                    {
                        $data['user_website'] = $identity->urls[0]->value;
                    }

                    // Gender.
                    $data['user_gender'] = '';
                    if (!empty($identity->gender))
                    {
                        switch ($identity->gender)
                        {
                            case 'male':
                                $data['user_gender'] = 'm';
                                break;

                            case 'female':
                                $data['user_gender'] = 'f';
                                break;
                        }
                    }

                    // Email Addresses.
                    $data['user_emails'] = array();
                    $data['user_emails_simple'] = array();

                    // Email Address.
                    $data['user_email'] = '';
                    $data['user_email_is_verified'] = false;

                    // Extract emails.
                    if (property_exists($identity, 'emails') && is_array($identity->emails))
                    {
                        // Loop through emails.
                        foreach ($identity->emails as $email)
                        {
                            // Add to simple list.
                            $data['user_emails_simple'][] = $email->value;

                            // Add to list.
                            $data['user_emails'][] = array(
                                'user_email' => $email->value,
                                'user_email_is_verified' => $email->is_verified);

                            // Keep one, if possible a verified one.
                            if (empty($data['user_email']) || $email->is_verified)
                            {
                                $data['user_email'] = $email->value;
                                $data['user_email_is_verified'] = $email->is_verified;
                            }
                        }
                    }

                    // Addresses.
                    $data['user_addresses'] = array();
                    $data['user_addresses_simple'] = array();

                    // Extract entries.
                    if (property_exists($identity, 'addresses') && is_array($identity->addresses))
                    {
                        // Loop through entries.
                        foreach ($identity->addresses as $address)
                        {
                            // Add to simple list.
                            $data['user_addresses_simple'][] = $address->formatted;

                            // Add to list.
                            $data['user_addresses'][] = array(
                                'formatted' => $address->formatted);
                        }
                    }

                    // Phone Number.
                    $data['user_phone_numbers'] = array();
                    $data['user_phone_numbers_simple'] = array();

                    // Extract entries.
                    if (property_exists($identity, 'phoneNumbers') && is_array($identity->phoneNumbers))
                    {
                        // Loop through entries.
                        foreach ($identity->phoneNumbers as $phone_number)
                        {
                            // Add to simple list.
                            $data['user_phone_numbers_simple'][] = $phone_number->value;

                            // Add to list.
                            $data['user_phone_numbers'][] = array(
                                'value' => $phone_number->value,
                                'type' => (isset($phone_number->type) ? $phone_number->type : null));
                        }
                    }

                    // URLs.
                    $data['user_interests'] = array();
                    $data['user_interests_simple'] = array();

                    // Extract entries.
                    if (property_exists($identity, 'interests') && is_array($identity->interests))
                    {
                        // Loop through entries.
                        foreach ($identity->interests as $interest)
                        {
                            // Add to simple list.
                            $data['user_interests_simple'][] = $interest->value;

                            // Add to list.
                            $data['users_interests'][] = array(
                                'value' => $interest->value,
                                'category' => (isset($interest->category) ? $interest->category : null));
                        }
                    }

                    // URLs.
                    $data['user_urls'] = array();
                    $data['user_urls_simple'] = array();

                    // Extract entries.
                    if (property_exists($identity, 'urls') && is_array($identity->urls))
                    {
                        // Loop through entries.
                        foreach ($identity->urls as $url)
                        {
                            // Add to simple list.
                            $data['user_urls_simple'][] = $url->value;

                            // Add to list.
                            $data['user_urls'][] = array(
                                'value' => $url->value,
                                'type' => (isset($url->type) ? $url->type : null));
                        }
                    }

                    // Certifications.
                    $data['user_certifications'] = array();
                    $data['user_certifications_simple'] = array();

                    // Extract entries.
                    if (property_exists($identity, 'certifications') && is_array($identity->certifications))
                    {
                        // Loop through entries.
                        foreach ($identity->certifications as $certification)
                        {
                            // Add to simple list.
                            $data['user_certifications_simple'][] = $certification->name;

                            // Add to list.
                            $data['user_certifications'][] = array(
                                'name' => $certification->name,
                                'number' => (isset($certification->number) ? $certification->number : null),
                                'authority' => (isset($certification->authority) ? $certification->authority : null),
                                'start_date' => (isset($certification->startDate) ? $certification->startDate : null));
                        }
                    }

                    // Recommendations.
                    $data['user_recommendations'] = array();
                    $data['user_recommendations_simple'] = array();

                    // Extract entries.
                    if (property_exists($identity, 'recommendations') && is_array($identity->recommendations))
                    {
                        // Loop through entries.
                        foreach ($identity->recommendations as $recommendation)
                        {
                            // Add to simple list.
                            $data['user_recommendations_simple'][] = $recommendation->value;

                            // Build data.
                            $data_entry = array(
                                'value' => $recommendation->value);

                            // Add recommender
                            if (property_exists($recommendation, 'recommender') && is_object($recommendation->recommender))
                            {
                                $data_entry['recommender'] = array();

                                // Add recommender details
                                foreach (get_object_vars($recommendation->recommender) as $field => $value)
                                {
                                    $data_entry['recommender'][$this->undo_camel_case($field)] = $value;
                                }
                            }

                            // Add to list.
                            $data['user_recommendations'][] = $data_entry;
                        }
                    }

                    // Accounts.
                    $data['user_accounts'] = array();

                    // Extract entries.
                    if (property_exists($identity, 'accounts') && is_array($identity->accounts))
                    {
                        // Loop through entries.
                        foreach ($identity->accounts as $account)
                        {
                            // Add to list.
                            $data['user_accounts'][] = array(
                                'domain' => (isset($account->domain) ? $account->domain : null),
                                'userid' => (isset($account->userid) ? $account->userid : null),
                                'username' => (isset($account->username) ? $account->username : null));
                        }
                    }

                    // Photos.
                    $data['user_photos'] = array();
                    $data['user_photos_simple'] = array();

                    // Extract entries.
                    if (property_exists($identity, 'photos') && is_array($identity->photos))
                    {
                        // Loop through entries.
                        foreach ($identity->photos as $photo)
                        {
                            // Add to simple list.
                            $data['user_photos_simple'][] = $photo->value;

                            // Add to list.
                            $data['user_photos'][] = array(
                                'value' => $photo->value,
                                'size' => $photo->size);
                        }
                    }

                    // Languages.
                    $data['user_languages'] = array();
                    $data['user_languages_simple'] = array();

                    // Extract entries.
                    if (property_exists($identity, 'languages') && is_array($identity->languages))
                    {
                        // Loop through entries.
                        foreach ($identity->languages as $language)
                        {
                            // Add to simple list
                            $data['user_languages_simple'][] = $language->value;

                            // Add to list.
                            $data['user_languages'][] = array(
                                'value' => $language->value,
                                'type' => (isset($language->type) ? $language->type : null)
                            );
                        }
                    }

                    // Educations.
                    $data['user_educations'] = array();
                    $data['user_educations_simple'] = array();

                    // Extract entries.
                    if (property_exists($identity, 'educations') && is_array($identity->educations))
                    {
                        // Loop through entries.
                        foreach ($identity->educations as $education)
                        {
                            // Add to simple list.
                            $data['user_educations_simple'][] = $education->value;

                            // Add to list.
                            $data['user_educations'][] = array(
                                'value' => $education->value,
                                'type' => (isset($education->type) ? $education->type : null)
                            );
                        }
                    }

                    // Organizations.
                    $data['user_organizations'] = array();
                    $data['user_organizations_simple'] = array();

                    // Extract entries.
                    if (property_exists($identity, 'organizations') && is_array($identity->organizations))
                    {
                        // Loop through entries.
                        foreach ($identity->organizations as $organization)
                        {
                            // At least the name is required.
                            if (!empty($organization->name))
                            {
                                // Add to simple list.
                                $data['user_organizations_simple'][] = $organization->name;

                                // Build entry.
                                $data_entry = array();

                                // Add all fields.
                                foreach (get_object_vars($organization) as $field => $value)
                                {
                                    $data_entry[$this->undo_camel_case($field)] = $value;
                                }

                                // Add to list.
                                $data['user_organizations'][] = $data_entry;
                            }
                        }
                    }
                }
            }

            return $data;
        }

        return false;
    }

    /**
     * Get the user_id for a given a username.
     */
    public function get_user_id_by_username($user_login)
    {
        // Read the user_id for this login
        $sql = "SELECT user_id FROM " . USERS_TABLE . "
                WHERE username_clean = '" . $this->db->sql_escape(utf8_clean_string($user_login)) . "'";
        $query = $this->db->sql_query_limit($sql, 1);
        $result = $this->db->sql_fetchrow($query);
        $this->db->sql_freeresult($query);

        // We have found an user_id.
        if (is_array($result) && !empty($result['user_id']))
        {
            return $result['user_id'];
        }

        // Not found.

        return false;
    }

    /**
     * Create user once credentials validated.
     */
    public function user_add($user_random_email, $user_data)
    {
        $error_message = null;
        $user_id = null;

        // User functions
        if (!function_exists('user_add'))
        {
            require $this->phpbb_root_path . 'includes/functions_user.' . $this->php_ext;
        }

        // String functions
        if (!function_exists('gen_rand_string'))
        {
            require $this->phpbb_root_path . 'includes/functions.' . $this->php_ext;
        }

        // Detect the default language of the forum.
        if (!empty($this->config['default_lang']))
        {
            $user_row['user_lang'] = trim($this->config['default_lang']);
        }
        // Use english
        else
        {
            $user_row['user_lang'] = 'en';
        }

        // Default group_id is required.
        $group_id = $this->get_default_group_id();

        // No group has been set.
        if (!is_numeric($group_id))
        {
            trigger_error('NO_GROUP');
        }

        // Activation Required.
        if (!$user_random_email && ($this->config['require_activation'] == USER_ACTIVATION_SELF || $this->config['require_activation'] == USER_ACTIVATION_ADMIN) && $this->config['email_enable'])
        {
            $user_type = USER_INACTIVE;
            $user_actkey = gen_rand_string(mt_rand(6, 10));

            $user_inactive_reason = INACTIVE_REGISTER;
            $user_inactive_time = time();
        }
        // No Activation Required.
        else
        {
            $user_type = USER_NORMAL;
            $user_actkey = '';

            $user_inactive_reason = 0;
            $user_inactive_time = 0;
        }

        // On 3.3 max_pass_chars is empty by default
        $min_pass_chars = (int) $this->config['min_pass_chars'];
        $max_pass_chars = (int) $this->config['max_pass_chars'];
        $max_pass_chars = $max_pass_chars < $min_pass_chars ? $min_pass_chars : $max_pass_chars;

        // Generate a random password.
        $new_password = gen_rand_string_friendly(max(8, mt_rand($min_pass_chars, $max_pass_chars)));

        // Setup user details.
        $user_row = array(
            'group_id' => $group_id,
            'user_type' => $user_type,
            'user_actkey' => $user_actkey,
            'user_password' => $this->passwords_manager->hash($new_password),
            'user_ip' => $this->user->ip,
            'user_inactive_reason' => $user_inactive_reason,
            'user_inactive_time' => $user_inactive_time,
            'user_lastvisit' => time(),
            'user_lang' => $user_row['user_lang'],
            'username' => $user_data['user_login'],
            'user_email' => $user_data['user_email']);

        // Adds the user to the Newly registered users group.
        if ($this->config['new_member_post_limit'])
        {
            $user_row['user_new'] = 1;
        }

        /**
         * Use this event to modify the values to be inserted when a user is added
         * Inspired by the core event: core.user_add_modify_data (which does not get our profile data)
         *
         * @event oneall.sociallogin.user_add_modify_data
         * @var array    user_row        Array of user details submited to user_add
         * @var array    cp_data            Array of Custom profile fields submited to user_add
         * @var array    social_profile    Array of social network profile, as read only
         * @since 3.1
         */

        $cp_data = array();
        $social_profile = $user_data; // Copy of profile user_data, updates ignore, to simulate read-only.
        $vars = array('user_row', 'cp_data', 'social_profile');
        extract($this->dispatcher->trigger_event('oneall.sociallogin.user_add_modify_data', compact($vars)));

        // Register user, with optional custom fields.
        $user_id_tmp = user_add($user_row, $cp_data);

        // This should not happen, because the required variables are listed above.
        if ($user_id_tmp === false)
        {
            trigger_error('NO_USER', E_USER_ERROR);
        }
        // User added successfully.
        else
        {
            // Add user to special group of OneAll registered users OA_SOCIAL_LOGIN_REGISTER.
            $sql = "SELECT group_id FROM " . GROUPS_TABLE . "
                    WHERE group_name = 'OA_SOCIAL_LOGIN_REGISTER'
                    AND group_type = " . GROUP_SPECIAL;
            $result = $this->db->sql_query($sql);
            $oa_group_id = (int) $this->db->sql_fetchfield('group_id');
            $this->db->sql_freeresult($result);
            $error = group_user_add($oa_group_id, $user_id_tmp);
            if ($error !== false)
            {
                trigger_error($error, E_USER_ERROR);
            }

            // Link the user to this social network.
            list($oasl_user_id, $oasl_identityid) = $this->add_local_storage_tokens_for_uid($user_id_tmp, $user_data['user_token'], $user_data['identity_token'], $user_data['identity_provider']);

            if (!empty($oasl_user_id))
            {
                // Process this user.
                $user_id = $user_id_tmp;

                // Add the avatar
                if ($this->config['oa_social_login_avatars_enable'] == 0)
                {
                    $this->upload_user_avatar($user_id, $user_data);
                }

                // Send Email (Only if it is not a random email address).
                if ($this->config['email_enable'] && !$user_random_email)
                {
                    // Do we have to include messenger?
                    require_once $this->phpbb_root_path . "includes/functions_messenger." . $this->php_ext;

                    // Activation Type.
                    if ($this->config['require_activation'] == USER_ACTIVATION_SELF)
                    {
                        $error_message = $this->user->lang['OA_SOCIAL_LOGIN_ACCOUNT_INACTIVE_OTHER'];
                        $email_template = 'user_welcome_inactive';
                    }
                    else
                    if ($this->config['require_activation'] == USER_ACTIVATION_ADMIN)
                    {
                        $error_message = $this->user->lang['OA_SOCIAL_LOGIN_ACCOUNT_INACTIVE_ADMIN'];
                        $email_template = 'admin_welcome_inactive';
                    }
                    else
                    {
                        $email_template = 'user_welcome';
                    }

                    // Url for activation.
                    $server_url = generate_board_url();

                    // Send email to new user
                    $messenger = new \messenger(false);
                    $messenger->template($email_template, $user_row['user_lang']);
                    $messenger->to($user_row['user_email'], $user_row['username']);
                    $messenger->anti_abuse_headers($this->config, $this->user);
                    $messenger->assign_vars(array(
                        'WELCOME_MSG' => htmlspecialchars_decode(sprintf($this->user->lang['WELCOME_SUBJECT'], $this->config['sitename'])),
                        'USERNAME' => htmlspecialchars_decode($user_row['username']),
                        'PASSWORD' => htmlspecialchars_decode($new_password),
                        'U_ACTIVATE' => $server_url . '/ucp.' . $this->php_ext . '?mode=activate&u=' . $user_id . '&k=' . $user_actkey));
                    $messenger->send(NOTIFY_EMAIL);
                    $messenger->save_queue();

                    // Send email to administrators.
                    if ($this->config['require_activation'] == USER_ACTIVATION_ADMIN)
                    {
                        // Read founders.
                        $sql = "SELECT user_id, username, user_email, user_lang, user_jabber, user_notify_type FROM " . USERS_TABLE . "
                                WHERE user_type = " . USER_FOUNDER;

                        // Grab an array of user_id's with a_user permissions ... these users can activate a user.
                        $acl_admins = $this->auth->acl_get_list(false, 'a_user', false);
                        $acl_admins = (!empty($acl_admins[0]['a_user'])) ? $acl_admins[0]['a_user'] : array();

                        // Include admins
                        if (is_array($acl_admins) && count($acl_admins) > 0)
                        {
                            $sql .= " OR " . $this->db->sql_in_set('user_id', $acl_admins);
                        }

                        // Retrieve founders/admins
                        $query = $this->db->sql_query($sql);

                        // Send emails to them
                        while ($row = $this->db->sql_fetchrow($query))
                        {
                            $messenger->template('admin_activate', $row['user_lang']);
                            $messenger->set_addresses($row);

                            $messenger->assign_vars(array(
                                'USERNAME' => htmlspecialchars_decode($user_row['username']),
                                'U_USER_DETAILS' => $server_url . '/memberlist.' . $this->php_ext . '?mode=viewprofile&u=' . $user_id,
                                'U_ACTIVATE' => $server_url . '/ucp.' . $this->php_ext . '?mode=activate&u=' . $user_id . '&k=' . $user_actkey));

                            $messenger->send($row['user_notify_type']);
                        }
                        $this->db->sql_freeresult($query);
                    }
                }
            }

            return array(
                $error_message,
                $user_id);
        }
    }
}
