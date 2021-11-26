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
 * SingleSignOn
 */
class SingleSignOn
{
    // @var \phpbb\config\config
    protected $config;

    // @var \phpbb\request\request
    protected $request;

    // @var \phpbb\template\template
    protected $template;

    // @var \phpbb\user
    protected $user;

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

    // @var \oneall\singlesignon\core\helper
    protected $helper;

    // @var \oneall\singlesignon\core\noticeManager
    protected $noticeManager;

    /**
     * Constructor
     */
    public function __construct(\phpbb\config\config $config, \phpbb\request\request $request, \phpbb\template\template $template, \phpbb\user $user, \phpbb\auth\auth $auth, \phpbb\db\driver\factory $db, \phpbb\event\dispatcher $phpbb_dispatcher, \phpbb\passwords\manager $passwords_manager, $phpbb_root_path, $php_ext, $table_prefix, \oneall\singlesignon\core\helper $helper, \oneall\singlesignon\core\noticeManager $noticeManager)
    {
        $this->config = $config;
        $this->request = $request;
        $this->template = $template;
        $this->user = $user;
        $this->auth = $auth;
        $this->db = $db;
        $this->dispatcher = $phpbb_dispatcher;
        $this->passwords_manager = $passwords_manager;
        $this->phpbb_root_path = $phpbb_root_path;
        $this->php_ext = $php_ext;
        $this->table_prefix = $table_prefix;
        $this->helper = $helper;
        $this->noticeManager = $noticeManager;
    }

    /**
     * This is the callback handler (referenced by routing.yml).
     */
    public function process_callback()
    {
        global $request;

        // Result container.
        $status = new \stdClass();
        $status->action = 'error';

        // Callback Handler.
        if (!empty($request->get_super_global()['oa_action']) && $request->get_super_global()['oa_action'] == 'single_sign_on' && isset($request->get_super_global()['connection_token']) && $this->helper->is_uuid($request->get_super_global()['connection_token']))
        {
            $connection_token = $request->get_super_global()['connection_token'];

            // Add log.
            $this->helper->add_log('[SSO Callback] Callback for connection_token [' . $connection_token . '] detected');

            // We cannot make a connection without a subdomain.
            if (!empty($this->config['oa_sso_api_subdomain']))
            {
                // See: http://docs.oneall.com/api/resources/connections/read-connection-details/
                $api_resource_url = $this->helper->get_api_url() . '/connections/' . $connection_token . '.json';

                // API Options.
                $api_options = array(
                    'method' => 'GET',
                    'api_key' => $this->config['oa_sso_api_key'],
                    'api_secret' => $this->config['oa_sso_api_secret']
                );

                // User lookup.
                $result = $this->helper->do_api_request($this->helper->get_connection_handler(), $api_resource_url, $api_options);

                // Check result. 201 Returned !!!
                if (is_object($result) && property_exists($result, 'code') && $result->get_code() == 200 && property_exists($result, 'data'))
                {
                    // Check data.
                    if ((($user_data = $this->helper->extract_social_network_profile($result)) !== false))
                    {
                        // The user_token uniquely identifies the user.
                        $user_token = $user_data['user_token'];

                        // The identity_token uniquely identifies the user's data.
                        $identity_token = $user_data['identity_token'];

                        // provider name
                        $provider = $user_data['identity_provider'];

                        // Add Log.
                        $this->helper->add_log('[CALLBACK] Token user_token [' . $user_token . '] / identity_token [' . $identity_token . '] retrieved for connection_token [' . $connection_token . ']');

                        // Add to status.
                        $status->user_token = $user_token;
                        $status->identity_token = $identity_token;

                        // Check if we have a customer for this user_token.
                        $uid = $this->helper->get_user_id_for_user_token($user_token);

                        // User found.
                        if (!empty($uid))
                        {
                            // Add Log.
                            $this->helper->add_log('[CALLBACK] Customer [' . $uid . '] logged in for user_token [' . $user_token . ']');

                            // Update (This is just to make sure that the table is always correct).
                            $this->helper->add_local_storage_tokens_for_uid($uid, $user_token, $identity_token, $provider);

                            // Update status.
                            $status->action = 'existing_user_login_user_token';
                            $status->user_id = $uid;

                            return $status;
                        }

                        // Add Log.
                        $this->helper->add_log('[CALLBACK] No user found for user_token [' . $user_token . ']. Trying email lookup.');

                        // Retrieve email from identity.
                        if (!empty($user_data['user_email']))
                        {
                            // Email details.
                            $email = $user_data['user_email'];
                            $email_is_verified = $user_data['user_email_is_verified'];
                            $email_is_random = false;

                            // Check if we have a user for this email.
                            $user = $this->helper->get_user_data_by_email($email);

                            // // User found.
                            if (is_array($user) && !empty($user['user_id']))
                            {
                                $uid = $user['user_id'];

                                // Update Status
                                $status->user = $user;

                                // Add log.
                                $this->helper->add_log('[CALLBACK] [U' . $uid . '] User found for email [' . $email . ']');

                                // Automatic link is disabled.
                                if (empty($this->config['oa_sso_auto_link_accounts']))
                                {
                                    // Add log.
                                    $this->helper->add_log('[CALLBACK] [U' . $uid . '] Autolink is disabled for everybody.');

                                    // Update status.
                                    $status->action = 'existing_user_no_login_autolink_off';

                                    return $status;
                                }
                                // Automatic link is enabled.
                                else
                                {
                                    // Automatic link is enabled, but not available for admins.
                                    if ($this->config['oa_sso_auto_link_accounts'] == 2 && $user->data['user_type'] == USER_FOUNDER)
                                    {
                                        // Add log.
                                        $this->helper->add_log('[CALLBACK] [U' . $uid . '] User is admin and autolink is disabled for admins');

                                        // Update status.
                                        $status->action = 'existing_user_no_login_autolink_not_allowed';

                                        return $status;
                                    }

                                    // The email has been verified.
                                    if ($email_is_verified)
                                    {
                                        // Add Log.
                                        $this->helper->add_log('[CALLBACK] [U' . $uid . '] Autolink enabled/Email verified. Linking user_token [' . $user_token . '] to user');

                                        // Add to database.
                                        $this->helper->add_local_storage_tokens_for_uid($uid, $user_token, $identity_token, $provider);

                                        // Update Status.
                                        $status->action = 'existing_user_login_email_verified';

                                        return $status;
                                    }
                                    // The email has NOT been verified.
                                    else
                                    {
                                        // We can use unverified emails.
                                        if (!empty($this->config['oa_sso_link_unverified_accounts']))
                                        {
                                            // Add Log.
                                            $this->helper->add_log('[CALLBACK] [U' . $uid . '] Autolink enabled/Email unverified. Linking user_token [' . $user_token . '] to user');

                                            // Add to database.
                                            $this->helper->add_local_storage_tokens_for_uid($uid, $user_token, $identity_token, $provider);

                                            // Update Status.
                                            $status->action = 'existing_user_login_email_unverified';

                                            return $status;
                                        }
                                        // We cannot use unverified emails.
                                        else
                                        {
                                            // Add Log.
                                            $this->helper->add_log('[CALLBACK] [U' . $uid . '] Autolink enabled/Unverified email not allowed. May not link user_token [' . $user_token . '] to user');

                                            // Update Status.
                                            $status->action = 'existing_user_no_login_autolink_off_unverified_emails';

                                            return $status;
                                        }
                                    }
                                }
                            }
                            // No customer found
                            else
                            {
                                // Add Log
                                $this->helper->add_log('[CALLBACK] No user found for email [' . $email . ']');
                            }
                        }
                        else
                        {
                            // Create Random email.
                            $email = $this->helper->generate_random_email();
                            $email_is_verified = false;
                            $email_is_random = true;
                            $user_data['user_email'] = $email;

                            // Add Log.
                            $this->helper->add_log('[CALLBACK] Identity provides no email address. Random address [' . $email . '] generated.');
                        }

                        // /////////////////////////////////////////////////////////////////////////
                        // This is a new user
                        // /////////////////////////////////////////////////////////////////////////

                        // We cannot create new accounts
                        if (empty($this->config['oa_sso_auto_create_accounts']))
                        {
                            // Add Log
                            $this->helper->add_log('[SSO Callback] New user, but account creation disabled. Cannot create user for user_token [' . $user_token . ']');

                            // Update Status
                            $status->action = 'new_user_no_login_autocreate_off';

                            // Done

                            return $status;
                        }

                        // Add Log
                        $this->helper->add_log('[SSO Callback] New user, account creation enabled. Creating user for user_token [' . $user_token . ']');

                        // Username is mandatory.
                        if (!isset($user_data['user_login']) || strlen(trim($user_data['user_login'])) == 0)
                        {
                            $user_data['user_login'] = $user_data['identity_provider'] . 'User';
                        }

                        // Username must be unique.
                        if ($this->helper->get_user_id_by_username($user_data['user_login']) !== false)
                        {
                            $i = 1;
                            $user_login_tmp = $user_data['user_login'] . ($i);
                            while ($this->helper->get_user_id_by_username($user_login_tmp) !== false)
                            {
                                $user_login_tmp = $user_data['user_login'] . ($i++);
                            }
                            $user_data['user_login'] = $user_login_tmp;
                        }

                        // Create and log user if no error and add token (add_local_storage_tokens_for_uid)
                        list($error_message, $user_id) = $this->helper->user_add($email_is_random, $user_data);

                        // The new user has been created correctly.
                        if (empty($error_message))
                        {
                            $uid = $user_id;

                            //  Add log.
                            $this->helper->add_log('[SSO Callback] New user [' . $user_id . '] created for user_token [' . $user_token . ']');

                            // Add to database.
                            $add_tokens = $this->helper->add_local_storage_tokens_for_uid($user_id, $user_token, $identity_token, $provider);

                            // Update status.
                            $status->action = 'new_user_created_login';
                            $status->user_token = $user_token;
                            $status->identity_token = $identity_token;
                            $status->user_id = $uid;
                        }
                        else
                        {
                            $status->action = 'user_creation_failed';
                        }
                    }
                    else
                    {
                        $status->action = 'api_data_decode_failed';
                    }
                }
                else
                {
                    $status->action = 'api_connection_failed';
                }
            }
            else
            {
                $status->action = 'extension_not_setup';
            }
        }
        else
        {
            $status->action = 'no_callback_data_received';
        }

        return $status;
    }

    // *****************************************************
    // Main actions
    // *****************************************************

    /**
     * Remove a Single Sign-On session for the given identity_token.
     */
    public function remove_session_for_identity_token($identity_token)
    {
        // Result container.
        $status = new \stdClass();
        $status->action = 'session_to_delete';
        $status->is_successfull = false;

        // We need the sso_session_token to remove the session.
        if (!empty($identity_token))
        {
            // We cannot make a connection without the subdomain.
            if (!empty($this->config['oa_sso_api_subdomain']))
            {
                // ////////////////////////////////////////////////////////////////////////////////////////////////
                // Destroy an existing Single Sign-On Session
                // ////////////////////////////////////////////////////////////////////////////////////////////////

                // API Endpoint: http://docs.oneall.com/api/resources/sso/delete-session/
                $api_resource_url = $this->helper->get_api_url() . '/sso/sessions/identities/' . $identity_token . '.json?confirm_deletion=true';

                // API Options.
                $api_options = array(
                    'method' => 'DELETE',
                    'api_key' => $this->config['oa_sso_api_key'],
                    'api_secret' => $this->config['oa_sso_api_secret']
                );

                // User lookup.
                $result = $this->helper->do_api_request($this->helper->get_connection_handler(), $api_resource_url, $api_options);

                // Check result. 201 Returned !!!
                if (is_object($result) && property_exists($result, 'code') && $result->get_code() == 200)
                {
                    // Update status.
                    $status->action = 'session_deleted';
                    $status->is_successfull = true;

                    // Add log.
                    $this->helper->add_log('[REMOVE SESSION] Sessions for identity_token [' . $identity_token . '] removed from repository');
                }
            }
            // Extension not setup.
            else
            {
                $status->action = 'extension_not_setup';
            }
        }

        return $status;
    }

    /**
     * Lookup the credentials in the cloud storage.
     */
    public function lookup_user($login, $password)
    {
        // Result Container.
        $status = new \stdClass();
        $status->is_successfull = false;

        // Lookup the local user.
        $user_id = $this->helper->get_user_id_by_username($login);
        if (empty($user_id))
        {
            $user_id = $this->helper->get_user_id_by_email($login);
        }

        // User found.
        if (!empty($user_id))
        {
            // Lookup using the email address.
            $result = $this->lookup_user_auth_cloud($user_id, $password);

            // Found user for the email/password.
            if ($result->is_successfull === true)
            {
                $status->is_successfull = true;
                $status->user_id = $result->user;
                $status->field = 'email';
                $status->action = $result->action;
                $status->user_id = $result->user_id;
                $status->user_token = $result->user_token;
                $status->identity_token = $result->identity_token;
            }
        }

        // Done.

        return $status;
    }

    /**
     * Check cloud credentials
     */
    public function lookup_user_auth_cloud($user_id, $password)
    {
        // Result Container
        $status = new \stdClass();
        $status->is_successfull = false;
        $status->identity_token = null;
        $status->user_token = null;

        // We cannot make a connection without the subdomain.
        if (!empty($this->config['oa_sso_api_subdomain']))
        {
            $this->helper->add_log('[TRY CLOUD LOGIN] [Username ' . $user_id . '] Verifying password');

            // We have the user, check if he has tokens.
            $token = $this->helper->get_user_token_information_for_uid($user_id);

            // Yes, we have a token
            if (!empty($token->user_token))
            {
                // API endpoint: http://docs.oneall.com/api/resources/storage/users/lookup-user/
                $api_resource_url = $this->helper->get_api_url() . '/storage/users/user/lookup.json';

                // API options.
                $api_options = array(
                    'method' => 'POST',
                    'api_key' => $this->config['oa_sso_api_key'],
                    'api_secret' => $this->config['oa_sso_api_secret'],
                    'api_data' => @json_encode(array(
                        'request' => array(
                            'user' => array(
                                'user_token' => $token->user_token,
                                'password' => $password
                            )
                        )
                    ))
                );

                // User lookup.
                $result = $this->helper->do_api_request($this->helper->get_connection_handler(), $api_resource_url, $api_options);

                // Check result.
                if (is_object($result) && property_exists($result, 'code') && $result->get_code() == 200 && property_exists($result, 'data'))
                {
                    // Decode result.
                    $decoded_result = $result->get_data();

                    // Check data.
                    if (is_object($decoded_result) && isset($decoded_result->response->result->data->user))
                    {
                        // Update status.
                        $status->action = 'existing_user_read';
                        $status->is_successfull = true;
                        $status->user_id = $user_id;
                        $status->user_token = $decoded_result->response->result->data->user->user_token;
                        $status->identity_token = $decoded_result->response->result->data->user->identity->identity_token;

                        // Add log.
                        $this->helper->add_log('[USER-LOOKUP-API] Login/Email [{' . $user_login . '}] found in cloud storage, user_token [' . $status->user_token . '] identity_token [' . $status->identity_token . '] assigned');

                        return $status;
                    }
                }
                else
                {
                    $this->helper->add_log('[USER-LOOKUP-API] Login/Email [{' . $user_login . '}] not found in cloud storage, status [' . $result->get_code() . ']');
                }

                return $status;
            }
        }
    }

    /**
     * Start a new Single Sign-On session for the given identity_token.
     */
    public function start_session_for_identity_token($identity_token)
    {
        // Result container.
        $status = new \stdClass();
        $status->is_successfull = false;

        // We need the identity_token to create a session.
        if (!empty($identity_token))
        {
            // We cannot make a connection without the subdomain.
            if (!empty($this->config['oa_sso_api_subdomain']))
            {
                // ////////////////////////////////////////////////////////////////////////////////////////////////
                // Start a new Single Sign-On Session
                // ////////////////////////////////////////////////////////////////////////////////////////////////

                // API Endpoint: http://docs.oneall.com/api/resources/sso/identity/start-session/
                $api_resource_url = $this->helper->get_api_url() . '/sso/sessions/identities/' . $identity_token . '.json';

                // API Options.
                $api_options = array(
                    'method' => 'PUT',
                    'api_key' => $this->config['oa_sso_api_key'],
                    'api_secret' => $this->config['oa_sso_api_secret'],
                    'api_data' => @json_encode(array(
                        'request' => array(
                            'sso_session' => array(
                                'top_realm' => $this->config['session_top_realm'],
                                'sub_realm' => $this->config['session_sub_realm'],
                                'lifetime' => $this->config['session_lifetime']
                            )
                        )
                    )
                    )
                );

                // User lookup.
                $result = $this->helper->do_api_request($this->helper->get_connection_handler(), $api_resource_url, $api_options);

                // Check result. 201 Returned !!!
                if (is_object($result) && property_exists($result, 'code') && property_exists($result, 'data'))
                {
                    // Success.
                    if ($result->get_code() == 201)
                    {
                        // Decode result.
                        $decoded_result = $result->get_data();

                        // Check result.
                        if (is_object($decoded_result) && isset($decoded_result->response->result->data->sso_session))
                        {
                            // Update status.
                            $status->action = 'session_started';
                            $status->sso_session_token = $decoded_result->response->result->data->sso_session->sso_session_token;
                            $status->date_expiration = $decoded_result->response->result->data->sso_session->date_expiration;
                            $status->is_successfull = true;

                            // Add log.
                            $this->helper->add_log('[START SESSION] Session [' . $status->sso_session_token . '] for identity [' . $identity_token . '] added to repository');
                        }
                        else
                        {
                            $status->action = 'invalid_user_object';
                        }
                    }
                    elseif ($result->get_code() == 404)
                    {
                        $status->action = 'invalid_identity_token';
                    }
                    else
                    {
                        $status->action = ('http_error_' . $result->get_code());
                    }
                }
                else
                {
                    $status->action = 'http_request_failed';
                }
            }
            else
            {
                $status->action = 'extension_not_setup';
            }
        }
        else
        {
            $status->action = 'empty_identity_token';
        }

        // Done.

        return $status;
    }

    /**
     * Start a new single sign-on session for the given user
     */
    public function start_session_for_user($user, $password, $retry_if_invalid = true)
    {
        $uid = $user->user_id;

        // User is logged in.
        if (is_object($user) && !empty($uid))
        {
            // Read the user's sso session token
            $token = $this->helper->get_user_token_information_for_uid($uid);

            // User has no token yet.
            if (empty($token->user_token))
            {
                // Add log.
                $this->helper->add_log('[SESSION-START] [UID' . $uid . '] User has no tokens. Creating tokens.');

                // Add user to cloud storage.
                $token = $this->synchronize_user_to_cloud_storage($user, $password);

                // User added.
                if ($token->is_successfull === true)
                {
                    // Add log.
                    $this->helper->add_log('[START SESSION] [UID' . $uid . '] Tokens created, user_token [' . $token->user_token . '] identity_token [' . $token->identity_token . ']');

                    // Add user token to database.
                    $oasl_user_id = $this->helper->link_user_token_to_user_id($uid, $token->user_token);

                    // Add identity token to database.
                    $oasl_identityid = $this->helper->link_user_to_identity($oasl_user_id, $token->identity_token, $token->provider);
                }
            }
            // User has already tokens.
            else
            {
                // Add log.
                $this->helper->add_log('[START SESSION] [UID' . $uid . '] User has already tokens, user_token [' . $token->user_token . '] identity_token [' . $token->identity_token . ']');
            }

            // Start session.
            if (!empty($token->identity_token))
            {
                // Add log.
                $this->helper->add_log('[START SESSION] [UID' . $uid . '] Starting session');

                // Start a new session.
                $start_session = $this->start_session_for_identity_token($token->identity_token);

                // Session started.
                if ($start_session->is_successfull === true)
                {
                    // Update status.
                    $token->sso_session_token = $start_session->sso_session_token;
                    $token->date_expiration = $start_session->date_expiration;
                    $token->is_successfull = true;

                    $datetime_expiration = new \Datetime($token->date_expiration);

                    // Add log.
                    $this->helper->add_log('[START SESSION] [UID' . $uid . '] Session created, sso_session_token [' . $token->sso_session_token . ']');

                    // // Store session data.
                    $this->helper->add_sso_session_token_to_identity_token($token->identity_token, $token->sso_session_token, $datetime_expiration->format('U'));
                }
                else
                {
                    // Invalid identity.
                    if ($start_session->action == 'invalid_identity_token')
                    {
                        // Add log.
                        $this->helper->add_log('[START SESSION] [UID' . $uid . '] Removing invalid token');

                        // Remove tokens.
                        $this->helper->delete_sso_session_token_to_identity_token($token->identity_token);
                    }
                }
            }
        }

        // Created session.

        return $token;
    }

    /**
     * Add a user to the cloud storage.
     */
    public function synchronize_user_to_cloud_storage($user, $password)
    {
        // Result Container
        $status = new \stdClass();
        $status->is_successfull = false;
        $status->identity_token = null;
        $status->user_token = null;

        $uid = $user->user_id;

        // User is logged in.
        if (is_object($user) && !empty($uid))
        {
            // We cannot make a connection without the subdomain.
            if (!empty($this->config['oa_sso_api_subdomain']))
            {
                // Add Log
                $this->helper->add_log('[SYNCHRONIZE USER] [UID' . $uid . '] Synchronize data with cloud storage');

                // ////////////////////////////////////////////////////////////////////////////////////////////////
                // If we are getting here, then a new identity needs to be added
                // ////////////////////////////////////////////////////////////////////////////////////////////////

                // Build data.
                $identity = array(
                    'preferredUsername' => $user->username,
                    'displayName' => $user->username
                );

                // User email.
                if (!empty($user->user_email))
                {
                    $identity['emails'] = array(
                        array(
                            'value' => $user->user_email,
                            'is_verified' => true
                        )
                    );
                }

                $this->helper->add_log('[SYNCHRONIZE USER] [UID' . $uid . '] Pushing user record to cloud storage');

                // API Endpoint: http://docs.oneall.com/api/resources/storage/users/create-user/
                $api_resource_url = $this->helper->get_api_url() . '/storage/users/user/synchronize.json';

                // API Options.
                $api_options = array(
                    'method' => 'PUT',
                    'api_key' => $this->config['oa_sso_api_key'],
                    'api_secret' => $this->config['oa_sso_api_secret'],
                    'api_data' => @json_encode(array(
                        'request' => array(
                            'synchronize' => array(
                                'identifier' => array(
                                    'field' => 'login',
                                    'value' => $user->user_email
                                ),
                                'user' => array(
                                    'login' => $user->user_email,
                                    'password' => $password,
                                    'identity' => $identity
                                )
                            )
                        )
                    )
                    )
                );

                // User lookup.
                $result = $this->helper->do_api_request($this->helper->get_connection_handler(), $api_resource_url, $api_options);

                // Check result. 201 Returned !!!
                if (is_object($result) && property_exists($result, 'code') && ($result->get_code() == 201 || $result->get_code() == 200) && property_exists($result, 'data'))
                {
                    // Decode result.
                    $decoded_result = $result->get_data();

                    // Check data.
                    if (is_object($decoded_result) && isset($decoded_result->response->result->data->user))
                    {
                        // Update status.
                        $status->action = 'new_user_created';
                        $status->is_successfull = true;
                        $status->user_token = $decoded_result->response->result->data->user->user_token;
                        $status->identity_token = $decoded_result->response->result->data->user->identity->identity_token;
                        $status->provider = $decoded_result->response->result->data->user->identity->provider;

                        // Add Log.
                        $this->helper->add_log('[SYNCHRONIZE USER] [UID' . $uid . '] User ' . ($result->get_code() == 201 ? 'created' : 'updated') . ', user_token [' . $status->user_token . '] and identity_token [' . $status->identity_token . '] assigned');

                        return $status;
                    }
                }
            }
        }

        // Error.

        return $status;
    }

    // OK
    /**
     * End single sign-on session for the given user
     */
    public function end_session_for_user($user_id)
    {
        // Result container.
        $status = new \stdClass();
        $status->is_successfull = false;

        // Add log.
        $this->helper->add_log('[END SESSION] [UID' . $user_id . '] Removing session token');

        // We have the user, check if he has token.
        $token = $this->helper->get_user_token_information_for_uid($user_id);

        // User has no token yet.
        if (!empty($token->sso_session_token))
        {
            // Remove session data from Drupal.
            $remove_local_session = $this->helper->delete_sso_session_token_to_oasl_uid($user_id);

            // Remove session data from Cloud.
            $remove_distant_session = $this->remove_session_for_identity_token($token->identity_token);

            // Removed.
            if ($remove_distant_session->is_successfull === true)
            {
                // Success.
                $status->is_successfull = true;

                // Add log.
                $this->helper->add_log('[END SESSION] [UID' . $user_id . '] Session token removed');
            }
        }

        return $status;
    }

    // *****************************************************
    // AJAX
    // *****************************************************

    // Read user token (Ajax, see single_sign_on.js)
    public function get_user_sso_token()
    {
        // Output for Ajax.
        $json_response = new \phpbb\json_response();

        // The user is currently logged in.
        if (!empty($this->user->data['user_id']) && (int) $this->user->data['user_id'] != ANONYMOUS)
        {
            // Read the user's token.
            $token = $this->helper->get_user_token_information_for_uid($this->user->data['user_id']);

            // We have a session token, refresh it.
            if (!empty($token->sso_session_token))
            {
                // Add log.
                $this->helper->add_log('[SSO JS] [UID' . $this->user->data['user_id'] . '] Open session found, registering token [' . $token->sso_session_token . ']');

                $json_response->send(array('val' => $token->sso_session_token));
                exit;
            }
        }
        // The user is currently not logged in.
        else
        {
            // If this value is in the future, we should not try to login the user with SSO.
            $login_wait = $this->helper->get_login_wait_value_from_cookie();

            // Try to login the user.
            if ($login_wait < time())
            {
                // Add log.
                $this->helper->add_log('[SSO JS] No open session found, checking...');

                $json_response->send(array('val' => 'check_session'));
                exit;
            }
        }

        $json_response->send(array('val' => 'no_token_found'));
        exit;
    }

    // Get user notice.
    public function get_user_notice()
    {
        // Output for Ajax.
        $json_response = new \phpbb\json_response();

        $json_response->send(array('val' => $this->noticeManager->display_user_notice()));
        exit;
    }
}
