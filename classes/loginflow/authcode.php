<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * @package auth_agentconnect
 * @author James McQuillan <james.mcquillan@remote-learner.net>
 * @author Lai Wei <lai.wei@enovation.ie>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2014 onwards Microsoft, Inc. (http://microsoft.com/)
 */

namespace auth_agentconnect\loginflow;

use auth_agentconnect\utils;

defined('MOODLE_INTERNAL') || die();

require_once($CFG->dirroot . '/auth/agentconnect/lib.php');
require_once($CFG->dirroot . '/auth/agentconnect/classes/utils.php');


/**
 * Login flow for the oauth2 authorization code grant.
 */
class authcode extends base {
    /**
     * Returns a list of potential IdPs that this authentication plugin supports. Used to provide links on the login page.
     *
     * @param string $wantsurl The relative url fragment the user wants to get to.
     * @return array Array of idps.
     */
    public function loginpage_idp_list($wantsurl) {
        if (empty($this->config->clientid) || empty($this->config->clientsecret)) {
            return [];
        }
        if (empty($this->config->authendpoint) || empty($this->config->tokenendpoint)) {
            return [];
        }

        if (!empty($this->config->customicon)) {
            $icon = new \pix_icon('0/customicon', get_string('pluginname', 'auth_agentconnect'), 'auth_agentconnect');
        } else {
            $icon = (!empty($this->config->icon)) ? $this->config->icon : 'auth_agentconnect:o365';
            $icon = explode(':', $icon);
            if (isset($icon[1])) {
                list($iconcomponent, $iconkey) = $icon;
            } else {
                $iconcomponent = 'auth_agentconnect';
                $iconkey = 'o365';
            }
            $icon = new \pix_icon($iconkey, get_string('pluginname', 'auth_agentconnect'), $iconcomponent);
        }

        return [
            [
                'url' => new \moodle_url('/auth/agentconnect/'),
                'icon' => $icon,
                'name' => $this->config->opname,
            ]
        ];
    }

    /**
     * Get an OIDC parameter.
     *
     * This is a modification to PARAM_ALPHANUMEXT to add a few additional characters from Base64-variants.
     *
     * @param string $name The name of the parameter.
     * @param string $fallback The fallback value.
     * @return string The parameter value, or fallback.
     */
    protected function getoidcparam($name, $fallback = '') {
        $val = optional_param($name, $fallback, PARAM_RAW);
        $val = trim($val);
        $valclean = preg_replace('/[^A-Za-z0-9\_\-\.\+\/\=]/i', '', $val);
        if ($valclean !== $val) {
            utils::debug('Authorization error.', 'authcode::cleanoidcparam', $name);
            throw new \moodle_exception('errorauthgeneral', 'auth_agentconnect');
        }
        return $valclean;
    }

    /**
     * Handle requests to the redirect URL.
     *
     * @return mixed Determined by loginflow.
     */
    public function handleredirect() {
        global $CFG, $SESSION;

        $state = $this->getoidcparam('state');
        $code = $this->getoidcparam('code');
        $promptlogin = (bool)optional_param('promptlogin', 0, PARAM_BOOL);
        $promptaconsent = (bool)optional_param('promptaconsent', 0, PARAM_BOOL);
        $justauth = (bool)optional_param('justauth', 0, PARAM_BOOL);
        $error = optional_param('error_description', '', PARAM_TEXT);
        utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
                'state'             => $state,
                'code'              => $code,
                'promptlogin'       => $promptlogin,
                'promptaconsent'    => $promptaconsent,
                'justauth'          => $justauth,
                'error_description' => $error,
        ]);
        if (!empty($state)) {
            $requestparams = [
                'state' => $state,
                'code' => $code,
                'error_description' => $error,
            ];
            // Response from OP.
            $this->handleauthresponse($requestparams);
        } else {
            utils::debug_log(__FILE__, __LINE__, __FUNCTION__);

            if (isloggedin() && !isguestuser() && empty($justauth) && empty($promptaconsent)) {
                if (isset($SESSION->wantsurl) and (strpos($SESSION->wantsurl, $CFG->wwwroot) === 0)) {
                    $urltogo = $SESSION->wantsurl;
                    unset($SESSION->wantsurl);
                } else {
                    $urltogo = new \moodle_url('/');
                }
                redirect($urltogo);
                die();
            }
            // Initial login request.
            $stateparams = ['forceflow' => 'authcode'];
            $extraparams = [];
            if ($promptaconsent === true) {
                $extraparams = ['prompt' => 'admin_consent'];
            }
            if ($justauth === true) {
                $stateparams['justauth'] = true;
            }
            $this->initiateauthrequest($promptlogin, $stateparams, $extraparams);
        }
    }

    /**
     * This is the primary method that is used by the authenticate_user_login() function in moodlelib.php.
     *
     * @param string $username The username (with system magic quotes)
     * @param string $password The password (with system magic quotes)
     * @return bool Authentication success or failure.
     */
    public function user_login($username, $password = null) {
        global $CFG, $DB;

        utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
                'username' => $username,
                'password' => $password,
        ]);

        // Check user exists.
    	// UPDATE : 20230329
        $userfilters = ['username' => trim(\core_text::strtolower($username)), 'mnethostid' => $CFG->mnet_localhost_id];
        $userexists = $DB->record_exists('user', $userfilters);

        // Check token exists.
        $tokenrec = $DB->get_record('auth_agentconnect_token', ['username' => $username]);
        if (is_object($tokenrec)) {
            $tokenrecdebug = clone($tokenrec);
        } else {
            $tokenrecdebug = 'Token not exists';
        }
        if (isset($tokenrecdebug->idtoken)) { unset($tokenrecdebug->idtoken); }
        $code = optional_param('code', null, PARAM_RAW);
        $tokenvalid = (!empty($tokenrec) && !empty($code) && $tokenrec->authcode === $code) ? true : false;

        utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
                'userexists' => $userexists,
                'tokenrec'   => $tokenrecdebug,
                'code'       => $code,
                'tokenvalid' => $tokenvalid,
                'return'     => ($userexists === true && $tokenvalid === true) ? true : false
        ]);

        return ($userexists === true && $tokenvalid === true) ? true : false;
    }

    /**
     * Initiate an authorization request to the configured OP.
     *
     * @param bool $promptlogin Whether to prompt for login or use existing session.
     * @param array $stateparams Parameters to store as state.
     * @param array $extraparams Additional parameters to send with the OIDC request.
     */
    public function initiateauthrequest($promptlogin = false, array $stateparams = array(), array $extraparams = array()) {
        $client = $this->get_oidcclient();
        $client->authrequest($promptlogin, $stateparams, $extraparams);
    }

    /**
     * Handle an authorization request response received from the configured OP.
     *
     * @param array $authparams Received parameters.
     */
    protected function handleauthresponse(array $authparams) {
        global $DB, $STATEADDITIONALDATA, $USER, $CFG;
        utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
                'authparams'             => $authparams,
                '$USER->id'              => $USER->id,
                '$STATEADDITIONALDATA'   => $STATEADDITIONALDATA
        ]);
        if (!empty($authparams['error_description'])) {
            utils::debug('Authorization error.', 'authcode::handleauthresponse', $authparams);
            // MENTOR_RQM-1755 : Remove pop-in error when user use "Revenir sur MENTOR azure test" button to agentconnect.              
            if($authparams['error_description'] === 'User auth aborted'){
                redirect($CFG->wwwroot);
             }
             redirect($CFG->wwwroot, get_string('errorauthgeneral', 'auth_agentconnect'), null, \core\output\notification::NOTIFY_ERROR);
        }

        if (!isset($authparams['code'])) {
            utils::debug('No auth code received.', 'authcode::handleauthresponse', $authparams);
            throw new \moodle_exception('errorauthnoauthcode', 'auth_agentconnect');
        }

        if (!isset($authparams['state'])) {
            utils::debug('No state received.', 'authcode::handleauthresponse', $authparams);
            throw new \moodle_exception('errorauthunknownstate', 'auth_agentconnect');
        }

        // Validate and expire state.
        $staterec = $DB->get_record('auth_agentconnect_state', ['state' => $authparams['state']]);

        if (empty($staterec)) {
            throw new \moodle_exception('errorauthunknownstate', 'auth_agentconnect');
        }
        $orignonce = $staterec->nonce;
        $additionaldata = [];
        if (!empty($staterec->additionaldata)) {
            $additionaldata = @unserialize($staterec->additionaldata);
            if (!is_array($additionaldata)) {
                $additionaldata = [];
            }
        }
        $STATEADDITIONALDATA = $additionaldata;
        utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
                '$STATEADDITIONALDATA'   => $STATEADDITIONALDATA
        ]);
        $DB->delete_records('auth_agentconnect_state', ['id' => $staterec->id]);

        // Get token from auth code.
        $client = $this->get_oidcclient();
        $tokenparams = $client->tokenrequest($authparams['code']);
        if (!isset($tokenparams['id_token'])) {
            throw new \moodle_exception('errorauthnoidtoken', 'auth_agentconnect');
        }

        // Decode and verify idtoken.
        list($oidcuniqid, $idtoken) = $this->process_idtoken($tokenparams['id_token'], $orignonce);

        // Check restrictions.
        $passed = $this->checkrestrictions($idtoken);
        if ($passed !== true && empty($additionaldata['ignorerestrictions'])) {
            $errstr = 'User prevented from logging in due to restrictions.';
            utils::debug($errstr, 'handleauthresponse', $idtoken);
            throw new \moodle_exception('errorrestricted', 'auth_agentconnect');
        }

        // This is for setting the system API user.
        if (isset($additionaldata['justauth']) && $additionaldata['justauth'] === true) {
            $eventdata = [
                'other' => [
                    'authparams' => $authparams,
                    'tokenparams' => $tokenparams,
                    'statedata' => $additionaldata,
                ]
            ];
            $event = \auth_agentconnect\event\user_authed::create($eventdata);
            $event->trigger();
            utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
                    'event'     => 'user_authed',
                    'eventdata' => $eventdata
            ]);
            return true;
        }

        // Check if OIDC user is already migrated.
        $tokenrec = $DB->get_record('auth_agentconnect_token', ['oidcuniqid' => $oidcuniqid]);
        if (isloggedin() && !isguestuser() && empty($tokenrec)) {

            // If user is already logged in and trying to link Microsoft 365 account or use it for OIDC.
            // Check if that Microsoft 365 account already exists in moodle.
            $userrec = $DB->count_records_sql('SELECT COUNT(*)
                                                 FROM {user}
                                                WHERE username = ?
                                                      AND id != ?',
                    [$idtoken->claim('upn'), $USER->id]);

            if (!empty($userrec)) {
                if (empty($additionaldata['redirect'])) {
                    $redirect = '/auth/agentconnect/ucp.php?o365accountconnected=true';
                } else if ($additionaldata['redirect'] == '/local/o365/ucp.php') {
                    $redirect = $additionaldata['redirect'].'?action=connection&o365accountconnected=true';
                } else {
                    throw new \moodle_exception('errorinvalidredirect_message', 'auth_agentconnect');
                }
                redirect(new \moodle_url($redirect));
            }

            // If the user is already logged in we can treat this as a "migration" - a user switching to OIDC.
            $connectiononly = false;
            if (isset($additionaldata['connectiononly']) && $additionaldata['connectiononly'] === true) {
                $connectiononly = true;
            }
            $this->handlemigration($oidcuniqid, $authparams, $tokenparams, $idtoken, $connectiononly);
            $redirect = (!empty($additionaldata['redirect'])) ? $additionaldata['redirect'] : '/auth/agentconnect/ucp.php';
            redirect(new \moodle_url($redirect));
        } else {
            // Otherwise it's a user logging in normally with OIDC.
            $this->handlelogin($oidcuniqid, $authparams, $tokenparams, $idtoken);
            redirect(core_login_get_return_url());
        }
    }

    /**
     * Handle a user migration event.
     *
     * @param string $oidcuniqid A unique identifier for the user.
     * @param array $authparams Paramteres receieved from the auth request.
     * @param array $tokenparams Parameters received from the token request.
     * @param \auth_agentconnect\jwt $idtoken A JWT object representing the received id_token.
     * @param bool $connectiononly Whether to just connect the user (true), or to connect and change login method (false).
     */
    protected function handlemigration($oidcuniqid, $authparams, $tokenparams, $idtoken, $connectiononly = false) {
        global $USER, $DB, $CFG;

        // Check if OIDC user is already connected to a Moodle user.
        $tokenrec = $DB->get_record('auth_agentconnect_token', ['oidcuniqid' => $oidcuniqid]);
        if (!empty($tokenrec)) {
            $existinguserparams = ['username' => $tokenrec->username, 'mnethostid' => $CFG->mnet_localhost_id];
            $existinguser = $DB->get_record('user', $existinguserparams);
            if (empty($existinguser)) {
                $DB->delete_records('auth_agentconnect_token', ['id' => $tokenrec->id]);
            } else {
                if ($USER->username === $tokenrec->username) {
                    // Already connected to current user.
                    $this->updatetoken($tokenrec->id, $authparams, $tokenparams);
                    return true;
                } else {
                    // OIDC user connected to user that is not us. Can't continue.
                    throw new \moodle_exception('errorauthuserconnectedtodifferent', 'auth_agentconnect');
                }
            }
        }

        // Check if Moodle user is already connected to an OIDC user.
        $tokenrec = $DB->get_record('auth_agentconnect_token', ['userid' => $USER->id]);
        if (!empty($tokenrec)) {
            if ($tokenrec->oidcuniqid === $oidcuniqid) {
                // Already connected to current user.
                $this->updatetoken($tokenrec->id, $authparams, $tokenparams);
                return true;
            } else {
                throw new \moodle_exception('errorauthuseralreadyconnected', 'auth_agentconnect');
            }
        }

        // Create token data.
        $tokenrec = $this->createtoken($oidcuniqid, $USER->username, $authparams, $tokenparams, $idtoken, $USER->id);

        $eventdata = [
            'objectid' => $USER->id,
            'userid' => $USER->id,
            'other' => [
                'username' => $USER->username,
                'userid' => $USER->id,
                'oidcuniqid' => $oidcuniqid,
            ],
        ];
        $event = \auth_agentconnect\event\user_connected::create($eventdata);
        $event->trigger();

        utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
                'event'     => 'user_connected',
                'eventdata' => $eventdata
        ]);

        return true;
    }

    /**
     * Determines whether the given Azure AD UPN is already matched to a Moodle user (and has not been completed).
     *
     * @return false|stdClass Either the matched Moodle user record, or false if not matched.
     */
    protected function check_for_matched($aadupn) {
        global $DB;

        if (auth_agentconnect_is_local_365_installed()) {
            $match = $DB->get_record('local_o365_connections', ['aadupn' => $aadupn]);
            if (!empty($match) && \local_o365\utils::is_o365_connected($match->muserid) !== true) {
                return $DB->get_record('user', ['id' => $match->muserid]);
            }
        }

        return false;
    }

    /**
     * Check for an existing user object.
     * @param string $oidcuniqid The user object ID to look up.
     * @param string $username The original username.
     * @return string If there is an existing user object, return the username associated with it.
     *                If there is no existing user object, return the original username.
     */
    protected function check_objects($oidcuniqid, $username) {
        global $DB;

        $user = null;
        if (auth_agentconnect_is_local_365_installed()) {
            $sql = 'SELECT u.username
                      FROM {local_o365_objects} obj
                      JOIN {user} u ON u.id = obj.moodleid
                     WHERE obj.objectid = ? and obj.type = ?';
            $params = [$oidcuniqid, 'user'];
            $user = $DB->get_record_sql($sql, $params);
        }

        return (!empty($user)) ? $user->username : $username;
    }

    /**
     * Handle a login event.
     *
     * @param string $oidcuniqid A unique identifier for the user.
     * @param array $authparams Parameters receieved from the auth request.
     * @param array $tokenparams Parameters received from the token request.
     * @param \auth_agentconnect\jwt $idtoken A JWT object representing the received id_token.
     */
    protected function handlelogin($oidcuniqid, $authparams, $tokenparams, $idtoken) {
        global $DB, $CFG;
        $tokenrec = $DB->get_record('auth_agentconnect_token', ['oidcuniqid' => $oidcuniqid]);
        $tokenparamsdebug = $tokenparams;
        if (is_object($tokenrec)) {
            $tokenrecdebug = clone($tokenrec);
        } else {
            $tokenrecdebug = 'Token not exists';
        }
        if (isset($tokenparamsdebug['id_token'])) { unset($tokenparamsdebug['id_token']); }
        if (isset($tokenrecdebug->idtoken)) { unset($tokenrecdebug->idtoken); }
        utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
                'oidcuniqid'  => $oidcuniqid,
                'authparams'  => $authparams,
                'tokenparams' => $tokenparamsdebug,
                'idtoken'     => isset($tokenparams['id_token']) ? $idtoken->decode($tokenparams['id_token']) : '\auth_agentconnect\jwt',
                'tokenrec'    => $tokenrecdebug
        ]);

        // Do not continue if auth plugin is not enabled,
        if (!is_enabled_auth('agentconnect')) {
            throw new \moodle_exception('erroroidcnotenabled', 'auth_agentconnect', null, null, '1');
        }

        $matchemail = get_config('auth_agentconnect', 'matchemail');

        if (!empty($tokenrec)) {
            utils::debug_log(__FILE__, __LINE__, __FUNCTION__);

            // Already connected user.
            if (empty($tokenrec->userid)) {
                utils::debug_log(__FILE__, __LINE__, __FUNCTION__);

                // Existing token record, but missing the user ID.
                $user = $DB->get_record('user', ['username' => $tokenrec->username]);
                if (empty($user)) {
                    utils::debug_log(__FILE__, __LINE__, __FUNCTION__);
                    // Token exists, but it doesn't have a valid username.
                    // In this case, delete the token, and try to process login again.
                    $DB->delete_records('auth_agentconnect_token', ['id' => $tokenrec->id]);
                    return $this->handlelogin($oidcuniqid, $authparams, $tokenparams, $idtoken);
                }
                utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
                        'context' => 'update userid on token record',
                        'OLDuserid' => $tokenrec->userid,
                        'NEWuserid' => $user->id,
                ]);
                $tokenrec->userid = $user->id;
                $DB->update_record('auth_agentconnect_token', $tokenrec);
            } else {
                // Existing token with a user ID.
                $user = $DB->get_record('user', ['id' => $tokenrec->userid]);

                if (empty($user)) {
                    $failurereason = AUTH_LOGIN_NOUSER;
                    $eventdata = ['other' => ['username' => $tokenrec->username, 'reason' => $failurereason]];
                    $event = \core\event\user_login_failed::create($eventdata);
                    $event->trigger();

                    utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
                            'context'   => 'Unable to get user record from id  : ' . $tokenrec->userid,
                            'event'     => 'user_login_failed',
                            'eventdata' => $eventdata
                    ]);

                    // Token is invalid, delete it.
                    $DB->delete_records('auth_agentconnect_token', ['id' => $tokenrec->id]);
                    return $this->handlelogin($oidcuniqid, $authparams, $tokenparams, $idtoken);
                }
            }

            $this->updatetoken($tokenrec->id, $authparams, $tokenparams);


            // Check if the $user->username is the same that $tokenrec->username
            // IF not can't login, then try to match the agentconnectid and update token record.
            $username = $user->username;
            if ($user && $user->username !== $tokenrec->username) {
                // Get agentconnectid of user by userid
                $uifid = $DB->get_field('user_info_field', 'id', ['shortname' => 'agentconnectid']);
                $agentconnectid = $DB->get_field('user_info_data', 'data', ['userid' =>$user->id , 'fieldid' => $uifid]);

                // The agentconnectid is = of new token, we can authenticate $user.
                if ($agentconnectid && $agentconnectid === $idtoken->claim('sub')) {
                    utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
                            'context' => 'update_token_rec_username',
                            'OLDusername' => $tokenrec->username,
                            'NEWusername' => $user->username
                    ]);
                    // Reload tokenrec record because he was updated.
                    $tokenrec = $DB->get_record('auth_agentconnect_token', ['id' => $tokenrec->id]);
                    $tokenrec->username     = $user->username;
                    $tokenrec->oidcusername = $user->username;
                    $DB->update_record('auth_agentconnect_token', $tokenrec);
                }
            }

            // Do not use authenticate_user_login, we want to authenticate user also if user->auth is not agentconnect
            //$user = authenticate_user_login($username, null, true);
    	    // UPDATE : 20230329
            $user = auth_agentconnect_authenticate_user_login($tokenrec->username);

            utils::debug_log(__FILE__, __LINE__, __FUNCTION__, ['username' => $username]);

            if (!empty($user)) {
                // Patch Edunao : disable password change for existing accounts.
                if(get_config('auth_agentconnect', 'disableforcepasswordchange')) {
                    // Set auth_forcepasswordchange to 0.
                    set_user_preference('auth_forcepasswordchange', 0, $user);
                }

                complete_user_login($user);
                utils::debug_log(__FILE__, __LINE__, __FUNCTION__);
            } else {
                // There was a problem in authenticate_user_login.
                throw new \moodle_exception('errorauthgeneral', 'auth_agentconnect', null, null, '2');
            }

            return true;
        } else {
            // No existing token, user not connected.
            //
            // Possibilities:
            //     - Matched user.
            //     - New user (maybe create).

            // Generate a Moodle username.
            // Use 'upn' if available for username (Azure-specific), or fall back to lower-case oidcuniqid.
            $username = $idtoken->claim('upn');
            $originalupn = null;
            utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
                    'context'     => 'Before match email',
                    'username'    => $username,
                    'originalupn' => $originalupn,
            ]);
            $email       = $idtoken->claim('email');
            if ($matchemail) {
                $sqllike = $DB->sql_like('email', ':email', false);
                $username = $DB->get_field_select('user', 'username',
                        "$sqllike AND deleted = 0 AND suspended = 0", ['email' => $email]);
                $username = $username ? $username : $email;
                $originalupn = $username;

                utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
                        'context'     => 'After match email',
                        'email'       => $email,
                        'username'    => $username,
                        'originalupn' => $originalupn,
                ]);
            }

            $username = trim(\core_text::strtolower($username));
            $tokenrec = $this->createtoken($oidcuniqid, $username, $authparams, $tokenparams, $idtoken);

            // Patch Edunao : disable password change for existing accounts.
            $newuser = false;

            $existinguserparams = ['username' => $username, 'mnethostid' => $CFG->mnet_localhost_id];
            if ($DB->record_exists('user', $existinguserparams) !== true) {
                utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
                        'context' => 'user record not exists',
                        'username' => $username,
                        'mnethostid' => $CFG->mnet_localhost_id
                ]);

                // User does not exist. Create user if site allows, otherwise fail.
                if (empty($CFG->authpreventaccountcreation)) {

                    // Create user.
                    $user = create_user_record($username, null, get_config('auth_agentconnect', 'authmethod'));

                    // Patch Edunao : disable password change for existing accounts.
                    $newuser = true;

                    // Add email to user record in order to send password email.
                    $user->email = $email;

                    // UNWANTED : Default value for notifications email profile field.
                    //$user->profile_field_notifications = $email;
                    //profile_save_data($user);

                    // Add new user to cohort : regular-user-cohort
                    $cohortid = $DB->get_field('cohort', 'id', ['idnumber' => 'regular-user-cohort']);
                    if ($cohortid) {
                        require_once($CFG->dirroot . '/cohort/lib.php');
                        cohort_add_member($cohortid, $user->id);
                    }

                    // Check if user must change password at first login, using password in email.
                    $forcechangepassword = get_config('auth_agentconnect', 'forcepasswordchange');
                    if ($forcechangepassword) {
                        if (setnew_password_and_mail($user, true)) {
                            set_user_preference('auth_forcepasswordchange', 1, $user);
                        }
                    }

                    utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
                            'context' => 'new user record, send_new_user_passwords_task',
                            'user'    => $user
                    ]);
                } else {
                    // Trigger login failed event.
                    $failurereason = AUTH_LOGIN_NOUSER;
                    $eventdata = ['other' => ['username' => $username, 'reason' => $failurereason]];
                    $event = \core\event\user_login_failed::create($eventdata);
                    $event->trigger();

                    utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
                            'event'     => 'user_login_failed',
                            'eventdata' => $eventdata
                    ]);

                    throw new \moodle_exception('errorauthloginfailednouser', 'auth_agentconnect', null, null, '1');
                }
            }

            // Do not use authenticate_user_login, we want to authenticate user also if user->auth is not agentconnect
            //$user = authenticate_user_login($username, null, true);
    	    // UPDATE : 20230329
            $user = auth_agentconnect_authenticate_user_login($tokenrec->username);

            if (!empty($user)) {

                $auth  = get_auth_plugin($user->auth);

                // Call the user_create of the auth method.
                if (method_exists($auth, 'user_create')) {
                    $auth->user_create($user, 'to be generated');
                }

                utils::debug_log(__FILE__, __LINE__, __FUNCTION__, 'user is not empty');

                // Add agentconnectid to user on user_info_field.
                $agentconnectid = $idtoken->claim('sub');
                if (!empty($agentconnectid)) {
                    $uifid = $DB->get_field('user_info_field', 'id', ['shortname' => 'agentconnectid']);
                    $uid = ['userid' => $user->id, 'fieldid' => $uifid];
                    if (!$DB->record_exists('user_info_data', $uid)) {
                        $uid['data'] = $idtoken->claim('sub');
                        $DB->insert_record('user_info_data', (object) $uid);
                    }
                }

                $tokenrec = $DB->get_record('auth_agentconnect_token', ['id' => $tokenrec->id]);
                // This should be already done in auth_plugin_agentconnect::user_authenticated_hook, but just in case...
                if (!empty($tokenrec) && empty($tokenrec->userid)) {
                    $updatedtokenrec = new \stdClass;
                    $updatedtokenrec->id = $tokenrec->id;
                    $updatedtokenrec->userid = $user->id;
                    $DB->update_record('auth_agentconnect_token', $updatedtokenrec);
                }

                // Patch Edunao : disable password change for existing accounts.
                if(get_config('auth_agentconnect', 'disableforcepasswordchange') && !$newuser) {
                    // Set auth_forcepasswordchange to 0.
                    set_user_preference('auth_forcepasswordchange', 0, $user);
                }

                complete_user_login($user);
            } else {

                // There was a problem in authenticate_user_login. Clean up incomplete token record.
                if (!empty($tokenrec)) {
                    $DB->delete_records('auth_agentconnect_token', ['id' => $tokenrec->id]);
                }

                utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
                        'context'  => 'user is empty, there was a problem in authenticate_user_login',
                        'username' => $username,
                ]);

                redirect($CFG->wwwroot, get_string('errorauthgeneral', 'auth_agentconnect'), null, \core\output\notification::NOTIFY_ERROR);
            }

            return true;
        }
    }
}
