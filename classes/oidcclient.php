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
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2014 onwards Microsoft, Inc. (http://microsoft.com/)
 */

namespace auth_agentconnect;

defined('MOODLE_INTERNAL') || die();

require_once($CFG->dirroot . '/auth/agentconnect/lib.php');

/**
 * OpenID Connect Client
 */
class oidcclient {
    /** @var httpclientinterface An HTTP client to use. */
    protected $httpclient;

    /** @var string The client ID. */
    protected $clientid;

    /** @var string The client secret. */
    protected $clientsecret;

    /** @var string The client redirect URI. */
    protected $redirecturi;

    /** @var array Array of endpoints. */
    protected $endpoints = [];

    protected $tokenresource;

    /**
     * Constructor.
     *
     * @param httpclientinterface $httpclient An HTTP client to use for background communication.
     */
    public function __construct(httpclientinterface $httpclient) {
        $this->httpclient = $httpclient;
    }

    /**
     * Set client details/credentials.
     *
     * @param string $id The registered client ID.
     * @param string $secret The registered client secret.
     * @param string $redirecturi The registered client redirect URI.
     * @param string $tokenresource
     * @param string $scope The requested OID scope.
     */
    public function setcreds($id, $secret, $redirecturi, $tokenresource, $scope) {
        $this->clientid = $id;
        $this->clientsecret = $secret;
        $this->redirecturi = $redirecturi;
        if (!empty($tokenresource)) {
            $this->tokenresource = $tokenresource;
        } else {
            if (auth_agentconnect_is_local_365_installed()) {
                if (\local_o365\rest\o365api::use_chinese_api() === true) {
                    $this->tokenresource = 'https://microsoftgraph.chinacloudapi.cn';
                } else {
                    $this->tokenresource = 'https://graph.microsoft.com';
                }
            } else {
                //NB: 20221013 - patch pour AgentConnect
                $this->tokenresource = null;
            }

        }
        $this->scope = (!empty($scope)) ? $scope : 'openid profile email';
    }

    /**
     * Get the set client ID.
     *
     * @return string The set client ID.
     */
    public function get_clientid() {
        return (isset($this->clientid)) ? $this->clientid : null;
    }

    /**
     * Get the set client secret.
     *
     * @return string The set client secret.
     */
    public function get_clientsecret() {
        return (isset($this->clientsecret)) ? $this->clientsecret : null;
    }

    /**
     * Get the set redirect URI.
     *
     * @return string The set redirect URI.
     */
    public function get_redirecturi() {
        return (isset($this->redirecturi)) ? $this->redirecturi : null;
    }

    /**
     * Get the set token resource.
     *
     * @return string The set token resource.
     */
    public function get_tokenresource() {
        return (isset($this->tokenresource)) ? $this->tokenresource : null;
    }

    /**
     * Get the set scope.
     *
     * @return string The set scope.
     */
    public function get_scope() {
        return (isset($this->scope)) ? $this->scope : null;
    }

    /**
     * Set OIDC endpoints.
     *
     * @param array $endpoints Array of endpoints. Can have keys 'auth', and 'token'.
     */
    public function setendpoints($endpoints) {
        foreach ($endpoints as $type => $uri) {
            if (clean_param($uri, PARAM_URL) !== $uri) {
                throw new \moodle_exception('erroroidcclientinvalidendpoint', 'auth_agentconnect');
            }
            $this->endpoints[$type] = $uri;
        }
    }

    public function get_endpoint($endpoint) {
        return (isset($this->endpoints[$endpoint])) ? $this->endpoints[$endpoint] : null;
    }

    /**
     * Get an array of authorization request parameters.
     *
     * @param bool $promptlogin Whether to prompt for login or use existing session.
     * @param array $stateparams Parameters to store as state.
     * @param array $extraparams Additional parameters to send with the OIDC request.
     * @return array Array of request parameters.
     */
    protected function getauthrequestparams($promptlogin = false, array $stateparams = array(), array $extraparams = array()) {
        $nonce = 'N'.uniqid();
        $params = [
            'response_type' => 'code',
            'client_id' => $this->clientid,
            'scope' =>  $this->scope,
            'nonce' => $nonce,
            //'response_mode' => 'form_post', NB: 20221013 - patch pour AgentConnect
            //'resource' => $this->tokenresource, NB: 20221013 - patch pour AgentConnect
            'acr_values' => 'eidas1',
            'state' => $this->getnewstate($nonce, $stateparams),
            'redirect_uri' => $this->redirecturi
        ];

        // NB: 20221013 - patch pour AgentConnect
        if (!is_null($this->tokenresource)) {
            $params['resource'] = $this->tokenresource;
        }

        if ($promptlogin === true) {
            $params['prompt'] = 'login';
        }

        $domainhint = get_config('auth_agentconnect', 'domainhint');
        if (!empty($domainhint)) {
            $params['domain_hint'] = $domainhint;
        }

        $params = array_merge($params, $extraparams);

        return $params;
    }

    /**
     * Generate a new state parameter.
     *
     * @param string $nonce The generated nonce value.
     * @return string The new state value.
     */
    public function getnewstate($nonce, array $stateparams = array()) {
        global $DB;
        $staterec = new \stdClass;
        $staterec->sesskey = sesskey();
        $staterec->state = random_string(15);
        $staterec->nonce = $nonce;
        $staterec->timecreated = time();
        $staterec->additionaldata = serialize($stateparams);
        $DB->insert_record('auth_agentconnect_state', $staterec);
        return $staterec->state;
    }

    /**
     * Perform an authorization request by redirecting resource owner's user agent to auth endpoint.
     *
     * @param bool $promptlogin Whether to prompt for login or use existing session.
     * @param array $stateparams Parameters to store as state.
     * @param array $extraparams Additional parameters to send with the OIDC request.
     */
    public function authrequest($promptlogin = false, array $stateparams = array(), array $extraparams = array()) {
        global $DB;
        if (empty($this->clientid)) {
            throw new \moodle_exception('erroroidcclientnocreds', 'auth_agentconnect');
        }

        if (empty($this->endpoints['auth'])) {
            throw new \moodle_exception('erroroidcclientnoauthendpoint', 'auth_agentconnect');
        }

        $params = $this->getauthrequestparams($promptlogin, $stateparams, $extraparams);
        $redirecturl = new \moodle_url($this->endpoints['auth'], $params);
        redirect($redirecturl);
    }

    /**
     * Make a token request using the resource-owner credentials login flow.
     *
     * @param string $username The resource owner's username.
     * @param string $password The resource owner's password.
     * @return array Received parameters.
     */
    public function rocredsrequest($username, $password) {
        if (empty($this->endpoints['token'])) {
            throw new \moodle_exception('erroroidcclientnotokenendpoint', 'auth_agentconnect');
        }

        if (strpos($this->endpoints['token'], 'https://') !== 0) {
            throw new \moodle_exception('erroroidcclientinsecuretokenendpoint', 'auth_agentconnect');
        }

        $params = [
            'grant_type' => 'password',
            'username' => $username,
            'password' => $password,
            'scope' => 'openid profile email',
            'resource' => $this->tokenresource,
            'client_id' => $this->clientid,
            'client_secret' => $this->clientsecret,
        ];

        try {
            $returned = $this->httpclient->post($this->endpoints['token'], $params);
            return utils::process_json_response($returned, ['token_type' => null, 'id_token' => null]);
        } catch (\Exception $e) {
            utils::debug('Error in rocredsrequest request', 'oidcclient::rocredsrequest', $e->getMessage());
            return false;
        }
    }

    /**
     * Exchange an authorization code for an access token.
     *
     * @param string $code An authorization code.
     * @return array Received parameters.
     */
    public function tokenrequest($code) {

        if (empty($this->endpoints['token'])) {
            throw new \moodle_exception('erroroidcclientnotokenendpoint', 'auth_agentconnect');
        }

        $params = [
            'client_id' => $this->clientid,
            'client_secret' => $this->clientsecret,
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirecturi,
        ];

        $returned = $this->httpclient->post($this->endpoints['token'], $params);

        // If userinfo is not empty, we have to retrieve user info and generate a new jwt token.
        $userinfo = get_config('auth_agentconnect', 'userinfo');
        if (empty($userinfo)) {
            return utils::process_json_response($returned, ['id_token' => null]);
        }

        // Decode first response, we need access_token.
        $returned = json_decode($returned);
        $returnedidtoken = \auth_agentconnect\jwt::decode($returned->id_token);

        // Get userinfo by using access_token.
        $userinfo = $this->httpclient->post($userinfo, ['access_token' => $returned->access_token]);
        $userinfoidtoken = \auth_agentconnect\jwt::decode($userinfo);

        // Merge data of old and new tokens.
        $alg = 'sha256'; // Default value.
        $returnedidtokenstr = '';
        foreach ($returnedidtoken as $rindex => $returnedidtokenpart) {
            // Use hash alg from response.
            //$alg = isset($returnedidtokenpart['alg']) ? $returnedidtokenpart['alg'] : $alg;
            foreach ($userinfoidtoken as $uindex => $userinfoidtokenpart) {

                // Merge data.
                if (count(array_intersect_key($returnedidtokenpart, $userinfoidtokenpart)) > 0) {
                    $returnedidtokenparts[$rindex] = array_merge($returnedidtokenpart, $userinfoidtokenpart);

                    // Format for jwt usage.
                    $returnedidtokenparts[$rindex] = (object) $returnedidtokenparts[$rindex];
                    $returnedidtokenparts[$rindex] = json_encode($returnedidtokenparts[$rindex]);
                    $returnedidtokenparts[$rindex] = base64_encode($returnedidtokenparts[$rindex]);
                    $returnedidtokenstr .= str_replace(['+', '/', '='], ['-', '_', ''], $returnedidtokenparts[$rindex]);
                    $returnedidtokenstr .= '.';
                }
            }
        }
        // Create Signature Hash (remove last "." from $returnedidtokenstr).
        $signature = hash_hmac($alg, substr($returnedidtokenstr, 0, -1), '', true);

        // Create JWT and return it in response.
        $jwt = $returnedidtokenstr . str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
        $returned->id_token = $jwt;
        $returned = json_encode($returned);
        return utils::process_json_response($returned, ['id_token' => null]);
    }
}
