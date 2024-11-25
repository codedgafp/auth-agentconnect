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

require_once(__DIR__.'/../../config.php');
require_once(__DIR__.'/auth.php');
require_once(__DIR__.'/lib.php');

require_login();

$action = optional_param('action', null, PARAM_TEXT);

$oidctoken = $DB->get_record('auth_agentconnect_token', ['userid' => $USER->id]);
$oidcconnected = (!empty($oidctoken)) ? true : false;

if (!is_enabled_auth('agentconnect')) {
    throw new \moodle_exception('erroroidcnotenabled', 'auth_agentconnect');
}

if (!empty($action)) {
    if ($action === 'connectlogin') {
        // Use authorization request login flow to connect existing users.
        auth_agentconnect_connectioncapability($USER->id, 'connect', true);
        $auth = new \auth_agentconnect\loginflow\authcode;
        $auth->set_httpclient(new \auth_agentconnect\httpclient());
        $auth->initiateauthrequest();
    } else if ($action === 'disconnectlogin') {
        if (is_enabled_auth('manual') === true) {
            auth_agentconnect_connectioncapability($USER->id, 'disconnect', true);
            $auth = new \auth_plugin_agentconnect;
            $auth->set_httpclient(new \auth_agentconnect\httpclient());
            $auth->disconnect();
        }
    } else {
        throw new \moodle_exception('errorucpinvalidaction', 'auth_agentconnect');
    }
} else {
    $PAGE->set_url('/auth/agentconnect/ucp.php');
    $usercontext = \context_user::instance($USER->id);
    $PAGE->set_context(\context_system::instance());
    $PAGE->set_pagelayout('standard');
    $USER->editing = false;
    $authconfig = get_config('auth_agentconnect');
    $opname = (!empty($authconfig->opname)) ? $authconfig->opname : get_string('pluginname', 'auth_agentconnect');

    $ucptitle = get_string('ucp_title', 'auth_agentconnect', $opname);
    $PAGE->navbar->add($ucptitle, $PAGE->url);
    $PAGE->set_title($ucptitle);

    echo $OUTPUT->header();
    echo \html_writer::tag('h2', $ucptitle);
    echo get_string('ucp_general_intro', 'auth_agentconnect', $opname);
    echo '<br /><br />';

    if (optional_param('o365accountconnected', null, PARAM_TEXT) == 'true') {
        echo \html_writer::start_div('connectionstatus alert alert-error');
        echo \html_writer::tag('h5', get_string('ucp_o365accountconnected', 'auth_agentconnect'));
        echo \html_writer::end_div();
    }

    // Login status.
    echo \html_writer::start_div('auth_agentconnect_ucp_indicator');
    echo \html_writer::tag('h4', get_string('ucp_login_status', 'auth_agentconnect', $opname));
    echo \html_writer::tag('h4', get_string('ucp_status_enabled', 'auth_agentconnect'), ['class' => 'notifysuccess']);
    if (is_enabled_auth('manual') === true) {
        if (auth_agentconnect_connectioncapability($USER->id, 'disconnect')) {
            $connectlinkuri = new \moodle_url('/auth/agentconnect/ucp.php', ['action' => 'disconnectlogin']);
            $strdisconnect = get_string('ucp_login_stop', 'auth_agentconnect', $opname);
            $linkhtml = \html_writer::link($connectlinkuri, $strdisconnect);
            echo \html_writer::tag('h5', $linkhtml);
            echo \html_writer::span(get_string('ucp_login_stop_desc', 'auth_agentconnect', $opname));
        }
    }

    echo \html_writer::end_div();

    echo $OUTPUT->footer();
}
