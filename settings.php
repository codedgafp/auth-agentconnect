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
 * Plugin settings.
 *
 * @package auth_agentconnect
 * @author James McQuillan <james.mcquillan@remote-learner.net>
 * @author Lai Wei <lai.wei@enovation.ie>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2014 onwards Microsoft, Inc. (http://microsoft.com/)
 */

defined('MOODLE_INTERNAL') || die();

use auth_agentconnect\adminsetting\auth_agentconnect_admin_setting_iconselect;
use auth_agentconnect\adminsetting\auth_agentconnect_admin_setting_loginflow;
use auth_agentconnect\adminsetting\auth_agentconnect_admin_setting_redirecturi;
use auth_agentconnect\adminsetting\auth_agentconnect_admin_setting_label;

require_once($CFG->dirroot . '/auth/agentconnect/lib.php');

$configkey = new lang_string('cfg_opname_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_opname_desc', 'auth_agentconnect');
$configdefault = new lang_string('pluginname', 'auth_agentconnect');
$settings->add(new admin_setting_configtext('auth_agentconnect/opname', $configkey, $configdesc, $configdefault, PARAM_TEXT));

$configkey = new lang_string('cfg_clientid_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_clientid_desc', 'auth_agentconnect');
$settings->add(new admin_setting_configtext('auth_agentconnect/clientid', $configkey, $configdesc, '', PARAM_TEXT));

$configkey = new lang_string('cfg_clientsecret_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_clientsecret_desc', 'auth_agentconnect');
$settings->add(new admin_setting_configtext('auth_agentconnect/clientsecret', $configkey, $configdesc, '', PARAM_TEXT));

$configkey = new lang_string('cfg_authendpoint_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_authendpoint_desc', 'auth_agentconnect');
$configdefault = 'https://login.microsoftonline.com/common/oauth2/authorize';
$settings->add(new admin_setting_configtext('auth_agentconnect/authendpoint', $configkey, $configdesc, $configdefault, PARAM_TEXT));

$configkey = new lang_string('cfg_tokenendpoint_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_tokenendpoint_desc', 'auth_agentconnect');
$configdefault = 'https://login.microsoftonline.com/common/oauth2/token';
$settings->add(new admin_setting_configtext('auth_agentconnect/tokenendpoint', $configkey, $configdesc, $configdefault, PARAM_TEXT));

$configkey = new lang_string('cfg_oidcresource_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_oidcresource_desc', 'auth_agentconnect');
$configdefault = 'null'; //NB: 20221013 - patch pour AgentConnect
$settings->add(new admin_setting_configtext('auth_agentconnect/oidcresource', $configkey, $configdesc, $configdefault, PARAM_TEXT));

$configkey = new lang_string('cfg_userinfo_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_userinfo_desc', 'auth_agentconnect');
$configdefault = '';
$settings->add(new admin_setting_configtext('auth_agentconnect/userinfo', $configkey, $configdesc, $configdefault, PARAM_TEXT));

$configkey = new lang_string('cfg_oidcscope_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_oidcscope_desc', 'auth_agentconnect');
$configdefault = 'openid profile email';
$settings->add(new admin_setting_configtext('auth_agentconnect/oidcscope', $configkey, $configdesc, $configdefault, PARAM_TEXT));

$configkey = new lang_string('cfg_redirecturi_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_redirecturi_desc', 'auth_agentconnect');
$settings->add(new auth_agentconnect_admin_setting_redirecturi('auth_agentconnect/redirecturi', $configkey, $configdesc));

$configkey = new lang_string('cfg_forceredirect_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_forceredirect_desc', 'auth_agentconnect');
$configdefault = 0;
$settings->add(new admin_setting_configcheckbox('auth_agentconnect/forceredirect', $configkey, $configdesc, $configdefault));

// Patch Edunao : force password change for new accounts.
$configkey = new lang_string('cfg_forcepasswordchange_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_forcepasswordchange_desc', 'auth_agentconnect');
$configdefault = 0;
$settings->add(new admin_setting_configcheckbox('auth_agentconnect/forcepasswordchange', $configkey, $configdesc, $configdefault));

// Patch Edunao : disable password change for existing accounts.
$configkey = new lang_string('cfg_disableforcepasswordchange_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_disableforcepasswordchange_desc', 'auth_agentconnect');
$configdefault = 1;
$settings->add(new admin_setting_configcheckbox('auth_agentconnect/disableforcepasswordchange', $configkey, $configdesc, $configdefault));

// Patch Edunao : choose auth method for new accounts.
$configkey  = new lang_string('cfg_authmethod_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_authmethod_desc', 'auth_agentconnect');
$authplugins = get_enabled_auth_plugins();
$authmethods = [];
foreach ($authplugins as $plugin) {
    $authmethods[$plugin] = get_string('pluginname', "auth_{$plugin}");
}
$settings->add(new admin_setting_configselect('auth_agentconnect/authmethod', $configkey, $configdesc, $configdefault, $authmethods));

$configkey = new lang_string('cfg_autoappend_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_autoappend_desc', 'auth_agentconnect');
$configdefault = '';
$settings->add(new admin_setting_configtext('auth_agentconnect/autoappend', $configkey, $configdesc, $configdefault, PARAM_TEXT));

$configkey = new lang_string('cfg_domainhint_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_domainhint_desc', 'auth_agentconnect');
$configdefault = '';
$settings->add(new admin_setting_configtext('auth_agentconnect/domainhint', $configkey, $configdesc, $configdefault, PARAM_TEXT));

$configkey = new lang_string('cfg_loginflow_key', 'auth_agentconnect');
$configdesc = '';
$configdefault = 'authcode';
$settings->add(new auth_agentconnect_admin_setting_loginflow('auth_agentconnect/loginflow', $configkey, $configdesc, $configdefault));

$configkey = new lang_string('cfg_userrestrictions_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_userrestrictions_desc', 'auth_agentconnect');
$configdefault = '';
$settings->add(new admin_setting_configtextarea('auth_agentconnect/userrestrictions', $configkey, $configdesc, $configdefault, PARAM_TEXT));

$configkey = new lang_string('cfg_userrestrictionscasesensitive_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_userrestrictioncasesensitive_desc', 'auth_agentconnect');
$settings->add(new admin_setting_configcheckbox('auth_agentconnect/userrestrictionscasesensitive', $configkey, $configdesc, '1'));

$configkey = new lang_string('cfg_signoffintegration_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_signoffintegration_desc', 'auth_agentconnect', $CFG->wwwroot);
$settings->add(new admin_setting_configcheckbox('auth_agentconnect/single_sign_off', $configkey, $configdesc, '0'));

$configkey = new lang_string('cfg_logoutendpoint_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_logoutendpoint_desc', 'auth_agentconnect');
$configdefault = 'https://login.microsoftonline.com/common/oauth2/logout';
$settings->add(new admin_setting_configtext('auth_agentconnect/logouturi', $configkey, $configdesc, $configdefault, PARAM_TEXT));

$label = new lang_string('cfg_debugmode_key', 'auth_agentconnect');
$desc = new lang_string('cfg_debugmode_desc', 'auth_agentconnect');
$settings->add(new \admin_setting_configcheckbox('auth_agentconnect/debugmode', $label, $desc, '0'));

$configkey = new lang_string('cfg_icon_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_icon_desc', 'auth_agentconnect');
$configdefault = 'auth_agentconnect:o365';
$icons = [
    [
        'pix' => 'o365',
        'alt' => new lang_string('cfg_iconalt_o365', 'auth_agentconnect'),
        'component' => 'auth_agentconnect',
    ],
    [
        'pix' => 't/locked',
        'alt' => new lang_string('cfg_iconalt_locked', 'auth_agentconnect'),
        'component' => 'moodle',
    ],
    [
        'pix' => 't/lock',
        'alt' => new lang_string('cfg_iconalt_lock', 'auth_agentconnect'),
        'component' => 'moodle',
    ],
    [
        'pix' => 't/go',
        'alt' => new lang_string('cfg_iconalt_go', 'auth_agentconnect'),
        'component' => 'moodle',
    ],
    [
        'pix' => 't/stop',
        'alt' => new lang_string('cfg_iconalt_stop', 'auth_agentconnect'),
        'component' => 'moodle',
    ],
    [
        'pix' => 't/user',
        'alt' => new lang_string('cfg_iconalt_user', 'auth_agentconnect'),
        'component' => 'moodle',
    ],
    [
        'pix' => 'u/user35',
        'alt' => new lang_string('cfg_iconalt_user2', 'auth_agentconnect'),
        'component' => 'moodle',
    ],
    [
        'pix' => 'i/permissions',
        'alt' => new lang_string('cfg_iconalt_key', 'auth_agentconnect'),
        'component' => 'moodle',
    ],
    [
        'pix' => 'i/cohort',
        'alt' => new lang_string('cfg_iconalt_group', 'auth_agentconnect'),
        'component' => 'moodle',
    ],
    [
        'pix' => 'i/groups',
        'alt' => new lang_string('cfg_iconalt_group2', 'auth_agentconnect'),
        'component' => 'moodle',
    ],
    [
        'pix' => 'i/mnethost',
        'alt' => new lang_string('cfg_iconalt_mnet', 'auth_agentconnect'),
        'component' => 'moodle',
    ],
    [
        'pix' => 'i/permissionlock',
        'alt' => new lang_string('cfg_iconalt_userlock', 'auth_agentconnect'),
        'component' => 'moodle',
    ],
    [
        'pix' => 't/more',
        'alt' => new lang_string('cfg_iconalt_plus', 'auth_agentconnect'),
        'component' => 'moodle',
    ],
    [
        'pix' => 't/approve',
        'alt' => new lang_string('cfg_iconalt_check', 'auth_agentconnect'),
        'component' => 'moodle',
    ],
    [
        'pix' => 't/right',
        'alt' => new lang_string('cfg_iconalt_rightarrow', 'auth_agentconnect'),
        'component' => 'moodle',
    ],
];
$settings->add(new auth_agentconnect_admin_setting_iconselect('auth_agentconnect/icon', $configkey, $configdesc, $configdefault, $icons));

$configkey = new lang_string('cfg_customicon_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_customicon_desc', 'auth_agentconnect');
$setting = new admin_setting_configstoredfile('auth_agentconnect/customicon', $configkey, $configdesc, 'customicon');
$setting->set_updatedcallback('auth_agentconnect_initialize_customicon');
$settings->add($setting);

// Tools to clean up tokens.
$cleanupoidctokensurl = new moodle_url('/auth/agentconnect/cleanupoidctokens.php');
$cleanupoidctokenslink = html_writer::link($cleanupoidctokensurl, get_string('cfg_cleanupoidctokens_key', 'auth_agentconnect'));
$settings->add(new auth_agentconnect_admin_setting_label('auth_agentconnect/cleaniodctokens', get_string('cfg_tools', 'auth_agentconnect'),
    $cleanupoidctokenslink, get_string('cfg_cleanupoidctokens_desc', 'auth_agentconnect')));

$configkey = new lang_string('cfg_matchemail_key', 'auth_agentconnect');
$configdesc = new lang_string('cfg_matchemail_desc', 'auth_agentconnect');
$configdefault = 0;
$settings->add(new admin_setting_configcheckbox('auth_agentconnect/matchemail', $configkey, $configdesc, $configdefault));

// Display locking / mapping of profile fields.
$authplugin = get_auth_plugin('agentconnect');
auth_agentconnect_display_auth_lock_options($settings, $authplugin->authtype, $authplugin->userfields,
    get_string('cfg_field_mapping_desc', 'auth_agentconnect'), true, false, $authplugin->get_custom_user_profile_fields());