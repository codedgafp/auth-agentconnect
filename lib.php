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

use auth_agentconnect\utils;

defined('MOODLE_INTERNAL') || die();

require_once($CFG->dirroot . '/auth/agentconnect/classes/utils.php');

function auth_agentconnect_initialize_customicon($filefullname) {
    global $CFG;

    $file = get_config('auth_agentconnect', 'customicon');
    $systemcontext = \context_system::instance();
    $fullpath = "/{$systemcontext->id}/auth_agentconnect/customicon/0{$file}";

    $fs = get_file_storage();
    if (!$file = $fs->get_file_by_hash(sha1($fullpath)) or $file->is_directory()) {
        return false;
    }
    $pixpluginsdir = 'pix_plugins/auth/agentconnect/0';
    $pixpluginsdirparts = explode('/', $pixpluginsdir);
    $curdir = $CFG->dataroot;
    foreach ($pixpluginsdirparts as $dir) {
        $curdir .= '/' . $dir;
        if (!file_exists($curdir)) {
            mkdir($curdir);
        }
    }

    if (file_exists($CFG->dataroot . '/pix_plugins/auth/agentconnect/0')) {
        $file->copy_content_to($CFG->dataroot . '/pix_plugins/auth/agentconnect/0/customicon.jpg');
        theme_reset_all_caches();
    }
}

/**
 * Check for connection abilities.
 *
 * @param int $userid Moodle user id to check permissions for.
 * @param string $mode Mode to check
 *                     'connect' to check for connect specific capability
 *                     'disconnect' to check for disconnect capability.
 *                     'both' to check for disconnect and connect capability.
 * @param boolean $require Use require_capability rather than has_capability.
 *
 * @return boolean True if has capability.
 */
function auth_agentconnect_connectioncapability($userid, $mode = 'connect', $require = false) {
    $check = 'has_capability';
    if ($require) {
        // If requiring the capability and user has manageconnection than checking connect and disconnect is not needed.
        $check = 'require_capability';
        if (has_capability('auth/agentconnect:manageconnection', \context_user::instance($userid), $userid)) {
            return true;
        }
    } else if ($check('auth/agentconnect:manageconnection', \context_user::instance($userid), $userid)) {
        return true;
    }

    $result = false;
    switch ($mode) {
        case "connect":
            $result = $check('auth/agentconnect:manageconnectionconnect', \context_user::instance($userid), $userid);
            break;
        case "disconnect":
            $result = $check('auth/agentconnect:manageconnectiondisconnect', \context_user::instance($userid), $userid);
            break;
        case "both":
            $result = $check('auth/agentconnect:manageconnectionconnect', \context_user::instance($userid), $userid);
            $result = $result && $check('auth/agentconnect:manageconnectiondisconnect', \context_user::instance($userid), $userid);
    }
    if ($require) {
        return true;
    }

    return $result;
}

/**
 * Determine if local_o365 plugins is installed.
 *
 * @return bool
 */
function auth_agentconnect_is_local_365_installed() {
    global $CFG, $DB;

    $dbmanager = $DB->get_manager();

    return file_exists($CFG->dirroot . '/local/o365/version.php') &&
        $DB->record_exists('config_plugins', ['plugin' => 'local_o365', 'name' => 'version']) &&
        $dbmanager->table_exists('local_o365_objects') &&
        $dbmanager->table_exists('local_o365_connections');
}

/**
 * Return details of all auth_agentconnect tokens having empty Moodle user IDs.
 *
 * @return array
 */
function auth_agentconnect_get_tokens_with_empty_ids() {
    global $DB;

    $emptyuseridtokens = [];

    $records = $DB->get_records('auth_agentconnect_token', ['userid' => '0']);

    foreach ($records as $record) {
        $item = new stdClass();
        $item->id = $record->id;
        $item->oidcusername = $record->oidcusername;
        $item->moodleusername = $record->username;
        $item->userid = 0;
        $item->oidcuniqueid = $record->oidcuniqid;
        $item->matchingstatus = get_string('unmatched', 'auth_agentconnect');
        $item->details = get_string('na', 'auth_agentconnect');
        $deletetokenurl = new moodle_url('/auth/agentconnect/cleanupoidctokens.php', ['id' => $record->id]);
        $item->action = html_writer::link($deletetokenurl, get_string('delete_token', 'auth_agentconnect'));

        $emptyuseridtokens[$record->id] = $item;
    }

    return $emptyuseridtokens;
}

/**
 * Return details of all auth_agentconnect tokens with matching Moodle user IDs, but mismatched usernames.
 *
 * @return array
 */
function auth_agentconnect_get_tokens_with_mismatched_usernames() {
    global $DB;

    $mismatchedtokens = [];

    $sql = 'SELECT tok.id AS id, tok.userid AS tokenuserid, tok.username AS tokenusernmae, tok.oidcusername AS oidcusername,
                   tok.oidcuniqid as oidcuniqid, u.id AS muserid, u.username AS musername
              FROM {auth_agentconnect_token} tok
              JOIN {user} u ON u.id = tok.userid
             WHERE tok.userid != 0
               AND u.username != tok.username';
    $records = $DB->get_recordset_sql($sql);
    foreach ($records as $record) {
        $item = new stdClass();
        $item->id = $record->id;
        $item->oidcusername = $record->oidcusername;
        $item->userid = $record->muserid;
        $item->oidcuniqueid = $record->oidcuniqid;
        $item->matchingstatus = get_string('mismatched', 'auth_agentconnect');
        $item->details = get_string('mismatched_details', 'auth_agentconnect',
            ['tokenusername' => $record->tokenusername, 'moodleusername' => $record->musername]);
        $deletetokenurl = new moodle_url('/auth/agentconnect/cleanupoidctokens.php', ['id' => $record->id]);
        $item->action = html_writer::link($deletetokenurl, get_string('delete_token_and_reference', 'auth_agentconnect'));

        $mismatchedtokens[$record->id] = $item;
    }

    return $mismatchedtokens;
}

/**
 * Delete the auth_agentconnect token with the ID.
 *
 * @param int $tokenid
 */
function auth_agentconnect_delete_token(int $tokenid) {
    global $DB;

    if (auth_agentconnect_is_local_365_installed()) {
        $sql = 'SELECT obj.id, obj.objectid, tok.token, u.id AS userid, u.email
                  FROM {local_o365_objects} obj
                  JOIN {auth_agentconnect_token} tok ON obj.o365name = tok.username
                  JOIN {user} u ON obj.moodleid = u.id
                 WHERE type = :type AND tok.id = :tokenid';
        if ($objectrecord = $DB->get_record_sql($sql, ['type' => 'user', 'tokenid' => $tokenid], IGNORE_MULTIPLE)) {
            // Delete record from local_o365_objects.
            $DB->get_records('local_o365_objects', ['id' => $objectrecord->id]);

            // Delete record from local_o365_token.
            $DB->delete_records('local_o365_token', ['user_id' => $objectrecord->userid]);

            // Delete record from local_o365_connections.
            $DB->delete_records_select('local_o365_connections', 'muserid = :userid OR LOWER(aadupn) = :email',
                ['userid' => $objectrecord->userid, 'email' => $objectrecord->email]);
        }
    }

    $DB->delete_records('auth_agentconnect_token', ['id' => $tokenid]);
}

/**
 * Return the list of remote field options in field mapping.
 *
 * @return array
 */
function auth_agentconnect_get_remote_fields() {
    if (auth_agentconnect_is_local_365_installed()) {
        $remotefields = [
            '' => get_string('settings_fieldmap_feild_not_mapped', 'auth_agentconnect'),
            'objectId' => get_string('settings_fieldmap_field_objectId', 'auth_agentconnect'),
            'userPrincipalName' => get_string('settings_fieldmap_field_userPrincipalName', 'auth_agentconnect'),
            'displayName' => get_string('settings_fieldmap_field_displayName', 'auth_agentconnect'),
            'givenName' => get_string('settings_fieldmap_field_givenName', 'auth_agentconnect'),
            'surname' => get_string('settings_fieldmap_field_surname', 'auth_agentconnect'),
            'mail' => get_string('settings_fieldmap_field_mail', 'auth_agentconnect'),
            'streetAddress' => get_string('settings_fieldmap_field_streetAddress', 'auth_agentconnect'),
            'city' => get_string('settings_fieldmap_field_city', 'auth_agentconnect'),
            'postalCode' => get_string('settings_fieldmap_field_postalCode', 'auth_agentconnect'),
            'state' => get_string('settings_fieldmap_field_state', 'auth_agentconnect'),
            'country' => get_string('settings_fieldmap_field_country', 'auth_agentconnect'),
            'jobTitle' => get_string('settings_fieldmap_field_jobTitle', 'auth_agentconnect'),
            'department' => get_string('settings_fieldmap_field_department', 'auth_agentconnect'),
            'companyName' => get_string('settings_fieldmap_field_companyName', 'auth_agentconnect'),
            'preferredLanguage' => get_string('settings_fieldmap_field_preferredLanguage', 'auth_agentconnect'),
            'employeeId' => get_string('settings_fieldmap_field_employeeId', 'auth_agentconnect'),
            'businessPhones' => get_string('settings_fieldmap_field_businessPhones', 'auth_agentconnect'),
            'faxNumber' => get_string('settings_fieldmap_field_faxNumber', 'auth_agentconnect'),
            'mobilePhone' => get_string('settings_fieldmap_field_mobilePhone', 'auth_agentconnect'),
            'officeLocation' => get_string('settings_fieldmap_field_officeLocation', 'auth_agentconnect'),
            'preferredName' => get_string('settings_fieldmap_field_preferredName', 'auth_agentconnect'),
            'manager' => get_string('settings_fieldmap_field_manager', 'auth_agentconnect'),
            'teams' => get_string('settings_fieldmap_field_teams', 'auth_agentconnect'),
            'groups' => get_string('settings_fieldmap_field_groups', 'auth_agentconnect'),
            'roles' => get_string('settings_fieldmap_field_roles', 'auth_agentconnect'),
        ];

        $order = 0;
        while ($order++ < 15) {
            $remotefields['extensionAttribute' . $order] = get_string('settings_fieldmap_field_extensionattribute', 'auth_agentconnect',
                $order);
        }
    } else {
        $remotefields = [
            '' => '',
            'objectId' => get_string('settings_fieldmap_field_objectId', 'auth_agentconnect'),
            'userPrincipalName' => get_string('settings_fieldmap_field_userPrincipalName', 'auth_agentconnect'),
            'usual_name' => get_string('settings_fieldmap_field_usual_name', 'auth_agentconnect'),
            'givenName' => get_string('settings_fieldmap_field_givenName', 'auth_agentconnect'),
            'surname' => get_string('settings_fieldmap_field_surname', 'auth_agentconnect'),
            'mail' => get_string('settings_fieldmap_field_mail', 'auth_agentconnect'),
        ];
    }


    return $remotefields;
}

/**
 * Return the current field mapping settings in an array.
 *
 * @return array
 */
function auth_agentconnect_get_field_mappings() {
    $fieldmappings = [];

    $userfields = auth_agentconnect_get_all_user_fields();

    $authoidcconfig = get_config('auth_agentconnect');

    foreach ($userfields as $userfield) {
        $fieldmapsettingname = 'field_map_' . $userfield;
        if (property_exists($authoidcconfig, $fieldmapsettingname) && $authoidcconfig->$fieldmapsettingname) {
            $fieldsetting = [];
            $fieldsetting['field_map'] = $authoidcconfig->$fieldmapsettingname;

            $fieldlocksettingname = 'field_lock_' . $userfield;
            if (property_exists($authoidcconfig, $fieldlocksettingname)) {
                $fieldsetting['field_lock'] = $authoidcconfig->$fieldlocksettingname;
            } else {
                $fieldsetting['field_lock'] = 'unlocked';
            }

            $fieldupdatelocksettignname = 'field_updatelocal_' . $userfield;
            if (property_exists($authoidcconfig, $fieldupdatelocksettignname)) {
                $fieldsetting['update_local'] = $authoidcconfig->$fieldupdatelocksettignname;
            } else {
                $fieldsetting['update_local'] = 'always';
            }

            $fieldmappings[$userfield] = $fieldsetting;
        }
    }

    return $fieldmappings;
}

/**
 * Helper function used to print mapping and locking for auth_agentconnect plugin on admin pages.
 *
 * @param stdclass $settings Moodle admin settings instance
 * @param string $auth authentication plugin shortname
 * @param array $userfields user profile fields
 * @param string $helptext help text to be displayed at top of form
 * @param boolean $mapremotefields Map fields or lock only.
 * @param boolean $updateremotefields Allow remote updates
 * @param array $customfields list of custom profile fields
 */
function auth_agentconnect_display_auth_lock_options($settings, $auth, $userfields, $helptext, $mapremotefields, $updateremotefields,
    $customfields = array()) {
    global $DB;

    // Introductory explanation and help text.
    if ($mapremotefields) {
        $settings->add(new admin_setting_heading($auth.'/data_mapping', new lang_string('auth_data_mapping', 'auth'), $helptext));
    } else {
        $settings->add(new admin_setting_heading($auth.'/auth_fieldlocks', new lang_string('auth_fieldlocks', 'auth'), $helptext));
    }

    // Generate the list of options.
    $lockoptions = [
        'unlocked' => get_string('unlocked', 'auth'),
        'unlockedifempty' => get_string('unlockedifempty', 'auth'),
        'locked' => get_string('locked', 'auth'),
    ];

    if (auth_agentconnect_is_local_365_installed()) {
        $alwaystext = get_string('update_oncreate_and_onlogin_and_usersync', 'auth_agentconnect');
        $onlogintext = get_string('update_onlogin_and_usersync', 'auth_agentconnect');
    } else {
        $alwaystext = get_string('update_oncreate_and_onlogin', 'auth_agentconnect');
        $onlogintext = get_string('update_onlogin', 'auth');
    }
    $updatelocaloptions = [
        'always' => $alwaystext,
        'oncreate' => get_string('update_oncreate', 'auth'),
        'onlogin' => $onlogintext,
    ];

    $updateextoptions = [
        '0' => get_string('update_never', 'auth'),
        '1' => get_string('update_onupdate', 'auth'),
    ];

    // Generate the list of profile fields to allow updates / lock.
    if (!empty($customfields)) {
        $userfields = array_merge($userfields, $customfields);
        $customfieldname = $DB->get_records('user_info_field', null, '', 'shortname, name');
    }

    $remotefields = auth_agentconnect_get_remote_fields();

    foreach ($userfields as $field) {
        // Define the fieldname we display to the  user.
        // this includes special handling for some profile fields.
        $fieldname = $field;
        $fieldnametoolong = false;
        if ($fieldname === 'lang') {
            $fieldname = get_string('language');
        } else if (!empty($customfields) && in_array($field, $customfields)) {
            // If custom field then pick name from database.
            $fieldshortname = str_replace('profile_field_', '', $fieldname);
            $fieldname = $customfieldname[$fieldshortname]->name;
            if (core_text::strlen($fieldshortname) > 67) {
                // If custom profile field name is longer than 67 characters we will not be able to store the setting
                // such as 'field_updateremote_profile_field_NOTSOSHORTSHORTNAME' in the database because the character
                // limit for the setting name is 100.
                $fieldnametoolong = true;
            }
        } else if ($fieldname == 'url') {
            $fieldname = get_string('webpage');
        } else {
            $fieldname = get_string($fieldname);
        }

        // Generate the list of fields / mappings.
        if ($fieldnametoolong) {
            // Display a message that the field can not be mapped because it's too long.
            $url = new moodle_url('/user/profile/index.php');
            $a = (object)['fieldname' => s($fieldname), 'shortname' => s($field), 'charlimit' => 67, 'link' => $url->out()];
            $settings->add(new admin_setting_heading($auth.'/field_not_mapped_'.sha1($field), '',
                get_string('cannotmapfield', 'auth', $a)));
        } else if ($mapremotefields) {
            // We are mapping to a remote field here.
            // Mapping.
            $settings->add(new admin_setting_configselect("auth_agentconnect/field_map_{$field}",
                get_string('auth_fieldmapping', 'auth', $fieldname), '', null, $remotefields));

            // Update local.
            $settings->add(new admin_setting_configselect("auth_{$auth}/field_updatelocal_{$field}",
                get_string('auth_updatelocalfield', 'auth', $fieldname), '', 'always', $updatelocaloptions));

            // Update remote.
            if ($updateremotefields) {
                $settings->add(new admin_setting_configselect("auth_{$auth}/field_updateremote_{$field}",
                    get_string('auth_updateremotefield', 'auth', $fieldname), '', 0, $updateextoptions));
            }

            // Lock fields.
            $settings->add(new admin_setting_configselect("auth_{$auth}/field_lock_{$field}",
                get_string('auth_fieldlockfield', 'auth', $fieldname), '', 'unlocked', $lockoptions));

        } else {
            // Lock fields Only.
            $settings->add(new admin_setting_configselect("auth_{$auth}/field_lock_{$field}",
                get_string('auth_fieldlockfield', 'auth', $fieldname), '', 'unlocked', $lockoptions));
        }
    }
}

/**
 * Return all user profile field names in an array.
 *
 * @return array|string[]|null
 */
function auth_agentconnect_get_all_user_fields() {
    $authplugin = get_auth_plugin('agentconnect');
    $userfields = $authplugin->userfields;
    $userfields = array_merge($userfields, $authplugin->get_custom_user_profile_fields());

    return $userfields;
}

/**
 * @param $username
 * @return false|mixed
 * @throws coding_exception
 * @throws dml_exception
 * @throws moodle_exception
 */
function auth_agentconnect_authenticate_user_login($username) {
    global $CFG;
    require_once($CFG->libdir . "/authlib.php");
    require_once($CFG->dirroot."/user/profile/lib.php");
    require_once($CFG->dirroot.'/user/lib.php');

    $user = get_complete_user_data('username', $username, $CFG->mnet_localhost_id);
    utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
            'username'   => $username,
            'userexists' => !empty($user)
    ]);
    $authplugin = get_auth_plugin('agentconnect');
    $authplugin->pre_user_login_hook($user);

    // nologin = Legacy way to suspend user.
    $failurereason = !empty($user->suspended) || $user->auth == 'nologin' ? AUTH_LOGIN_SUSPENDED : null;
    $userlogin     = $authplugin->user_login($username, null);
    $failurereason = !$userlogin && $failurereason === null ? AUTH_LOGIN_UNAUTHORISED : $failurereason;
    if ($failurereason) {
        // Trigger login failed event.
        $eventdata = ['other' => ['username' => $username, 'reason' => $failurereason]];
        $event = \core\event\user_login_failed::create($eventdata);
        $event->trigger();

        utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
                'event'     => 'user_login_failed',
                'eventdata' => $eventdata
        ]);

        throw new \moodle_exception('errorauthloginfailednouser', 'auth_agentconnect', null, null);
    }

    // Update user record from agentconnect data.
    $newuser = array();
    // UPDATE : 20230329
    if ($newinfo = $authplugin->get_userinfo($username)) {
        $newinfo = truncate_userinfo($newinfo);
        $customfields = $authplugin->get_custom_user_profile_fields();

        foreach ($newinfo as $key => $value) {
            $iscustom = in_array($key, $customfields);
            if (!$iscustom) {
                $key = strtolower($key);
            }
            if ((!property_exists($user, $key) && !$iscustom) or $key === 'username' or $key === 'id'
                or $key === 'auth' or $key === 'mnethostid' or $key === 'deleted') {
                // Unknown or must not be changed.
                continue;
            }
            if (empty($authplugin->config->{'field_updatelocal_' . $key}) || empty($authplugin->config->{'field_lock_' . $key})) {
                continue;
            }
            $confval = $authplugin->config->{'field_updatelocal_' . $key};
            $lockval = $authplugin->config->{'field_lock_' . $key};

            if ($confval === 'onlogin') {
                // MDL-4207 Don't overwrite modified user profile values with
                // empty LDAP values when 'unlocked if empty' is set. The purpose
                // of the setting 'unlocked if empty' is to allow the user to fill
                // in a value for the selected field _if LDAP is giving
                // nothing_ for this field. Thus it makes sense to let this value
                // stand in until LDAP is giving a value for this field.
                if (!(empty($value) && $lockval === 'unlockedifempty')) {
                    if ($iscustom || (in_array($key, $authplugin->userfields) && ((string)$user->$key !== (string)$value))) {
                        $newuser[$key] = (string)$value;
                    }
                }
            }
        }
        utils::debug_log(__FILE__, __LINE__, __FUNCTION__, [
                'newuser' => $newuser
        ]);
        if ($newuser) {
            $newuser['id'] = $user->id;
            $newuser['timemodified'] = time();
            user_update_user((object) $newuser, false, false);

            // Save user profile data.
            profile_save_data((object) $newuser);

            // Trigger event.
            \core\event\user_updated::create_from_userid($newuser['id'])->trigger();
            $user = get_complete_user_data('id', $user->id);
        }
    }

    $authplugin->user_authenticated_hook($user, $username, null);
    login_attempt_valid($user);
    return $user;
}