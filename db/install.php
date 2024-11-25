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
 * Plugin installation file
 *
 * @package    auth
 * @subpackage auth_agentconnect
 * @copyright  2021 Edunao SAS (contact@edunao.com)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
defined('MOODLE_INTERNAL') || die();

function xmldb_auth_agentconnect_install() {
    global $DB;
    $category            = (object) [
            'name'      => 'AgentConnect',
            'sortorder' => 10
    ];
    $categoryid          = $DB->insert_record('user_info_category', $category);
    $category->id        = $categoryid;
    $category->sortorder = $categoryid;
    $DB->update_record('user_info_category', $category);

    $userfield = (object) [
            'shortname'   => 'agentconnectid',
            'name'        => 'AgentConnectID',
            'datatype'    => 'text',
            'categoryid'  => $categoryid,
            'required'    => 0,
            'locked'      => 1,
            'visible'     => 0,
            'forceunique' => 1,
            'signup'      => 0
    ];
    $DB->insert_record('user_info_field', $userfield);

    return true;
}
