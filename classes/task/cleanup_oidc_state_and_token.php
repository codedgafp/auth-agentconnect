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
 * A scheduled task to clean up oidc state and invalid token.
 *
 * @package auth_agentconnect
 * @author Lai Wei <lai.wei@enovation.ie>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2021 onwards Microsoft, Inc. (http://microsoft.com/)
 */

namespace auth_agentconnect\task;

defined('MOODLE_INTERNAL') || die();

use core\task\scheduled_task;

class cleanup_oidc_state_and_token extends scheduled_task {
    /**
     * Get a descriptive name for the task.
     */
    public function get_name() {
        return get_string('task_cleanup_oidc_state_and_token', 'auth_agentconnect');
    }

    /**
     * Clean up oidc state and invalid oidc token.
     */
    public function execute() {
        global $DB;

        // Clean up oidc state.
        $DB->delete_records_select('auth_agentconnect_state', 'timecreated < ?', [strtotime('-5 min')]);

        // Clean up invalid oidc token.
        $DB->delete_records('auth_agentconnect_token', ['userid' => 0]);
    }
}
