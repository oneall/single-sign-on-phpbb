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
namespace oneall\singlesignon\migrations\v10x;

/**
 * Migration stage 3: add OneAll group to GROUPS_TABLE
 */
class m3_group_data extends \phpbb\db\migration\migration
{
    public function update_data()
    {
        return array(
            array(
                'custom',
                array(
                    array(
                        $this,
                        'add_group_register_oneall'
                    )
                )
            )
        );
    }

    public function add_group_register_oneall()
    {
        $group_data = array(
            'group_type' => GROUP_SPECIAL,
            'group_name' => 'OA_SINGLE_SIGN_ON_REGISTER',
            'group_desc' => 'Members registered via OneAll single sign on'
        );
        $sql = 'INSERT INTO ' . GROUPS_TABLE . ' ' . $this->db->sql_build_array('INSERT', $group_data);
        $this->db->sql_query($sql);
    }

    public function revert_data()
    {
        return array(
            array(
                'custom',
                array(
                    array(
                        $this,
                        'del_group_register_oneall'
                    )
                )
            )
        );
    }

    public function del_group_register_oneall()
    {
        $sql = 'DELETE FROM ' . GROUPS_TABLE . " WHERE group_name = 'OA_SINGLE_SIGN_ON_REGISTER'";
        $this->db->sql_query($sql);
    }
}
