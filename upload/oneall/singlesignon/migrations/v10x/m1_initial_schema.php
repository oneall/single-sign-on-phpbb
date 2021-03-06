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
 * Migration stage 1: Initial schema changes to the database
 */
class m1_initial_schema extends \phpbb\db\migration\migration
{
    public function update_schema()
    {
        return array(
            'add_tables' => array(
                $this->table_prefix . 'oasl_identity' => array(
                    'COLUMNS' => array(
                        'oasl_identity_id' => array(
                            'UINT',
                            null,
                            'auto_increment'
                        ),
                        'oasl_user_id' => array(
                            'UINT',
                            0
                        ),
                        'identity_token' => array(
                            'VCHAR:255',
                            ''
                        ),
                        'identity_provider' => array(
                            'VCHAR:255',
                            ''
                        ),
                        'sso_session_token' => array(
                            'CHAR:36',
                            null
                        ),
                        'sso_session_token_expiration' => array(
                            'UINT:11',
                            null
                        ),
                        'num_logins' => array(
                            'UINT',
                            0
                        ),
                        'date_added' => array(
                            'TIMESTAMP',
                            0
                        ),
                        'date_updated' => array(
                            'TIMESTAMP',
                            0
                        )
                    ),
                    'PRIMARY_KEY' => 'oasl_identity_id',
                    'KEYS' => array(
                        'oaid' => array(
                            'UNIQUE',
                            'oasl_identity_id'
                        )
                    )
                ),
                $this->table_prefix . 'oasl_user' => array(
                    'COLUMNS' => array(
                        'oasl_user_id' => array(
                            'UINT',
                            null,
                            'auto_increment'
                        ),
                        'user_id' => array(
                            'UINT',
                            0
                        ),
                        'user_token' => array(
                            'VCHAR:255',
                            ''
                        ),
                        'date_added' => array(
                            'TIMESTAMP',
                            0
                        )
                    ),
                    'PRIMARY_KEY' => 'oasl_user_id',
                    'KEYS' => array(
                        'oauid' => array(
                            'UNIQUE',
                            'oasl_user_id'
                        )
                    )
                ),
                $this->table_prefix . 'oasl_notices' => array(
                    'COLUMNS' => array(
                        'notices' => array(
                            'TEXT',
                            ''
                        )
                    )
                )
            )
        );
    }

    public function revert_schema()
    {
        return array(
            'drop_tables' => array(
                $this->table_prefix . 'oasl_user',
                $this->table_prefix . 'oasl_identity'
            )
        );
    }
}
