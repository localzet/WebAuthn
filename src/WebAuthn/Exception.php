<?php

/*
 * @package     Localzet WebAuthn library
 * @link        https://github.com/localzet/WebAuthn
 *
 * @author      Ivan Zorin <creator@localzet.com>
 * @copyright   Copyright (c) 2018-2024 Zorin Projects S.P.
 * @license     https://www.gnu.org/licenses/agpl-3.0 GNU Affero General Public License v3.0
 *
 *              This program is free software: you can redistribute it and/or modify
 *              it under the terms of the GNU Affero General Public License as published
 *              by the Free Software Foundation, either version 3 of the License, or
 *              (at your option) any later version.
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *              GNU Affero General Public License for more details.
 *
 *              You should have received a copy of the GNU Affero General Public License
 *              along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *              For any questions, please contact <creator@localzet.com>
 */

namespace localzet\WebAuthn;

class Exception extends \Exception
{
    const INVALID_DATA = 1;
    const INVALID_TYPE = 2;
    const INVALID_CHALLENGE = 3;
    const INVALID_ORIGIN = 4;
    const INVALID_RELYING_PARTY = 5;
    const INVALID_SIGNATURE = 6;
    const INVALID_PUBLIC_KEY = 7;
    const CERTIFICATE_NOT_TRUSTED = 8;
    const USER_PRESENT = 9;
    const USER_VERIFICATED = 10;
    const SIGNATURE_COUNTER = 11;
    const CRYPTO_STRONG = 13;
    const BYTEBUFFER = 14;
    const CBOR = 15;
    const ANDROID_NOT_TRUSTED = 16;

    public function __construct($message = "", $code = 0, $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
