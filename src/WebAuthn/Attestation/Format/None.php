<?php

/**
 * @package     Localzet WebAuthn library
 * @link        https://github.com/localzet/WebAuthn
 *
 * @author      Ivan Zorin <creator@localzet.com>
 * @copyright   Copyright (c) 2018-2023 Localzet Group
 * @license     GNU Affero General Public License, version 3
 *
 *              This program is free software: you can redistribute it and/or modify
 *              it under the terms of the GNU Affero General Public License as
 *              published by the Free Software Foundation, either version 3 of the
 *              License, or (at your option) any later version.
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *              GNU Affero General Public License for more details.
 *
 *              You should have received a copy of the GNU Affero General Public License
 *              along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

namespace localzet\WebAuthn\Attestation\Format;

use localzet\WebAuthn\Attestation\AuthenticatorData;
use localzet\WebAuthn\Exception;

/**
 *
 */
class None extends FormatBase
{


    /**
     * @param $AttestionObject
     * @param AuthenticatorData $authenticatorData
     */
    public function __construct($AttestionObject, AuthenticatorData $authenticatorData)
    {
        parent::__construct($AttestionObject, $authenticatorData);
    }


    /**
     * returns the key certificate in PEM format
     * @return string|null
     */
    public function getCertificatePem(): ?string
    {
        return null;
    }

    /**
     * @param string $clientDataHash
     * @return bool
     */
    public function validateAttestation(string $clientDataHash): bool
    {
        return true;
    }

    /**
     * validates the certificate against root certificates.
     * Format 'none' does not contain any ca, so always false.
     * @param array $rootCas
     * @return boolean
     * @throws Exception
     */
    public function validateRootCertificate(array $rootCas): bool
    {
        return false;
    }
}
