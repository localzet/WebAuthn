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
use localzet\WebAuthn\Binary\ByteBuffer;
use localzet\WebAuthn\Exception;
use function array_key_exists;
use function count;
use function is_array;
use function is_object;
use function openssl_error_string;
use function openssl_pkey_get_public;
use function openssl_verify;
use function openssl_x509_checkpurpose;

/**
 *
 */
class AndroidKey extends FormatBase
{
    /**
     * @var mixed
     */
    private mixed $_alg;
    /**
     * @var string
     */
    private string $_signature;
    /**
     * @var string
     */
    private string $_x5c;

    /**
     * @param $AttestionObject
     * @param AuthenticatorData $authenticatorData
     * @throws Exception
     */
    public function __construct($AttestionObject, AuthenticatorData $authenticatorData)
    {
        parent::__construct($AttestionObject, $authenticatorData);

        // check u2f data
        $attStmt = $this->_attestationObject['attStmt'];

        if (!array_key_exists('alg', $attStmt) || $this->_getCoseAlgorithm($attStmt['alg']) === null) {
            throw new Exception('Неподдерживаемый алгоритм: ' . $attStmt['alg'], Exception::INVALID_DATA);
        }

        if (!array_key_exists('sig', $attStmt) || !is_object($attStmt['sig']) || !($attStmt['sig'] instanceof ByteBuffer)) {
            throw new Exception('Подпись не найдена', Exception::INVALID_DATA);
        }

        if (!array_key_exists('x5c', $attStmt) || !is_array($attStmt['x5c']) || count($attStmt['x5c']) < 1) {
            throw new Exception('Недействительный сертификат x5c', Exception::INVALID_DATA);
        }

        if (!is_object($attStmt['x5c'][0]) || !($attStmt['x5c'][0] instanceof ByteBuffer)) {
            throw new Exception('Недействительный сертификат x5c', Exception::INVALID_DATA);
        }

        $this->_alg = $attStmt['alg'];
        $this->_signature = $attStmt['sig']->getBinaryString();
        $this->_x5c = $attStmt['x5c'][0]->getBinaryString();

        if (count($attStmt['x5c']) > 1) {
            for ($i = 1; $i < count($attStmt['x5c']); $i++) {
                $this->_x5c_chain[] = $attStmt['x5c'][$i]->getBinaryString();
            }
            unset($i);
        }
    }


    /**
     * returns the key certificate in PEM format
     * @return string|null
     */
    public function getCertificatePem(): ?string
    {
        return $this->_createCertificatePem($this->_x5c);
    }

    /**
     * @param string $clientDataHash
     * @return bool
     * @throws Exception
     */
    public function validateAttestation(string $clientDataHash): bool
    {
        $publicKey = openssl_pkey_get_public($this->getCertificatePem());

        if ($publicKey === false) {
            throw new Exception('Неверный открытый ключ: ' . openssl_error_string(), Exception::INVALID_PUBLIC_KEY);
        }

        // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
        // using the attestation public key in attestnCert with the algorithm specified in alg.
        $dataToVerify = $this->_authenticatorData->getBinary();
        $dataToVerify .= $clientDataHash;

        $coseAlgorithm = $this->_getCoseAlgorithm($this->_alg);

        // check certificate
        return openssl_verify($dataToVerify, $this->_signature, $publicKey, $coseAlgorithm->openssl) === 1;
    }

    /**
     * validates the certificate against root certificates
     * @param array $rootCas
     * @return boolean
     * @throws Exception
     */
    public function validateRootCertificate(array $rootCas): bool
    {
        $chainC = $this->_createX5cChainFile();
        if ($chainC) {
            $rootCas[] = $chainC;
        }

        $v = openssl_x509_checkpurpose($this->getCertificatePem(), -1, $rootCas);
        if ($v === -1) {
            throw new Exception('Ошибка при проверке корневого сертификата: ' . openssl_error_string(), Exception::CERTIFICATE_NOT_TRUSTED);
        }
        return $v;
    }
}
