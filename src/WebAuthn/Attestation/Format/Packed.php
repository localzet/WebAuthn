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
class Packed extends FormatBase
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
     * @throws Exception
     */
    public function __construct($AttestionObject, AuthenticatorData $authenticatorData)
    {
        parent::__construct($AttestionObject, $authenticatorData);

        // check packed data
        $attStmt = $this->_attestationObject['attStmt'];

        if (!array_key_exists('alg', $attStmt) || $this->_getCoseAlgorithm($attStmt['alg']) === null) {
            throw new Exception('Неподдерживаемый алгоритм: ' . $attStmt['alg'], Exception::INVALID_DATA);
        }

        if (!array_key_exists('sig', $attStmt) || !is_object($attStmt['sig']) || !($attStmt['sig'] instanceof ByteBuffer)) {
            throw new Exception('Подпись не найдена', Exception::INVALID_DATA);
        }

        $this->_alg = $attStmt['alg'];
        $this->_signature = $attStmt['sig']->getBinaryString();

        // certificate for validation
        if (array_key_exists('x5c', $attStmt) && is_array($attStmt['x5c']) && count($attStmt['x5c']) > 0) {

            // The attestation certificate attestnCert MUST be the first element in the array
            $attestnCert = array_shift($attStmt['x5c']);

            if (!($attestnCert instanceof ByteBuffer)) {
                throw new Exception('Недействительный сертификат x5c', Exception::INVALID_DATA);
            }

            $this->_x5c = $attestnCert->getBinaryString();

            // certificate chain
            foreach ($attStmt['x5c'] as $chain) {
                if ($chain instanceof ByteBuffer) {
                    $this->_x5c_chain[] = $chain->getBinaryString();
                }
            }
        }
    }


    /**
     * returns the key certificate in PEM format
     * @return string|null
     */
    public function getCertificatePem(): ?string
    {
        if (!$this->_x5c) {
            return null;
        }
        return $this->_createCertificatePem($this->_x5c);
    }

    /**
     * @param string $clientDataHash
     * @return bool
     * @throws Exception
     */
    public function validateAttestation(string $clientDataHash): bool
    {
        if ($this->_x5c) {
            return $this->_validateOverX5c($clientDataHash);
        } else {
            return $this->_validateSelfAttestation($clientDataHash);
        }
    }

    /**
     * validates the certificate against root certificates
     * @param array $rootCas
     * @return boolean
     * @throws Exception
     */
    public function validateRootCertificate(array $rootCas): bool
    {
        if (!$this->_x5c) {
            return false;
        }

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

    /**
     * validate if x5c is present
     * @param string $clientDataHash
     * @return bool
     * @throws Exception
     */
    protected function _validateOverX5c(string $clientDataHash): bool
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
     * validate if self attestation is in use
     * @param string $clientDataHash
     * @return bool
     * @throws Exception
     */
    protected function _validateSelfAttestation(string $clientDataHash): bool
    {
        // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
        // using the credential public key with alg.
        $dataToVerify = $this->_authenticatorData->getBinary();
        $dataToVerify .= $clientDataHash;

        $publicKey = $this->_authenticatorData->getPublicKeyPem();

        // check certificate
        return openssl_verify($dataToVerify, $this->_signature, $publicKey, OPENSSL_ALGO_SHA256) === 1;
    }
}
