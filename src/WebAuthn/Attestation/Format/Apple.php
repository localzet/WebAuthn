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
use function openssl_error_string;
use function openssl_pkey_get_public;
use function openssl_x509_checkpurpose;

/**
 *
 */
class Apple extends FormatBase
{
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
        } else {
            throw new Exception('Недействительное заявление об аттестации Apple: отсутствует x5c', Exception::INVALID_DATA);
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
        return $this->_validateOverX5c($clientDataHash);
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

        // Concatenate authenticatorData and clientDataHash to form nonceToHash.
        $nonceToHash = $this->_authenticatorData->getBinary();
        $nonceToHash .= $clientDataHash;

        // Perform SHA-256 hash of nonceToHash to produce nonce
        $nonce = hash('SHA256', $nonceToHash, true);

        $credCert = openssl_x509_read($this->getCertificatePem());
        if ($credCert === false) {
            throw new Exception('Недействительный сертификат x5c: ' . openssl_error_string(), Exception::INVALID_DATA);
        }

        $keyData = openssl_pkey_get_details(openssl_pkey_get_public($credCert));
        $key = is_array($keyData) && array_key_exists('key', $keyData) ? $keyData['key'] : null;


        // Verify that nonce equals the value of the extension with OID ( 1.2.840.113635.100.8.2 ) in credCert.
        $parsedCredCert = openssl_x509_parse($credCert);
        $nonceExtension = $parsedCredCert['extensions']['1.2.840.113635.100.8.2'] ?? '';

        // nonce padded by ASN.1 string: 30 24 A1 22 04 20
        // 30     — type tag indicating sequence
        // 24     — 36 byte following
        //   A1   — Enumerated [1]
        //   22   — 34 byte following
        //     04 — type tag indicating octet string
        //     20 — 32 byte following

        $asn1Padding = "\x30\x24\xA1\x22\x04\x20";
        if (str_starts_with($nonceExtension, $asn1Padding)) {
            $nonceExtension = substr($nonceExtension, strlen($asn1Padding));
        }

        if ($nonceExtension !== $nonce) {
            throw new Exception('Одноразовый номер не равен значению расширения с OID 1.2.840.113635.100.8.2', Exception::INVALID_DATA);
        }

        // Verify that the credential public key equals the Subject Public Key of credCert.
        $authKeyData = openssl_pkey_get_details(openssl_pkey_get_public($this->_authenticatorData->getPublicKeyPem()));
        $authKey = is_array($authKeyData) && array_key_exists('key', $authKeyData) ? $authKeyData['key'] : null;

        if ($key === null || $key !== $authKey) {
            throw new Exception('открытый ключ учетных данных не равен открытому ключу субъекта credCert', Exception::INVALID_DATA);
        }

        return true;
    }
}
