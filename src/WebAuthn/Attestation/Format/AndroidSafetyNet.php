<?php

/**
 * @package     Localzet WebAuthn library
 * @link        https://github.com/localzet/WebAuthn
 *
 * @author      Ivan Zorin <creator@localzet.com>
 * @copyright   Copyright (c) 2018-2024 Localzet Group
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
use stdClass;
use function array_key_exists;
use function base64_decode;
use function base64_encode;
use function count;
use function explode;
use function hash;
use function in_array;
use function is_array;
use function json_decode;
use function openssl_error_string;
use function openssl_pkey_get_public;
use function openssl_verify;
use function openssl_x509_checkpurpose;
use function openssl_x509_parse;
use function str_repeat;
use function strlen;

/**
 *
 */
class AndroidSafetyNet extends FormatBase
{
    /**
     * @var string
     */
    private string $_signature;
    /**
     * @var string
     */
    private string $_signedValue;
    /**
     * @var string|false
     */
    private string|false $_x5c;
    /**
     * @var stdClass
     */
    private stdClass $_payload;

    /**
     * @throws Exception
     */
    public function __construct($AttestionObject, AuthenticatorData $authenticatorData)
    {
        parent::__construct($AttestionObject, $authenticatorData);

        // check data
        $attStmt = $this->_attestationObject['attStmt'];

        if (!array_key_exists('ver', $attStmt) || !$attStmt['ver']) {
            throw new Exception('Неверный формат сети Android Safety', Exception::INVALID_DATA);
        }

        if (!array_key_exists('response', $attStmt) || !($attStmt['response'] instanceof ByteBuffer)) {
            throw new Exception('Неверный формат сети Android Safety', Exception::INVALID_DATA);
        }

        $response = $attStmt['response']->getBinaryString();

        // Response is a JWS [RFC7515] object in Compact Serialization.
        // JWSs have three segments separated by two period ('.') characters
        $parts = explode('.', $response);
        unset($response);
        if (count($parts) !== 3) {
            throw new Exception('Неверные данные JWS', Exception::INVALID_DATA);
        }

        $header = $this->_base64url_decode($parts[0]);
        $payload = $this->_base64url_decode($parts[1]);
        $this->_signature = $this->_base64url_decode($parts[2]);
        $this->_signedValue = $parts[0] . '.' . $parts[1];
        unset($parts);

        $header = json_decode($header);
        $payload = json_decode($payload);

        if (!($header instanceof stdClass)) {
            throw new Exception('Неверный заголовок JWS', Exception::INVALID_DATA);
        }
        if (!($payload instanceof stdClass)) {
            throw new Exception('Неверная полезная нагрузка JWS', Exception::INVALID_DATA);
        }

        if (!isset($header->x5c) || !is_array($header->x5c) || count($header->x5c) === 0) {
            throw new Exception('Нет подписи X.509 в заголовке JWS', Exception::INVALID_DATA);
        }

        // algorithm
        if (!in_array($header->alg, array('RS256', 'ES256'))) {
            throw new Exception('Неверный алгоритм JWS ' . $header->alg, Exception::INVALID_DATA);
        }

        $this->_x5c = base64_decode($header->x5c[0]);
        $this->_payload = $payload;

        if (count($header->x5c) > 1) {
            for ($i = 1; $i < count($header->x5c); $i++) {
                $this->_x5c_chain[] = base64_decode($header->x5c[$i]);
            }
            unset($i);
        }
    }

    /**
     * ctsProfileMatch: A stricter verdict of device integrity.
     * If the value of ctsProfileMatch is true, then the profile of the device running your app matches
     * the profile of a device that has passed Android compatibility testing and
     * has been approved as a Google-certified Android device.
     * @return bool
     */
    public function ctsProfileMatch(): bool
    {
        return isset($this->_payload->ctsProfileMatch) && !!$this->_payload->ctsProfileMatch;
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

        // Verify that the nonce in the response is identical to the Base64 encoding
        // of the SHA-256 hash of the concatenation of authenticatorData and clientDataHash.
        if (empty($this->_payload->nonce) || $this->_payload->nonce !== base64_encode(hash('SHA256', $this->_authenticatorData->getBinary() . $clientDataHash, true))) {
            throw new Exception('Недопустимый одноразовый номер в полезной нагрузке JWS', Exception::INVALID_DATA);
        }

        // Verify that attestationCert is issued to the hostname "attest.android.com"
        $certInfo = openssl_x509_parse($this->getCertificatePem());
        if (!is_array($certInfo) || ($certInfo['subject']['CN'] ?? '') !== 'attest.android.com') {
            throw new Exception('Недействительный сертификат CN в JWS (' . ($certInfo['subject']['CN'] ?? '-') . ')', Exception::INVALID_DATA);
        }

        // Verify that the basicIntegrity attribute in the payload of response is true.
        if (empty($this->_payload->basicIntegrity)) {
            throw new Exception('Недопустимая базовая целостность в полезной нагрузке', Exception::INVALID_DATA);
        }

        // check certificate
        return openssl_verify($this->_signedValue, $this->_signature, $publicKey, OPENSSL_ALGO_SHA256) === 1;
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
     * decode base64 url
     * @param string $data
     * @return string
     */
    private function _base64url_decode($data): string
    {
        return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', 3 - (3 + strlen($data)) % 4));
    }
}
