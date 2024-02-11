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

namespace localzet\WebAuthn\Attestation;

use localzet\WebAuthn\Attestation\Format\{AndroidKey, AndroidSafetyNet, Apple, FormatBase, None, Packed, Tpm, U2f};
use localzet\WebAuthn\Binary\ByteBuffer;
use localzet\WebAuthn\CBOR\CborDecoder;
use localzet\WebAuthn\Exception;
use function array_key_exists;
use function is_array;
use function is_object;
use function openssl_x509_parse;

/**
 *
 */
class AttestationObject
{
    /**
     * @var AuthenticatorData
     */
    private AuthenticatorData $_authenticatorData;
    /**
     * @var U2f|AndroidSafetyNet|AndroidKey|None|Packed|Apple|Tpm
     */
    private Format\U2f|Format\AndroidSafetyNet|Format\AndroidKey|Format\None|Format\Packed|Format\Apple|Format\Tpm $_attestationFormat;
    /**
     * @var string
     */
    private string $_attestationFormatName;

    /**
     * @throws Exception
     */
    public function __construct($binary, $allowedFormats)
    {
        $enc = CborDecoder::decode($binary);

        if (!is_array($enc) || !array_key_exists('fmt', $enc) || !is_string($enc['fmt'])) {
            throw new Exception('Неверный формат аттестации', Exception::INVALID_DATA);
        }

        if (!array_key_exists('attStmt', $enc) || !is_array($enc['attStmt'])) {
            throw new Exception('Неверный формат аттестации (attStmt недоступен)', Exception::INVALID_DATA);
        }

        if (!array_key_exists('authData', $enc) || !is_object($enc['authData']) || !($enc['authData'] instanceof ByteBuffer)) {
            throw new Exception('Неверный формат аттестации (authData недоступен)', Exception::INVALID_DATA);
        }

        $this->_authenticatorData = new AuthenticatorData($enc['authData']->getBinaryString());
        $this->_attestationFormatName = $enc['fmt'];

        if (!in_array($this->_attestationFormatName, $allowedFormats)) {
            throw new Exception('Неверный формат аттестации: ' . $this->_attestationFormatName, Exception::INVALID_DATA);
        }


        $this->_attestationFormat = match ($this->_attestationFormatName) {
            'android-key' => new Format\AndroidKey($enc, $this->_authenticatorData),
            'android-safetynet' => new Format\AndroidSafetyNet($enc, $this->_authenticatorData),
            'apple' => new Format\Apple($enc, $this->_authenticatorData),
            'fido-u2f' => new Format\U2f($enc, $this->_authenticatorData),
            'none' => new Format\None($enc, $this->_authenticatorData),
            'packed' => new Format\Packed($enc, $this->_authenticatorData),
            'tpm' => new Format\Tpm($enc, $this->_authenticatorData),
            default => throw new Exception('Неверный формат аттестации: ' . $enc['fmt'], Exception::INVALID_DATA),
        };
    }

    /**
     * Вернуть имя формата аттестации
     * @return string
     */
    public function getAttestationFormatName(): string
    {
        return $this->_attestationFormatName;
    }

    /**
     * Вернуть класс формата аттестации
     * @return FormatBase|Tpm|Apple|Packed|None|AndroidKey|AndroidSafetyNet|U2f
     */
    public function getAttestationFormat(): Format\FormatBase|Format\Tpm|Format\Apple|Format\Packed|Format\None|Format\AndroidKey|Format\AndroidSafetyNet|Format\U2f
    {
        return $this->_attestationFormat;
    }

    /**
     * Вернуть открытый ключ аттестации в формате PEM
     * @return AuthenticatorData
     */
    public function getAuthenticatorData(): AuthenticatorData
    {
        return $this->_authenticatorData;
    }

    /**
     * Вернуть цепочку сертификатов как PEM
     * @return string|null
     */
    public function getCertificateChain(): ?string
    {
        return $this->_attestationFormat->getCertificateChain();
    }

    /**
     * Вернуть эмитента сертификата в виде строки
     * @return string
     */
    public function getCertificateIssuer(): string
    {
        $pem = $this->getCertificatePem();
        $issuer = '';
        if ($pem) {
            $certInfo = openssl_x509_parse($pem);
            if (is_array($certInfo) && array_key_exists('issuer', $certInfo) && is_array($certInfo['issuer'])) {

                $cn = $certInfo['issuer']['CN'] ?? '';
                $o = $certInfo['issuer']['O'] ?? '';
                $ou = $certInfo['issuer']['OU'] ?? '';

                if ($cn) {
                    $issuer .= $cn;
                }
                if ($issuer && ($o || $ou)) {
                    $issuer .= ' (' . trim($o . ' ' . $ou) . ')';
                } else {
                    $issuer .= trim($o . ' ' . $ou);
                }
            }
        }

        return $issuer;
    }

    /**
     * Вернуть субъект сертификата в виде строки
     * @return string
     */
    public function getCertificateSubject(): string
    {
        $pem = $this->getCertificatePem();
        $subject = '';
        if ($pem) {
            $certInfo = openssl_x509_parse($pem);
            if (is_array($certInfo) && array_key_exists('subject', $certInfo) && is_array($certInfo['subject'])) {

                $cn = $certInfo['subject']['CN'] ?? '';
                $o = $certInfo['subject']['O'] ?? '';
                $ou = $certInfo['subject']['OU'] ?? '';

                if ($cn) {
                    $subject .= $cn;
                }
                if ($subject && ($o || $ou)) {
                    $subject .= ' (' . trim($o . ' ' . $ou) . ')';
                } else {
                    $subject .= trim($o . ' ' . $ou);
                }
            }
        }

        return $subject;
    }

    /**
     * Возвращает ключ сертификата в формате PEM
     * @return string|null
     */
    public function getCertificatePem(): ?string
    {
        return $this->_attestationFormat->getCertificatePem();
    }

    /**
     * Проверяет действительность подписи
     * @param string $clientDataHash
     * @return bool
     * @throws Exception
     */
    public function validateAttestation(string $clientDataHash): bool
    {
        return $this->_attestationFormat->validateAttestation($clientDataHash);
    }

    /**
     * Проверяет сертификат на соответствие корневым сертификатам
     * @param array $rootCas
     * @return boolean
     * @throws Exception
     */
    public function validateRootCertificate(array $rootCas): bool
    {
        return $this->_attestationFormat->validateRootCertificate($rootCas);
    }

    /**
     * Проверяет, соответствует ли RpId хэшу
     * @param string $rpIdHash
     * @return bool
     */
    public function validateRpIdHash(string $rpIdHash): bool
    {
        return $rpIdHash === $this->_authenticatorData->getRpIdHash();
    }
}
