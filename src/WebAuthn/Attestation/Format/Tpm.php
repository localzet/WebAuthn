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
use function array_key_exists;
use function count;
use function hash;
use function is_array;
use function is_object;
use function openssl_error_string;
use function openssl_pkey_get_public;
use function openssl_verify;
use function openssl_x509_checkpurpose;

/**
 *
 */
class Tpm extends FormatBase
{
    /**
     * @var string
     */
    private string $_TPM_GENERATED_VALUE = "\xFF\x54\x43\x47";
    /**
     * @var string
     */
    private string $_TPM_ST_ATTEST_CERTIFY = "\x80\x17";
    /**
     * @var mixed
     */
    private mixed $_alg;
    /**
     * @var string
     */
    private string $_signature;
    /**
     * @var ByteBuffer
     */
    private ByteBuffer $_pubArea;
    /**
     * @var string
     */
    private string $_x5c;

    /**
     * @var ByteBuffer
     */
    private ByteBuffer $_certInfo;


    /**
     * @throws Exception
     */
    public function __construct($AttestionObject, AuthenticatorData $authenticatorData)
    {
        parent::__construct($AttestionObject, $authenticatorData);

        // check packed data
        $attStmt = $this->_attestationObject['attStmt'];

        if (!array_key_exists('ver', $attStmt) || $attStmt['ver'] !== '2.0') {
            throw new Exception('Неверная версия tpm: ' . $attStmt['ver'], Exception::INVALID_DATA);
        }

        if (!array_key_exists('alg', $attStmt) || $this->_getCoseAlgorithm($attStmt['alg']) === null) {
            throw new Exception('Неподдерживаемый алгоритм: ' . $attStmt['alg'], Exception::INVALID_DATA);
        }

        if (!array_key_exists('sig', $attStmt) || !is_object($attStmt['sig']) || !($attStmt['sig'] instanceof ByteBuffer)) {
            throw new Exception('Подпись не найдена', Exception::INVALID_DATA);
        }

        if (!array_key_exists('certInfo', $attStmt) || !is_object($attStmt['certInfo']) || !($attStmt['certInfo'] instanceof ByteBuffer)) {
            throw new Exception('certInfo не найден', Exception::INVALID_DATA);
        }

        if (!array_key_exists('pubArea', $attStmt) || !is_object($attStmt['pubArea']) || !($attStmt['pubArea'] instanceof ByteBuffer)) {
            throw new Exception('pubArea не найден', Exception::INVALID_DATA);
        }

        $this->_alg = $attStmt['alg'];
        $this->_signature = $attStmt['sig']->getBinaryString();
        $this->_certInfo = $attStmt['certInfo'];
        $this->_pubArea = $attStmt['pubArea'];

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
            throw new Exception('Сертификат x5c не найден', Exception::INVALID_DATA);
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

        // Concatenate authenticatorData and clientDataHash to form attToBeSigned.
        $attToBeSigned = $this->_authenticatorData->getBinary();
        $attToBeSigned .= $clientDataHash;

        // Validate that certInfo is valid:

        // Verify that magic is set to TPM_GENERATED_VALUE.
        if ($this->_certInfo->getBytes(0, 4) !== $this->_TPM_GENERATED_VALUE) {
            throw new Exception('Магия TPM не TPM_GENERATED_VALUE', Exception::INVALID_DATA);
        }

        // Verify that type is set to TPM_ST_ATTEST_CERTIFY.
        if ($this->_certInfo->getBytes(4, 2) !== $this->_TPM_ST_ATTEST_CERTIFY) {
            throw new Exception('Тип TPM не TPM_ST_ATTEST_CERTIFY', Exception::INVALID_DATA);
        }

        $offset = 6;
        $qualifiedSigner = $this->_tpmReadLengthPrefixed($this->_certInfo, $offset);
        $extraData = $this->_tpmReadLengthPrefixed($this->_certInfo, $offset);
        $coseAlg = $this->_getCoseAlgorithm($this->_alg);

        // Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
        if ($extraData->getBinaryString() !== hash($coseAlg->hash, $attToBeSigned, true)) {
            throw new Exception('certInfo:extraData не является хэшем attToBeSigned', Exception::INVALID_DATA);
        }

        // Verify the sig is a valid signature over certInfo using the attestation
        // public key in aikCert with the algorithm specified in alg.
        return openssl_verify($this->_certInfo->getBinaryString(), $this->_signature, $publicKey, $coseAlg->openssl) === 1;
    }


    /**
     * returns next part of ByteBuffer
     * @param ByteBuffer $buffer
     * @param int $offset
     * @return ByteBuffer
     * @throws Exception
     */
    protected function _tpmReadLengthPrefixed(ByteBuffer $buffer, int &$offset): ByteBuffer
    {
        $len = $buffer->getUint16Val($offset);
        $data = $buffer->getBytes($offset + 2, $len);
        $offset += (2 + $len);

        return new ByteBuffer($data);
    }
}
