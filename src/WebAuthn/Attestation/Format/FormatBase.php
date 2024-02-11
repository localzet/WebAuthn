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
use stdClass;
use function base64_encode;
use function base_convert;
use function chunk_split;
use function count;
use function file_get_contents;
use function file_put_contents;
use function in_array;
use function is_array;
use function is_file;
use function openssl_x509_parse;
use function rand;
use function sys_get_temp_dir;
use function unlink;


/**
 *
 */
abstract class FormatBase
{
    /**
     * @var array|null
     */
    protected ?array $_attestationObject = null;
    /**
     * @var AuthenticatorData|null
     */
    protected ?AuthenticatorData $_authenticatorData = null;
    /**
     * @var array
     */
    protected array $_x5c_chain = array();
    /**
     * @var string|null
     */
    protected ?string $_x5c_tempFile = null;

    /**
     *
     * @param array $AttestionObject
     * @param AuthenticatorData $authenticatorData
     */
    public function __construct(array $AttestionObject, AuthenticatorData $authenticatorData)
    {
        $this->_attestationObject = $AttestionObject;
        $this->_authenticatorData = $authenticatorData;
    }

    /**
     *
     */
    public function __destruct()
    {
        // delete X.509 chain certificate file after use
        if ($this->_x5c_tempFile && is_file($this->_x5c_tempFile)) {
            unlink($this->_x5c_tempFile);
        }
    }

    /**
     * returns the certificate chain in PEM format
     * @return string|null
     */
    public function getCertificateChain(): ?string
    {
        if ($this->_x5c_tempFile && is_file($this->_x5c_tempFile)) {
            return file_get_contents($this->_x5c_tempFile);
        }
        return null;
    }

    /**
     * returns the key X.509 certificate in PEM format
     * @return string|null
     */
    public function getCertificatePem(): ?string
    {
        // need to be overwritten
        return null;
    }

    /**
     * checks validity of the signature
     * @param string $clientDataHash
     * @return bool
     */
    public function validateAttestation(string $clientDataHash): bool
    {
        // need to be overwritten
        return false;
    }

    /**
     * validates the certificate against root certificates
     * @param array $rootCas
     * @return boolean
     */
    public function validateRootCertificate(array $rootCas): bool
    {
        // need to be overwritten
        return false;
    }


    /**
     * create a PEM encoded certificate with X.509 binary data
     * @param string $x5c
     * @return string
     */
    protected function _createCertificatePem(string $x5c): string
    {
        $pem = '-----BEGIN CERTIFICATE-----' . "\n";
        $pem .= chunk_split(base64_encode($x5c), 64, "\n");
        $pem .= '-----END CERTIFICATE-----' . "\n";
        return $pem;
    }

    /**
     * creates a PEM encoded chain file
     */
    protected function _createX5cChainFile(): ?string
    {
        $content = '';
        if (count($this->_x5c_chain) > 0) {
            foreach ($this->_x5c_chain as $x5c) {
                $certInfo = openssl_x509_parse($this->_createCertificatePem($x5c));

                // check if certificate is self signed
                if (is_array($certInfo) && is_array($certInfo['issuer']) && is_array($certInfo['subject'])) {
                    $selfSigned = false;

                    $subjectKeyIdentifier = $certInfo['extensions']['subjectKeyIdentifier'] ?? null;
                    $authorityKeyIdentifier = $certInfo['extensions']['authorityKeyIdentifier'] ?? null;

                    if ($authorityKeyIdentifier && str_starts_with($authorityKeyIdentifier, 'keyid:')) {
                        $authorityKeyIdentifier = substr($authorityKeyIdentifier, 6);
                    }
                    if ($subjectKeyIdentifier && str_starts_with($subjectKeyIdentifier, 'keyid:')) {
                        $subjectKeyIdentifier = substr($subjectKeyIdentifier, 6);
                    }

                    if (($subjectKeyIdentifier && !$authorityKeyIdentifier) || ($authorityKeyIdentifier && $authorityKeyIdentifier === $subjectKeyIdentifier)) {
                        $selfSigned = true;
                    }

                    if (!$selfSigned) {
                        $content .= "\n" . $this->_createCertificatePem($x5c) . "\n";
                    }
                }
            }
        }

        if ($content) {
            $this->_x5c_tempFile = sys_get_temp_dir() . '/x5c_chain_' . base_convert(rand(), 10, 36) . '.pem';
            if (file_put_contents($this->_x5c_tempFile, $content) !== false) {
                return $this->_x5c_tempFile;
            }
        }

        return null;
    }


    /**
     * returns the name and openssl key for provided cose number.
     * @param int $coseNumber
     * @return stdClass|null
     */
    protected function _getCoseAlgorithm(int $coseNumber): ?stdClass
    {
        // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
        $coseAlgorithms = array(
            array(
                'hash' => 'SHA1',
                'openssl' => OPENSSL_ALGO_SHA1,
                'cose' => array(
                    -65535  // RS1
                )
            ),

            array(
                'hash' => 'SHA256',
                'openssl' => OPENSSL_ALGO_SHA256,
                'cose' => array(
                    -257, // RS256
                    -37,  // PS256
                    -7,   // ES256
                    5     // HMAC256
                )
            ),

            array(
                'hash' => 'SHA384',
                'openssl' => OPENSSL_ALGO_SHA384,
                'cose' => array(
                    -258, // RS384
                    -38,  // PS384
                    -35,  // ES384
                    6     // HMAC384
                )
            ),

            array(
                'hash' => 'SHA512',
                'openssl' => OPENSSL_ALGO_SHA512,
                'cose' => array(
                    -259, // RS512
                    -39,  // PS512
                    -36,  // ES512
                    7     // HMAC512
                )
            )
        );

        foreach ($coseAlgorithms as $coseAlgorithm) {
            if (in_array($coseNumber, $coseAlgorithm['cose'], true)) {
                $return = new stdClass();
                $return->hash = $coseAlgorithm['hash'];
                $return->openssl = $coseAlgorithm['openssl'];
                return $return;
            }
        }

        return null;
    }
}
