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

namespace localzet\WebAuthn\Attestation;

use localzet\WebAuthn\Binary\ByteBuffer;
use localzet\WebAuthn\CBOR\CborDecoder;
use localzet\WebAuthn\Exception;
use stdClass;
use function base64_encode;
use function chr;
use function chunk_split;
use function intdiv;
use function is_array;
use function ord;
use function strlen;
use function substr;
use function unpack;

/**
 * @author Lukas Buchs
 * @license https://github.com/lbuchs/WebAuthn/blob/master/LICENSE MIT
 */
class AuthenticatorData
{
    /**
     * @var string
     */
    protected string $_binary;
    /**
     * @var string
     */
    protected string $_rpIdHash;
    /**
     * @var stdClass
     */
    protected stdClass $_flags;
    /**
     * @var mixed
     */
    protected mixed $_signCount;
    /**
     * @var stdClass
     */
    protected stdClass $_attestedCredentialData;

    // Cose encoded keys
    /**
     * @var int
     */
    private static int $_COSE_KTY = 1;
    /**
     * @var int
     */
    private static int $_COSE_ALG = 3;

    // Cose EC2 ES256 P-256 curve
    /**
     * @var int
     */
    private static int $_COSE_CRV = -1;
    /**
     * @var int
     */
    private static int $_COSE_X = -2;
    /**
     * @var int
     */
    private static int $_COSE_Y = -3;

    // Cose RSA PS256
    /**
     * @var int
     */
    private static int $_COSE_N = -1;
    /**
     * @var int
     */
    private static int $_COSE_E = -2;

    /**
     * @var int
     */
    private static int $_EC2_TYPE = 2;
    /**
     * @var int
     */
    private static int $_EC2_ES256 = -7;
    /**
     * @var int
     */
    private static int $_EC2_P256 = 1;

    /**
     * @var int
     */
    private static int $_RSA_TYPE = 3;
    /**
     * @var int
     */
    private static int $_RSA_RS256 = -257;

    /**
     * Parsing the authenticatorData binary.
     * @param string $binary
     * @throws Exception
     */
    public function __construct(string $binary)
    {
        if (strlen($binary) < 37) {
            throw new Exception('Неверный ввод данных аутентификатора', Exception::INVALID_DATA);
        }
        $this->_binary = $binary;

        // Read infos from binary
        // https://www.w3.org/TR/webauthn/#sec-authenticator-data

        // RP ID
        $this->_rpIdHash = substr($binary, 0, 32);

        // flags (1 byte)
        $flags = unpack('Cflags', substr($binary, 32, 1))['flags'];
        $this->_flags = $this->_readFlags($flags);

        // signature counter: 32-bit unsigned big-endian integer.
        $this->_signCount = unpack('Nsigncount', substr($binary, 33, 4))['signcount'];

        $offset = 37;
        // https://www.w3.org/TR/webauthn/#sec-attested-credential-data
        if ($this->_flags->attestedDataIncluded) {
            $this->_attestedCredentialData = $this->_readAttestData($binary, $offset);
        }

        if ($this->_flags->extensionDataIncluded) {
            $this->_readExtensionData(substr($binary, $offset));
        }
    }

    /**
     * Authenticator Attestation Globally Unique Identifier, a unique number
     * that identifies the model of the authenticator (not the specific instance
     * of the authenticator)
     * The aaguid may be 0 if the user is using a old u2f device and/or if
     * the browser is using the fido-u2f format.
     * @return string
     */
    public function getAAGUID(): string
    {
        return $this->_attestedCredentialData->aaguid;
    }

    /**
     * Возвращает authenticatorData в двоичном виде
     * @return string
     */
    public function getBinary(): string
    {
        return $this->_binary;
    }

    /**
     * Возвращает credentialId
     * @return string
     */
    public function getCredentialId(): string
    {
        return $this->_attestedCredentialData->credentialId;
    }

    /**
     * Возвращает открытый ключ в формате PEM
     *
     * @return string
     * @throws Exception
     */
    public function getPublicKeyPem(): string
    {
        $der = match ($this->_attestedCredentialData->credentialPublicKey->kty) {
            self::$_EC2_TYPE => $this->_getEc2Der(),
            self::$_RSA_TYPE => $this->_getRsaDer(),
            default => throw new Exception('Неверный тип ключа', Exception::INVALID_DATA),
        };

        $pem = '-----BEGIN PUBLIC KEY-----' . "\n";
        $pem .= chunk_split(base64_encode($der), 64, "\n");
        $pem .= '-----END PUBLIC KEY-----' . "\n";
        return $pem;
    }

    /**
     * Возвращает открытый ключ в формате U2F
     *
     * @return string
     */
    public function getPublicKeyU2F(): string
    {
        return "\x04" . // ECC несжатый
            $this->_attestedCredentialData->credentialPublicKey->x .
            $this->_attestedCredentialData->credentialPublicKey->y;
    }

    /**
     * Возвращает хэш SHA256 идентификатора проверяющей стороны
     *
     * @return string
     */
    public function getRpIdHash(): string
    {
        return $this->_rpIdHash;
    }

    /**
     * Возвращает счетчик знака
     *
     * @return int
     */
    public function getSignCount(): int
    {
        return $this->_signCount;
    }

    /**
     * Возвращает true, если пользователь присутствует
     *
     * @return boolean
     */
    public function getUserPresent(): bool
    {
        return $this->_flags->userPresent;
    }

    /**
     * Возвращает true, если пользователь проверен
     *
     * @return boolean
     */
    public function getUserVerified(): bool
    {
        return $this->_flags->userVerified;
    }

    // -----------------------------------------------
    // PRIVATE
    // -----------------------------------------------

    /**
     * Возвращает ключ EC2 в кодировке DER
     *
     * @return string
     * @throws Exception
     */
    private function _getEc2Der(): string
    {
        return $this->_der_sequence(
            $this->_der_sequence(
                $this->_der_oid("\x2A\x86\x48\xCE\x3D\x02\x01") . // OID 1.2.840.10045.2.1 ecPublicKey
                $this->_der_oid("\x2A\x86\x48\xCE\x3D\x03\x01\x07")  // 1.2.840.10045.3.1.7 prime256v1
            ) .
            $this->_der_bitString($this->getPublicKeyU2F())
        );
    }

    /**
     * Возвращает ключ RSA в кодировке DER
     *
     * @return string
     */
    private function _getRsaDer(): string
    {
        return $this->_der_sequence(
            $this->_der_sequence(
                $this->_der_oid("\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01") . // OID 1.2.840.113549.1.1.1 rsaEncryption
                $this->_der_nullValue()
            ) .
            $this->_der_bitString(
                $this->_der_sequence(
                    $this->_der_unsignedInteger($this->_attestedCredentialData->credentialPublicKey->n) .
                    $this->_der_unsignedInteger($this->_attestedCredentialData->credentialPublicKey->e)
                )
            )
        );
    }

    /**
     * Читаем флаги из байта флага
     *
     * @param string $binFlag
     *
     * @return stdClass
     */
    private function _readFlags(string $binFlag): stdClass
    {
        $flags = new stdClass();

        $flags->bit_0 = !!($binFlag & 1);
        $flags->bit_1 = !!($binFlag & 2);
        $flags->bit_2 = !!($binFlag & 4);
        $flags->bit_3 = !!($binFlag & 8);
        $flags->bit_4 = !!($binFlag & 16);
        $flags->bit_5 = !!($binFlag & 32);
        $flags->bit_6 = !!($binFlag & 64);
        $flags->bit_7 = !!($binFlag & 128);

        $flags->userPresent = $flags->bit_0;
        $flags->userVerified = $flags->bit_2;
        $flags->attestedDataIncluded = $flags->bit_6;
        $flags->extensionDataIncluded = $flags->bit_7;

        return $flags;
    }

    /**
     * Читаем подтвержденные данные
     *
     * @param string $binary
     * @param int $endOffset
     *
     * @return stdClass
     * @throws Exception
     */
    private function _readAttestData(string $binary, int &$endOffset): stdClass
    {
        $attestedCData = new stdClass();
        if (strlen($binary) <= 55) {
            throw new Exception('Аттестованные данные должны присутствовать, но отсутствуют', Exception::INVALID_DATA);
        }

        // AAGUID аутентификатора
        $attestedCData->aaguid = substr($binary, 37, 16);

        // Длина идентификатора учетных данных L в байтах, 16-разрядное целое число без знака с обратным порядком байтов.
        $length = unpack('nlength', substr($binary, 53, 2))['length'];
        $attestedCData->credentialId = substr($binary, 55, $length);

        // Установить конечное смещение
        $endOffset = 55 + $length;

        // Извлечь открытый ключ
        $attestedCData->credentialPublicKey = $this->_readCredentialPublicKey($binary, 55 + $length, $endOffset);

        return $attestedCData;
    }

    /**
     * Читаем открытый ключ эллиптической кривой с кодировкой COSE в формате EC2
     *
     * @param string $binary
     * @param $offset
     * @param int $endOffset
     *
     * @return stdClass
     * @throws Exception
     */
    private function _readCredentialPublicKey(string $binary, $offset, int &$endOffset): stdClass
    {
        $enc = CborDecoder::decodeInPlace($binary, $offset, $endOffset);

        // Открытый ключ эллиптической кривой с кодировкой COSE в формате EC2
        $credPKey = new stdClass();
        $credPKey->kty = $enc[self::$_COSE_KTY];
        $credPKey->alg = $enc[self::$_COSE_ALG];

        switch ($credPKey->alg) {
            case self::$_EC2_ES256:
                $this->_readCredentialPublicKeyES256($credPKey, $enc);
                break;
            case self::$_RSA_RS256:
                $this->_readCredentialPublicKeyRS256($credPKey, $enc);
                break;
        }

        return $credPKey;
    }

    /**
     * Извлечь информацию ES256 из COSE
     *
     * @param stdClass $credPKey
     * @param array $enc
     *
     * @throws Exception
     */
    private function _readCredentialPublicKeyES256(stdClass &$credPKey, array $enc): void
    {
        $credPKey->crv = $enc[self::$_COSE_CRV];
        $credPKey->x = $enc[self::$_COSE_X] instanceof ByteBuffer ? $enc[self::$_COSE_X]->getBinaryString() : null;
        $credPKey->y = $enc[self::$_COSE_Y] instanceof ByteBuffer ? $enc[self::$_COSE_Y]->getBinaryString() : null;
        unset($enc);

        if ($credPKey->kty !== self::$_EC2_TYPE) {
            throw new Exception('Открытый ключ не в формате EC2', Exception::INVALID_PUBLIC_KEY);
        }

        if ($credPKey->alg !== self::$_EC2_ES256) {
            throw new Exception('Алгоритм подписи не ES256', Exception::INVALID_PUBLIC_KEY);
        }

        if ($credPKey->crv !== self::$_EC2_P256) {
            throw new Exception('Кривая не Р-256', Exception::INVALID_PUBLIC_KEY);
        }

        if (strlen($credPKey->x) !== 32) {
            throw new Exception('Неверная координата X', Exception::INVALID_PUBLIC_KEY);
        }

        if (strlen($credPKey->y) !== 32) {
            throw new Exception('Неверная координата Y', Exception::INVALID_PUBLIC_KEY);
        }
    }

    /**
     * Извлечь информацию RS256 из COSE
     *
     * @param stdClass $credPKey
     * @param array $enc
     *
     * @throws Exception
     */
    private function _readCredentialPublicKeyRS256(stdClass &$credPKey, array $enc): void
    {
        $credPKey->n = $enc[self::$_COSE_N] instanceof ByteBuffer ? $enc[self::$_COSE_N]->getBinaryString() : null;
        $credPKey->e = $enc[self::$_COSE_E] instanceof ByteBuffer ? $enc[self::$_COSE_E]->getBinaryString() : null;
        unset($enc);

        if ($credPKey->kty !== self::$_RSA_TYPE) {
            throw new Exception('Открытый ключ не в формате RSA', Exception::INVALID_PUBLIC_KEY);
        }

        if ($credPKey->alg !== self::$_RSA_RS256) {
            throw new Exception('Алгоритм подписи не ES256', Exception::INVALID_PUBLIC_KEY);
        }

        if (strlen($credPKey->n) !== 256) {
            throw new Exception('Недопустимый модуль RSA', Exception::INVALID_PUBLIC_KEY);
        }

        if (strlen($credPKey->e) !== 3) {
            throw new Exception('Недопустимый общедоступный показатель RSA', Exception::INVALID_PUBLIC_KEY);
        }
    }

    /**
     * Считывает данные расширения, закодированные CBOR
     *
     * @param string $binary
     *
     * @return void
     * @throws Exception
     */
    private function _readExtensionData(string $binary): void
    {
        $ext = CborDecoder::decode($binary);
        if (!is_array($ext)) {
            throw new Exception('Неверные данные расширения', Exception::INVALID_DATA);
        }

    }


    // ---------------
    // DER
    // ---------------

    /**
     * @param $len
     * @return string
     */
    private function _der_length($len): string
    {
        if ($len < 128) {
            return chr($len);
        }
        $lenBytes = '';
        while ($len > 0) {
            $lenBytes = chr($len % 256) . $lenBytes;
            $len = intdiv($len, 256);
        }
        return chr(0x80 | strlen($lenBytes)) . $lenBytes;
    }

    /**
     * @param $contents
     * @return string
     */
    private function _der_sequence($contents): string
    {
        return "\x30" . $this->_der_length(strlen($contents)) . $contents;
    }

    /**
     * @param $encoded
     * @return string
     */
    private function _der_oid($encoded): string
    {
        return "\x06" . $this->_der_length(strlen($encoded)) . $encoded;
    }

    /**
     * @param $bytes
     * @return string
     */
    private function _der_bitString($bytes): string
    {
        return "\x03" . $this->_der_length(strlen($bytes) + 1) . "\x00" . $bytes;
    }

    /**
     * @return string
     */
    private function _der_nullValue(): string
    {
        return "\x05\x00";
    }

    /**
     * @param $bytes
     * @return string
     */
    private function _der_unsignedInteger($bytes): string
    {
        $len = strlen($bytes);

        // Удалить начальные нулевые байты
        for ($i = 0; $i < ($len - 1); $i++) {
            if (ord($bytes[$i]) !== 0) {
                break;
            }
        }
        if ($i !== 0) {
            $bytes = substr($bytes, $i);
        }

        // Если установлен старший значащий бит, добавьте к префиксу еще один ноль, 
        // чтобы он не воспринимался как отрицательное число.
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }

        return "\x02" . $this->_der_length(strlen($bytes)) . $bytes;
    }
}
