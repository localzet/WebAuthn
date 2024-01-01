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

namespace localzet\WebAuthn\Binary;

use JsonSerializable;
use localzet\WebAuthn\Exception;
use Serializable;
use function base64_decode;
use function base64_encode;
use function bin2hex;
use function function_exists;
use function hex2bin;
use function json_decode;
use function json_last_error;
use function json_last_error_msg;
use function openssl_random_pseudo_bytes;
use function ord;
use function random_bytes;
use function rtrim;
use function serialize;
use function str_repeat;
use function strlen;
use function strtr;
use function substr;
use function unserialize;

/**
 * Класс для работы с двоичными данными
 */
class ByteBuffer implements JsonSerializable, Serializable
{
    /**
     * @var bool
     */
    public static bool $useBase64UrlEncoding = false;

    /**
     * @var string
     */
    private string $_data;

    /**
     * @var int
     */
    private int $_length;

    /**
     * @param $binaryData
     */
    public function __construct($binaryData)
    {
        $this->_data = (string)$binaryData;
        $this->_length = strlen($binaryData);
    }


    // -----------------------
    // PUBLIC STATIC
    // -----------------------

    /**
     * @param string $base64url
     * @return ByteBuffer
     * @throws Exception
     */
    public static function fromBase64Url(string $base64url): ByteBuffer
    {
        $bin = self::_base64url_decode($base64url);
        if ($bin === false) {
            throw new Exception('ByteBuffer: Недопустимая строка base64url', Exception::BYTEBUFFER);
        }
        return new ByteBuffer($bin);
    }

    /**
     * @param string $hex
     * @return ByteBuffer
     * @throws Exception
     */
    public static function fromHex(string $hex): ByteBuffer
    {
        $bin = hex2bin($hex);
        if ($bin === false) {
            throw new Exception('ByteBuffer: Недопустимая шестнадцатеричная строка', Exception::BYTEBUFFER);
        }
        return new ByteBuffer($bin);
    }

    /**
     * Криптографически безопасные случайные байты
     * @param string $length
     * @return ByteBuffer
     * @throws Exception
     * @throws \Exception
     */
    public static function randomBuffer(string $length): ByteBuffer
    {
        if (function_exists('random_bytes')) {
            // >PHP 7.0
            return new ByteBuffer(random_bytes($length));
        } else if (function_exists('openssl_random_pseudo_bytes')) {
            return new ByteBuffer(openssl_random_pseudo_bytes($length));
        } else {
            throw new Exception('ByteBuffer: нечем сгенерировать криптографически безопасные случайные байты', Exception::BYTEBUFFER);
        }
    }

    // -----------------------
    // PUBLIC
    // -----------------------

    /**
     * @param $offset
     * @param $length
     * @return string
     * @throws Exception
     */
    public function getBytes($offset, $length): string
    {
        if ($offset < 0 || $length < 0 || ($offset + $length > $this->_length)) {
            throw new Exception('ByteBuffer: Недопустимое смещение или длина', Exception::BYTEBUFFER);
        }
        return substr($this->_data, $offset, $length);
    }

    /**
     * @param $offset
     * @return int
     * @throws Exception
     */
    public function getByteVal($offset): int
    {
        if ($offset < 0 || $offset >= $this->_length) {
            throw new Exception('ByteBuffer: Недопустимое смещение', Exception::BYTEBUFFER);
        }
        return ord(substr($this->_data, $offset, 1));
    }

    /**
     * @throws Exception
     */
    public function getJson($jsonFlags = 0)
    {
        $data = json_decode($this->getBinaryString(), null, 512, $jsonFlags);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception(json_last_error_msg(), Exception::BYTEBUFFER);
        }
        return $data;
    }

    /**
     * @return int
     */
    public function getLength(): int
    {
        return $this->_length;
    }

    /**
     * @throws Exception
     */
    public function getUint16Val($offset)
    {
        if ($offset < 0 || ($offset + 2) > $this->_length) {
            throw new Exception('ByteBuffer: Недопустимое смещение', Exception::BYTEBUFFER);
        }
        return unpack('n', $this->_data, $offset)[1];
    }

    /**
     * @throws Exception
     */
    public function getUint32Val($offset)
    {
        if ($offset < 0 || ($offset + 4) > $this->_length) {
            throw new Exception('ByteBuffer: Недопустимое смещение', Exception::BYTEBUFFER);
        }
        $val = unpack('N', $this->_data, $offset)[1];

        // Переполнение целого числа вызывает отрицательные числа
        if ($val < 0) {
            throw new Exception('ByteBuffer: Значение вне целочисленного диапазона.', Exception::BYTEBUFFER);
        }
        return $val;
    }

    /**
     * @throws Exception
     */
    public function getUint64Val($offset)
    {
        if (PHP_INT_SIZE < 8) {
            throw new Exception('ByteBuffer: 64-битные значения не поддерживаются этой системой', Exception::BYTEBUFFER);
        }
        if ($offset < 0 || ($offset + 8) > $this->_length) {
            throw new Exception('ByteBuffer: Недопустимое смещение', Exception::BYTEBUFFER);
        }
        $val = unpack('J', $this->_data, $offset)[1];

        // Переполнение целого числа вызывает отрицательные числа
        if ($val < 0) {
            throw new Exception('ByteBuffer: Значение вне целочисленного диапазона.', Exception::BYTEBUFFER);
        }

        return $val;
    }

    /**
     * @throws Exception
     */
    public function getHalfFloatVal($offset): float|int
    {
        $half = $this->getUint16Val($offset);

        $exp = ($half >> 10) & 0x1f;
        $mant = $half & 0x3ff;

        if ($exp === 0) {
            $val = $mant * (2 ** -24);
        } elseif ($exp !== 31) {
            $val = ($mant + 1024) * (2 ** ($exp - 25));
        } else {
            $val = ($mant === 0) ? INF : NAN;
        }

        return ($half & 0x8000) ? -$val : $val;
    }

    /**
     * @throws Exception
     */
    public function getFloatVal($offset)
    {
        if ($offset < 0 || ($offset + 4) > $this->_length) {
            throw new Exception('ByteBuffer: Недопустимое смещение', Exception::BYTEBUFFER);
        }
        return unpack('G', $this->_data, $offset)[1];
    }

    /**
     * @throws Exception
     */
    public function getDoubleVal($offset)
    {
        if ($offset < 0 || ($offset + 8) > $this->_length) {
            throw new Exception('ByteBuffer: Недопустимое смещение', Exception::BYTEBUFFER);
        }
        return unpack('E', $this->_data, $offset)[1];
    }

    /**
     * @return string
     */
    public function getBinaryString(): string
    {
        return $this->_data;
    }

    /**
     * @param string|ByteBuffer $buffer
     * @return bool
     */
    public function equals(ByteBuffer|string $buffer): bool
    {
        if ($buffer instanceof ByteBuffer) {
            return $buffer->getBinaryString() === $this->getBinaryString();
        } else return $buffer === $this->getBinaryString();
    }

    /**
     * @return string
     */
    public function getHex(): string
    {
        return bin2hex($this->_data);
    }

    /**
     * @return bool
     */
    public function isEmpty(): bool
    {
        return $this->_length === 0;
    }


    /**
     * @return string Двоичные данные в сериализованной строке в стиле RFC 1342
     */
    public function jsonSerialize(): string
    {
        if (ByteBuffer::$useBase64UrlEncoding) {
            return self::_base64url_encode($this->_data);
        } else {
            return '=?BINARY?B?' . base64_encode($this->_data) . '?=';
        }
    }

    /**
     * @return string
     */
    public function serialize(): string
    {
        return serialize($this->_data);
    }

    /**
     * @param string $serialized
     */
    public function unserialize(string $serialized): void
    {
        $this->_data = unserialize($serialized);
        $this->_length = strlen($this->_data);
    }

    /**
     * @return array
     */
    public function __serialize(): array
    {
        return [
            'data' => serialize($this->_data)
        ];
    }

    /**
     * @return string
     */
    public function __toString(): string
    {
        return $this->getHex();
    }

    /**
     * @param array $data
     * @return void
     */
    public function __unserialize(array $data)
    {
        if ($data && isset($data['data'])) {
            $this->_data = unserialize($data['data']);
            $this->_length = strlen($this->_data);
        }
    }

    // -----------------------
    // PROTECTED STATIC
    // -----------------------

    /**
     * @param string $data
     * @return string
     */
    protected static function _base64url_decode(string $data): string
    {
        return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', 3 - (3 + strlen($data)) % 4));
    }

    /**
     * @param string $data
     * @return string
     */
    protected static function _base64url_encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
