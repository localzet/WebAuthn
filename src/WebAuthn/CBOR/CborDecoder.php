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

namespace localzet\WebAuthn\CBOR;

use localzet\WebAuthn\Binary\ByteBuffer;
use localzet\WebAuthn\Exception;
use function is_int;
use function is_string;

/**
 *
 */
class CborDecoder
{
    /**
     *
     */
    const CBOR_MAJOR_UNSIGNED_INT = 0;
    /**
     *
     */
    const CBOR_MAJOR_TEXT_STRING = 3;
    /**
     *
     */
    const CBOR_MAJOR_FLOAT_SIMPLE = 7;
    /**
     *
     */
    const CBOR_MAJOR_NEGATIVE_INT = 1;
    /**
     *
     */
    const CBOR_MAJOR_ARRAY = 4;
    /**
     *
     */
    const CBOR_MAJOR_TAG = 6;
    /**
     *
     */
    const CBOR_MAJOR_MAP = 5;
    /**
     *
     */
    const CBOR_MAJOR_BYTE_STRING = 2;

    // ---------------------
    // PUBLIC STATIC
    // ---------------------

    /**
     * @param string|ByteBuffer $bufOrBin
     * @return mixed
     * @throws Exception
     */
    public static function decode(ByteBuffer|string $bufOrBin): mixed
    {
        $buf = $bufOrBin instanceof ByteBuffer ? $bufOrBin : new ByteBuffer($bufOrBin);

        $offset = 0;
        $result = self::_parseItem($buf, $offset);
        if ($offset !== $buf->getLength()) {
            throw new Exception('Неиспользуемые байты после элемента данных.', Exception::CBOR);
        }
        return $result;
    }

    /**
     * @param string|ByteBuffer $bufOrBin
     * @param int $startOffset
     * @param int|null $endOffset
     * @return mixed
     * @throws Exception
     */
    public static function decodeInPlace(ByteBuffer|string $bufOrBin, int $startOffset, int &$endOffset = null): mixed
    {
        $buf = $bufOrBin instanceof ByteBuffer ? $bufOrBin : new ByteBuffer($bufOrBin);

        $offset = $startOffset;
        $data = self::_parseItem($buf, $offset);
        $endOffset = $offset;
        return $data;
    }

    // ---------------------
    // PROTECTED STATIC
    // ---------------------

    /**
     * @param ByteBuffer $buf
     * @param int $offset
     * @return mixed
     * @throws Exception
     */
    protected static function _parseItem(ByteBuffer $buf, int &$offset): mixed
    {
        $first = $buf->getByteVal($offset++);
        $type = $first >> 5;
        $val = $first & 0b11111;

        if ($type === self::CBOR_MAJOR_FLOAT_SIMPLE) {
            return self::_parseFloatSimple($val, $buf, $offset);
        }

        $val = self::_parseExtraLength($val, $buf, $offset);

        return self::_parseItemData($type, $val, $buf, $offset);
    }

    /**
     * @param $val
     * @param ByteBuffer $buf
     * @param $offset
     * @return bool|float|int|mixed|null
     * @throws Exception
     */
    protected static function _parseFloatSimple($val, ByteBuffer $buf, &$offset): mixed
    {
        switch ($val) {
            case 24:
                $val = $buf->getByteVal($offset);
                $offset++;
                return self::_parseSimple($val);

            case 25:
                $floatValue = $buf->getHalfFloatVal($offset);
                $offset += 2;
                return $floatValue;

            case 26:
                $floatValue = $buf->getFloatVal($offset);
                $offset += 4;
                return $floatValue;

            case 27:
                $floatValue = $buf->getDoubleVal($offset);
                $offset += 8;
                return $floatValue;

            case 28:
            case 29:
            case 30:
                throw new Exception('Используется зарезервированное значение.', Exception::CBOR);

            case 31:
                throw new Exception('Неопределенная длина не поддерживается.', Exception::CBOR);
        }

        return self::_parseSimple($val);
    }

    /**
     * @param int $val
     * @return bool|null
     * @throws Exception
     */
    protected static function _parseSimple(int $val): ?bool
    {
        if ($val === 20) {
            return false;
        }
        if ($val === 21) {
            return true;
        }
        if ($val === 22) {
            return null;
        }
        throw new Exception(sprintf('Неподдерживаемое значение %d.', $val), Exception::CBOR);
    }

    /**
     * @param $val
     * @param ByteBuffer $buf
     * @param $offset
     * @return int|mixed
     * @throws Exception
     */
    protected static function _parseExtraLength($val, ByteBuffer $buf, &$offset): mixed
    {
        switch ($val) {
            case 24:
                $val = $buf->getByteVal($offset);
                $offset++;
                break;

            case 25:
                $val = $buf->getUint16Val($offset);
                $offset += 2;
                break;

            case 26:
                $val = $buf->getUint32Val($offset);
                $offset += 4;
                break;

            case 27:
                $val = $buf->getUint64Val($offset);
                $offset += 8;
                break;

            case 28:
            case 29:
            case 30:
                throw new Exception('Используется зарезервированное значение.', Exception::CBOR);

            case 31:
                throw new Exception('Неопределенная длина не поддерживается.', Exception::CBOR);
        }

        return $val;
    }

    /**
     * @param $type
     * @param $val
     * @param ByteBuffer $buf
     * @param $offset
     * @return array|bool|float|int|ByteBuffer|mixed|string|null
     * @throws Exception
     */
    protected static function _parseItemData($type, $val, ByteBuffer $buf, &$offset): mixed
    {
        switch ($type) {
            case self::CBOR_MAJOR_UNSIGNED_INT: // uint
                return $val;

            case self::CBOR_MAJOR_NEGATIVE_INT:
                return -1 - $val;

            case self::CBOR_MAJOR_BYTE_STRING:
                $data = $buf->getBytes($offset, $val);
                $offset += $val;
                return new ByteBuffer($data); // байты

            case self::CBOR_MAJOR_TEXT_STRING:
                $data = $buf->getBytes($offset, $val);
                $offset += $val;
                return $data; // UTF-8

            case self::CBOR_MAJOR_ARRAY:
                return self::_parseArray($buf, $offset, $val);

            case self::CBOR_MAJOR_MAP:
                return self::_parseMap($buf, $offset, $val);

            case self::CBOR_MAJOR_TAG:
                return self::_parseItem($buf, $offset); // 1 встроенный элемент данных
        }

        // Дай бог до сюда оно не дойдёт
        throw new Exception(sprintf('Неизвестный major-тип %d.', $type), Exception::CBOR);
    }

    /**
     * @param ByteBuffer $buf
     * @param $offset
     * @param $count
     * @return array
     * @throws Exception
     */
    protected static function _parseMap(ByteBuffer $buf, &$offset, $count): array
    {
        $map = array();

        for ($i = 0; $i < $count; $i++) {
            $mapKey = self::_parseItem($buf, $offset);
            $mapVal = self::_parseItem($buf, $offset);

            if (!is_int($mapKey) && !is_string($mapKey)) {
                throw new Exception('В качестве карты ключей можно использовать только строки или целые числа', Exception::CBOR);
            }

            $map[$mapKey] = $mapVal; // Дублировать...
        }
        return $map;
    }

    /**
     * @param ByteBuffer $buf
     * @param $offset
     * @param $count
     * @return array
     * @throws Exception
     */
    protected static function _parseArray(ByteBuffer $buf, &$offset, $count): array
    {
        $arr = array();
        for ($i = 0; $i < $count; $i++) {
            $arr[] = self::_parseItem($buf, $offset);
        }

        return $arr;
    }
}
