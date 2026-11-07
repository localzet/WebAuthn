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

namespace localzet\WebAuthn;

use localzet\WebAuthn\Binary\ByteBuffer;
use function chunk_split;
use function count;
use function explode;
use function file_put_contents;
use function in_array;
use function is_array;
use function is_dir;
use function is_file;
use function is_object;
use function is_string;
use function mb_strlen;
use function pathinfo;
use function preg_replace;
use function property_exists;
use function realpath;
use function rtrim;
use function scandir;
use function str_repeat;
use function str_replace;
use function strtolower;
use function trim;
use function unlink;

trait Certs
{
    /**
     * @param string $path Файл или директория с сертификатами
     * @param array|null $certFileExtensions Если $path - директория, стоит задать список расширений ключей
     */
    public function addRootCertificates(string $path, array $certFileExtensions = null): void
    {
        if (!is_array($this->_caFiles)) {
            $this->_caFiles = array();
        }
        if ($certFileExtensions === null) {
            // Расширения ключей по умолчанию :)
            $certFileExtensions = array('pem', 'crt', 'cer', 'der');
        }
        $path = rtrim(trim($path), '\\/');
        if (is_dir($path)) {
            foreach (scandir($path) as $ca) {
                if (is_file($path . DIRECTORY_SEPARATOR . $ca) && in_array(strtolower(pathinfo($ca, PATHINFO_EXTENSION)), $certFileExtensions)) {
                    $this->addRootCertificates($path . DIRECTORY_SEPARATOR . $ca);
                }
            }
        } else if (is_file($path) && !in_array(realpath($path), $this->_caFiles)) {
            $this->_caFiles[] = realpath($path);
        }
    }

    /**
     * Downloads root certificates from FIDO Alliance Metadata Service (MDS) to a specific folder
     * https://fidoalliance.org/metadata/
     * @param string $certFolder Folder path to save the certificates in PEM format.
     * @param bool $deleteCerts delete certificates in the target folder before adding the new ones.
     * @return int number of certificates
     * @throws Exception
     */
    public function queryFidoMetaDataService(string $certFolder, bool $deleteCerts = true): int
    {
        // FIDO MDS is a signed JWT. TLS alone does not establish trust in its
        // attestation roots. Never import unverified payload data into the CA store.
        throw new Exception(
            'MDS imports are disabled until JWT signatures and trust anchors are verified.'
        );

    }
}
