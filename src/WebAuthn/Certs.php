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
        $certFolder = rtrim(realpath($certFolder), '\\/');
        if (!is_dir($certFolder)) {
            throw new Exception('Недопустимый путь к папке для запроса службы метаданных FIDO Alliance.');
        }

        $curl = curl_init();
        curl_setopt($curl, CURLOPT_TIMEOUT, 30);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 30);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($curl, CURLOPT_MAXREDIRS, 5);
        curl_setopt($curl, CURLINFO_HEADER_OUT, true);
        curl_setopt($curl, CURLOPT_ENCODING, 'identity');
        curl_setopt($curl, CURLOPT_USERAGENT, 'Localzet FIDO CA');
        curl_setopt($curl, CURLOPT_URL, 'https://mds.fidoalliance.org');
        curl_setopt($curl, CURLOPT_HTTPHEADER, [
            'Accept: */*',
            'Content-Type: application/json',
            'Cache-Control: max-age=0',
            'Connection: keep-alive',
            'Expect: ',
            'Pragma: ',
        ]);
        $raw = curl_exec($curl);

        if (!is_string($raw)) {
            throw new Exception('Не удалось запросить службу метаданных FIDO Alliance.');
        }

        $jwt = explode('.', $raw);
        if (count($jwt) !== 3) {
            throw new Exception('Недействительный JWT из службы метаданных FIDO Alliance');
        }

        if ($deleteCerts) {
            foreach (scandir($certFolder) as $ca) {
                if (str_ends_with($ca, '.pem')) {
                    if (unlink($certFolder . DIRECTORY_SEPARATOR . $ca) === false) {
                        throw new Exception('Не удается удалить сертификаты в папке для службы метаданных FIDO Alliance');
                    }
                }
            }
        }

        list($header, $payload, $hash) = $jwt;
        $payload = ByteBuffer::fromBase64Url($payload)->getJson();

        $count = 0;
        if (is_object($payload) && property_exists($payload, 'entries') && is_array($payload->entries)) {
            foreach ($payload->entries as $entry) {
                if (is_object($entry) && property_exists($entry, 'metadataStatement') && is_object($entry->metadataStatement)) {
                    $description = $entry->metadataStatement->description ?? null;
                    $attestationRootCertificates = $entry->metadataStatement->attestationRootCertificates ?? null;

                    if ($description && $attestationRootCertificates) {

                        // Название файла
                        $certFilename = preg_replace('/[^a-z0-9]/i', '_', $description);
                        $certFilename = trim(preg_replace('/\_{2,}/i', '_', $certFilename), '_') . '.pem';
                        $certFilename = strtolower($certFilename);

                        // Контент
                        $certContent = $description . "\n";
                        $certContent .= str_repeat('-', mb_strlen($description)) . "\n";

                        foreach ($attestationRootCertificates as $attestationRootCertificate) {
                            $attestationRootCertificate = str_replace(["\n", "\r", ' '], '', trim($attestationRootCertificate));
                            $count++;
                            $certContent .= "\n-----BEGIN CERTIFICATE-----\n";
                            $certContent .= chunk_split($attestationRootCertificate, 64, "\n");
                            $certContent .= "-----END CERTIFICATE-----\n";
                        }

                        if (file_put_contents($certFolder . DIRECTORY_SEPARATOR . $certFilename, $certContent) === false) {
                            throw new Exception('Не удалось сохранить сертификат из службы метаданных FIDO Alliance');
                        }
                    }
                }
            }
        }

        return $count;
    }
}
