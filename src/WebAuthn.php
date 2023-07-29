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

namespace localzet;

use JetBrains\PhpStorm\ArrayShape;
use localzet\WebAuthn\Attestation\{AttestationObject, AuthenticatorData};
use localzet\WebAuthn\Binary\ByteBuffer;
use localzet\WebAuthn\Certs;
use localzet\WebAuthn\Exception;
use stdClass;
use function array_diff;
use function array_map;
use function function_exists;
use function hash;
use function is_object;
use function json_decode;
use function openssl_get_md_methods;
use function openssl_pkey_get_public;
use function openssl_verify;
use function parse_url;
use function preg_match;
use function preg_quote;
use function property_exists;
use function trim;

/**
 *
 */
class WebAuthn
{
    use Certs;

    /**
     * @var string
     */
    private string $_rpName;
    /**
     * @var string
     */
    private string $_rpId;
    /**
     * @var string
     */
    private string $_rpIdHash;

    /**
     * @var ByteBuffer
     */
    private ByteBuffer $_challenge;
    /**
     * @var int|null
     */
    private ?int $_signatureCounter = null;
    /**
     * @var
     */
    private $_caFiles;
    /**
     * @var array|string[]|null
     */
    private ?array $_formats;

    /**
     * @param string $name
     * @param string $domain
     * @param array $allowedFormats Список принимаемых форматов
     * @param bool $useBase64UrlEncoding Значение true, чтобы использовать кодировку URL-адресов base64 для двоичных данных в объектах json.
     *                                      По умолчанию используется сериализованная строка в стиле RFC 1342.
     * @throws Exception
     */
    public function __construct(
        string $name,
        string $domain,
        array  $allowedFormats = [],
        bool   $useBase64UrlEncoding = false
    )
    {
        $this->_rpName = $name;
        $this->_rpId = $domain;
        $this->_rpIdHash = hash('sha256', $this->_rpId, true);

        $this->queryFidoMetaDataService(__DIR__ . '/WebAuthn/Certificates/');
        $this->addRootCertificates(__DIR__ . '/WebAuthn/Certificates/');

        ByteBuffer::$useBase64UrlEncoding = $useBase64UrlEncoding;
        $supportedFormats = array('android-key', 'android-safetynet', 'apple', 'fido-u2f', 'none', 'packed', 'tpm');

        // Проверки OpenSSL и SHA256
        if (!function_exists('\openssl_open')) {
            throw new Exception('Модуль OpenSSL не установлен');;
        }

        if (!in_array('SHA256', array_map('\strtoupper', openssl_get_md_methods()))) {
            throw new Exception('SHA256 не поддерживается установленным OpenSSL.');
        }

        // По умолчанию: принимать все поддерживаемые форматы
        if (!is_array($allowedFormats)) {
            $allowedFormats = $allowedFormats ?? $supportedFormats;
        }
        $this->_formats = $allowedFormats;

        // Сверяем форматы
        $invalidFormats = array_diff($this->_formats, $supportedFormats);
        if (!$this->_formats || $invalidFormats) {
            throw new Exception('Неподдерживаемые форматы: ' . implode(', ', $invalidFormats));
        }
    }

    /**
     * Генерация объекта регистрации
     * navigator.credentials.create
     *
     * @param mixed $userId
     * @param string $userName
     * @param string $userDisplayName
     * @param array $excludeCredentialIds
     * @param int $timeout
     * @param bool|string $requireResidentKey Должен ли ключ храниться устройством аутентификации?
     *                                          Допустимые значения: true (required), false (preferred), 'required' 'preferred' 'discouraged'
     *
     * @param bool|string $requireVerification Требовать проверки пользователя и завершиться ошибкой, если в ответе не установлен флаг UV?
     *                                          Допустимые значения: true (required), false (preferred), 'required' 'preferred' 'discouraged'
     *
     * @param bool|null $crossPlatformAttachment true - кроссплатформенная аутентификация (FIDO-USB),
     *                                              false - системная аутентификация (Windows Hello, Android Safetynet),
     *                                              null - оба :)
     *
     * @return stdClass
     * @throws Exception
     */
    public function createAuth(
        mixed       $userId,
        string      $userName,
        string      $userDisplayName,
        array       $excludeCredentialIds = [],
        int         $timeout = 60,
        bool|string $requireResidentKey = false,
        bool|string $requireVerification = true,
        bool        $crossPlatformAttachment = null
    ): stdClass
    {
        $args = new stdClass();
        $args->publicKey = new stdClass();

        // Доверительная сторона
        $args->publicKey->rp = new stdClass();
        $args->publicKey->rp->name = $this->_rpName;
        $args->publicKey->rp->id = $this->_rpId;

        // Форматы
        $args->publicKey->attestationFormats = $this->_formats;

        // Аутентификация
        $args->publicKey->authenticatorSelection = new stdClass();
        $args->publicKey->authenticatorSelection->userVerification = 'preferred';

        // Требовать проверки пользователя?
        if (is_bool($requireVerification)) {
            $args->publicKey->authenticatorSelection->userVerification = $requireVerification ? 'required' : 'preferred';
        } else if (is_string($requireVerification) && in_array(strtolower($requireVerification), ['required', 'preferred', 'discouraged'])) {
            $args->publicKey->authenticatorSelection->userVerification = strtolower($requireVerification);
        }

        // Должен ли ключ храниться устройством аутентификации?
        if (is_bool($requireResidentKey) && $requireResidentKey) {
            $args->publicKey->authenticatorSelection->requireResidentKey = true;
            $args->publicKey->authenticatorSelection->residentKey = 'required';
        } else if (is_string($requireResidentKey) && in_array(strtolower($requireResidentKey), ['required', 'preferred', 'discouraged'])) {
            $requireResidentKey = strtolower($requireResidentKey);
            $args->publicKey->authenticatorSelection->residentKey = $requireResidentKey;
            $args->publicKey->authenticatorSelection->requireResidentKey = $requireResidentKey === 'required';
        }

        // Тип аутентификации
        if (is_bool($crossPlatformAttachment)) {
            $args->publicKey->authenticatorSelection->authenticatorAttachment = $crossPlatformAttachment ? 'cross-platform' : 'platform';
        }

        // Пользователь
        $args->publicKey->user = new stdClass();
        $args->publicKey->user->id = new ByteBuffer($userId); // Бинарник, мать его
        $args->publicKey->user->name = $userName;
        $args->publicKey->user->displayName = $userDisplayName;

        // Алгоритмы
        $args->publicKey->pubKeyCredParams = array();
        $tmp = new stdClass();
        $tmp->type = 'public-key';
        $tmp->alg = -7; // ES256
        $args->publicKey->pubKeyCredParams[] = $tmp;
        unset($tmp);

        $tmp = new stdClass();
        $tmp->type = 'public-key';
        $tmp->alg = -257; // RS256
        $args->publicKey->pubKeyCredParams[] = $tmp;
        unset($tmp);

        // Если добавлены сертификаты, нам нужна аттестация для проверки сертификата.
        // Если нет добавленных сертификатов, примем анонимно, 
        // Ибо мы все равно не сможем ничего проверить ¯\_(ツ)_/¯
        $attestation = 'indirect';
        if (count($this->_formats) === 1 && in_array('none', $this->_formats)) {
            $attestation = 'none';
        } else {
            if (is_array($this->_caFiles)) {
                $attestation = 'direct';
            }
        }

        $args->publicKey->attestation = $attestation;

        $args->publicKey->extensions = new stdClass();
        $args->publicKey->extensions->exts = true;

        $args->publicKey->timeout = $timeout * 1000; // Микросекунды

        $args->publicKey->challenge = $this->_createChallenge(); // binary

        // Предотвратить повторную регистрацию, указав существующие учетные данные
        $args->publicKey->excludeCredentials = array();

        if ($excludeCredentialIds) {
            foreach ($excludeCredentialIds as $id) {
                $id = base64_decode($id);
                $tmp = new stdClass();
                $tmp->id = $id instanceof ByteBuffer ? $id : new ByteBuffer($id);  // binary
                $tmp->type = 'public-key';
                $tmp->transports = array(
                    'hybrid',
                    'internal',
                    'ble', // Bluetooth Low Energy
                    'nfc', // Near Field Communication
//                     'usb'
                );
                $args->publicKey->excludeCredentials[] = $tmp;
                unset($tmp);
            }
        }

        return $args;
    }

    /**
     * Генерация объекта валидации
     * navigator.credentials.get
     *
     * @param array $allowCredentials
     * @param int $timeout Время ожидания в секундах
     * @param bool|string $requireVerification Требовать проверки пользователя и завершиться ошибкой, если в ответе не установлен флаг UV?
     *                                          Допустимые значения: true (required), false (preferred), 'required' 'preferred' 'discouraged'
     * @return stdClass
     * @throws Exception
     */
    public function verifyAuth(
        array       $allowCredentials,
        int         $timeout = 60,
        bool|string $requireVerification = true
    ): stdClass
    {
        if (count($allowCredentials) === 0) {
            throw new Exception('Встроенная идентификация отключена в этом аккаунте');
        }

        // Требовать проверки пользователя?
        if (is_bool($requireVerification)) {
            $requireVerification = $requireVerification ? 'required' : 'preferred';
        } else if (is_string($requireVerification) && in_array(strtolower($requireVerification), ['required', 'preferred', 'discouraged'])) {
            $requireVerification = strtolower($requireVerification);
        } else {
            $requireVerification = 'preferred';
        }

        $args = new stdClass();
        $args->publicKey = new stdClass();
        $args->publicKey->timeout = $timeout * 1000; // Микросекунды
        $args->publicKey->challenge = $this->_createChallenge();  // binary
        $args->publicKey->userVerification = $requireVerification;
        $args->publicKey->rpId = $this->_rpId;

        if (count($allowCredentials) > 0) {
            $args->publicKey->allowCredentials = array();

            foreach ($allowCredentials as $id) {
                $id = base64_decode($id);
                $tmp = new stdClass();
                $tmp->id = $id instanceof ByteBuffer ? $id : new ByteBuffer($id);  // binary
                $tmp->transports = array(
                    'hybrid',
                    'internal',
                    'ble', // Bluetooth Low Energy
                    'nfc', // Near Field Communication
//                    'usb'
                );

                $tmp->type = 'public-key';
                $args->publicKey->allowCredentials[] = $tmp;
                unset($tmp);
            }
        }

        return $args;
    }

    /**
     * Регистрация
     *
     * @param string $clientDataJSON
     * @param string $attestationObject
     * @param string|ByteBuffer $challenge
     *
     * @param bool $requireVerification Устройство должно верифицировать пользователя? (например, по биометрическим данным или пин-коду)
     * @param bool $requireUserPresent Устройство должно проверять присутствие пользователя?
     * @param bool $failIfRootMismatch Должна возникать ошибка, если корневой сертификат не соответствует?
     * @param bool $requireCtsProfileMatch Проверять, одобрено ли устройство как Android, сертифицированный Google?
     *
     * @return array
     * @throws Exception
     */
    #[ArrayShape([
        'rpId' => 'string',
        'attestationFormat' => 'string',
        'credentialId' => 'string',
        'credentialPublicKey' => 'string',
        'certificateChain' => 'string|null',
        'certificate' => 'string',
        'certificateIssuer' => 'string',
        'certificateSubject' => 'string',
        'signatureCounter' => 'int',
        'AAGUID' => 'string',
        'rootValid' => 'bool',
        'userPresent' => 'bool',
        'userVerified' => 'bool',
    ])]
    public function processCreate(
        string            $clientDataJSON,
        string            $attestationObject,
        ByteBuffer|string $challenge,
        bool              $requireVerification = true,
        bool              $requireUserPresent = true,
        bool              $failIfRootMismatch = false,
        bool              $requireCtsProfileMatch = false
    ): array
    {
        $clientDataHash = hash('sha256', $clientDataJSON, true);
        $clientData = json_decode($clientDataJSON);
        $challenge = $challenge instanceof ByteBuffer ? $challenge : new ByteBuffer($challenge);

        // https://www.w3.org/TR/webauthn/#registering-a-new-credential

        // 2. Пусть $clientData, клиентские данные, заявленные как собранные во время создания учетных данных, 
        //    будут результатом запуска синтаксического анализатора JSON для конкретной реализации JSONtext.
        if (!is_object($clientData)) {
            throw new Exception('Неверные данные клиента', Exception::INVALID_DATA);
        }

        // 3. Проверим, что значение $clientData->type = webauthn.create.
        if (!property_exists($clientData, 'type') || $clientData->type !== 'webauthn.create') {
            throw new Exception('Неверный тип', Exception::INVALID_TYPE);
        }

        // 4. Проверим, что значение $clientData->challenge соответствует challenge, который был отправлен аутентификатору в вызове create().
        if (!property_exists($clientData, 'challenge') || ByteBuffer::fromBase64Url($clientData->challenge)->getBinaryString() !== $challenge->getBinaryString()) {
            throw new Exception('Неверный challenge', Exception::INVALID_CHALLENGE);
        }

        // 5. Проверим, что значение $clientData->origin соответствует происхождению проверяющей стороны.
        if (!property_exists($clientData, 'origin') || !$this->_checkOrigin($clientData->origin)) {
            throw new Exception('Неверный источник', Exception::INVALID_ORIGIN);
        }

        // Аттестация
        $attestationObject = new AttestationObject($attestationObject, $this->_formats);

        // 9. Проверим, что хэш RP ID в authData действительно является хэшем SHA-256 RP ID, ожидаемого RP.
        if (!$attestationObject->validateRpIdHash($this->_rpIdHash)) {
            throw new Exception('Неверный хэш RP ID', Exception::INVALID_RELYING_PARTY);
        }

        // 14. Проверим, что attStmt является правильным оператором аттестации, передающим действительную подпись аттестации.
        if (!$attestationObject->validateAttestation($clientDataHash)) {
            throw new Exception('Неверная подпись сертификата', Exception::INVALID_SIGNATURE);
        }

        // Android-SafetyNet: при необходимости проверьте наличие комплекта для тестирования совместимости (CTS).
        // if ($requireCtsProfileMatch && $attestationObject->getAttestationFormat() instanceof Attestation\Format\AndroidSafetyNet) {
        //     if (!$attestationObject->getAttestationFormat()->ctsProfileMatch()) {
        //         throw new Exception('Ошибка ctsProfileMatch: устройство Android не сертифицировано Google.', Exception::ANDROID_NOT_TRUSTED);
        //     }
        // }

        // 15. Если проверка прошла успешно, получим список приемлемых якорей доверия.
        $rootValid = is_array($this->_caFiles) ? $attestationObject->validateRootCertificate($this->_caFiles) : null;
        if ($failIfRootMismatch && is_array($this->_caFiles) && !$rootValid) {
            throw new Exception('Неверный корневой сертификат', Exception::CERTIFICATE_NOT_TRUSTED);
        }

        // 10. Проверим, что флаг UserPresent установлен в authData.
        $userPresent = $attestationObject->getAuthenticatorData()->getUserPresent();
        if ($requireUserPresent && !$userPresent) {
            throw new Exception('Пользователь не присутствует во время аутентификации', Exception::USER_PRESENT);
        }

        // 11. Если для этой регистрации требуется проверка пользователя, убедитесь, что установлен флаг UserVerified в authData.
        $userVerified = $attestationObject->getAuthenticatorData()->getUserVerified();
        if ($requireVerification && !$userVerified) {
            throw new Exception('Пользователь не верифицирован при аутентификации', Exception::USER_VERIFICATED);
        }

        $signCount = $attestationObject->getAuthenticatorData()->getSignCount();
        if ($signCount > 0) {
            $this->_signatureCounter = $signCount;
        }

        return [
            'rpId' => $this->_rpId,
            'attestationFormat' => $attestationObject->getAttestationFormatName(),
            'credentialId' => base64_encode($attestationObject->getAuthenticatorData()->getCredentialId()),
            'credentialPublicKey' => $attestationObject->getAuthenticatorData()->getPublicKeyPem(),
            'certificateChain' => $attestationObject->getCertificateChain(),
            'certificate' => $attestationObject->getCertificatePem(),
            'certificateIssuer' => $attestationObject->getCertificateIssuer(),
            'certificateSubject' => $attestationObject->getCertificateSubject(),
            'signatureCounter' => $this->_signatureCounter,
            'AAGUID' => base64_encode($attestationObject->getAuthenticatorData()->getAAGUID()),
            'rootValid' => $rootValid,
            'userPresent' => $userPresent,
            'userVerified' => $userVerified,
        ];
    }


    /**
     * Авторизация
     *
     * @param string $clientDataJSON
     * @param string $authenticatorData
     * @param string $signature
     * @param string|ByteBuffer $challenge
     *
     * @param string $credentialPublicKey Открытый ключ в формате PEM из используемого credentialId
     * @param int|null $prevSignatureCnt Количество подписей последнего входа в систему
     * @param bool $requireVerification Устройство должно верифицировать пользователя? (например, по биометрическим данным или пин-коду)
     * @param bool $requireUserPresent Устройство должно проверять присутствие пользователя?
     *
     * @return boolean
     * @throws Exception
     */
    public function processGet(
        string            $clientDataJSON,
        string            $authenticatorData,
        string            $signature,
        string            $credentialPublicKey,
        ByteBuffer|string $challenge,
        int               $prevSignatureCnt = null,
        bool              $requireVerification = false,
        bool              $requireUserPresent = true
    ): bool
    {
        $clientDataHash = hash('sha256', $clientDataJSON, true);
        $clientData = json_decode($clientDataJSON);
        $challenge = $challenge instanceof ByteBuffer ? $challenge : new ByteBuffer($challenge);

        // https://www.w3.org/TR/webauthn/#verifying-assertion

        // 5. Пусть JSONtext будет результатом выполнения декодирования UTF-8 $clientData.
        if (!is_object($clientData)) {
            throw new Exception('Неверные данные клиента', Exception::INVALID_DATA);
        }

        // 7. Проверим, что значение $clientData->type = webauthn.create.
        if (!property_exists($clientData, 'type') || $clientData->type !== 'webauthn.get') {
            throw new Exception('Неверный тип', Exception::INVALID_TYPE);
        }

        // 8. Проверим, что значение $clientData->challenge соответствует challenge, который был отправлен аутентификатору в вызове get()
        if (!property_exists($clientData, 'challenge') || ByteBuffer::fromBase64Url($clientData->challenge)->getBinaryString() !== $challenge->getBinaryString()) {
            throw new Exception('Неверный challenge', Exception::INVALID_CHALLENGE);
        }

        // 9. Проверим, что значение $clientData->origin соответствует происхождению проверяющей стороны.
        if (!property_exists($clientData, 'origin') || !$this->_checkOrigin($clientData->origin)) {
            throw new Exception('Неверный источник', Exception::INVALID_ORIGIN);
        }

        // Аттестация
        $authenticatorObj = new AuthenticatorData($authenticatorData);

        // 11. Проверим, что хэш RP ID в authData действительно является хэшем SHA-256 RP ID, ожидаемого RP.
        if ($authenticatorObj->getRpIdHash() !== $this->_rpIdHash) {
            throw new Exception('Неверный хэш RP ID', Exception::INVALID_RELYING_PARTY);
        }

        // 12. Проверим, что флаг UserPresent установлен в authData.
        if ($requireUserPresent && !$authenticatorObj->getUserPresent()) {
            throw new Exception('Пользователь не присутствует во время аутентификации', Exception::USER_PRESENT);
        }

        // 13. Если для этой регистрации требуется проверка пользователя, убедитесь, что установлен флаг UserVerified в authData.
        if ($requireVerification && !$authenticatorObj->getUserVerified()) {
            throw new Exception('Пользователь не верифицирован при аутентификации', Exception::USER_VERIFICATED);
        }

        $dataToVerify = $authenticatorData;
        $dataToVerify .= $clientDataHash;

        $publicKey = openssl_pkey_get_public($credentialPublicKey);
        if ($publicKey === false) {
            throw new Exception('Открытый ключ недействителен', Exception::INVALID_PUBLIC_KEY);
        }

        if (openssl_verify($dataToVerify, $signature, $publicKey, OPENSSL_ALGO_SHA256) !== 1) {
            throw new Exception('Неверная подпись', Exception::INVALID_SIGNATURE);
        }

        $signatureCounter = $authenticatorObj->getSignCount();
        if ($signatureCounter !== 0) {
            $this->_signatureCounter = $signatureCounter;
        }

        if ($prevSignatureCnt !== null) {
            if ($signatureCounter !== 0 || $prevSignatureCnt !== 0) {
                if ($prevSignatureCnt >= $signatureCounter) {
                    throw new Exception('Счетчик подписи недействителен', Exception::SIGNATURE_COUNTER);
                }
            }
        }

        return true;
    }

    /**
     * @return ByteBuffer
     */
    public function getChallenge(): ByteBuffer
    {
        return $this->_challenge;
    }

    // -----------------------------------------------
    // PRIVATE
    // -----------------------------------------------

    /**
     * Проверка соответствия RP ID
     * @param string $origin
     * @return boolean
     */
    private function _checkOrigin(string $origin): bool
    {
        // https://www.w3.org/TR/webauthn/#rp-id

        // Схема источника должна быть https
        if ($this->_rpId !== 'localhost' && parse_url($origin, PHP_URL_SCHEME) !== 'https') {
            return false;
        }

        // Извлечь хост из источника
        $host = parse_url($origin, PHP_URL_HOST);
        $host = trim($host, '.');

        // Идентификатор RP должен совпадать с действующим доменом источника 
        // или суффиксом регистрируемого домена источника.
        return preg_match('/' . preg_quote($this->_rpId) . '$/i', $host) === 1;
    }

    /**
     * Генерируем криптографически безопасную случайную строку
     * @param int $length
     * @return ByteBuffer|string
     * @throws Exception
     */
    private function _createChallenge(int $length = 32): ByteBuffer|string
    {
        if (!isset($this->_challenge)) {
            $this->_challenge = ByteBuffer::randomBuffer($length);
        }
        return $this->_challenge;
    }
}
