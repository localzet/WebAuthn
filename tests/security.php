<?php declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use localzet\WebAuthn;
use localzet\WebAuthn\Exception;

function expect(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$auth = new WebAuthn('Example', 'example.com');
$checkOrigin = new ReflectionMethod(WebAuthn::class, '_checkOrigin');
expect($checkOrigin->invoke($auth, 'https://example.com'), 'Exact RP ID rejected');
expect($checkOrigin->invoke($auth, 'https://login.example.com'), 'Allowed subdomain rejected');
expect(!$checkOrigin->invoke($auth, 'https://evil-example.com'), 'RP ID suffix accepted without dot boundary');
expect(!$checkOrigin->invoke($auth, 'http://example.com'), 'Insecure RP origin accepted');
expect(!$checkOrigin->invoke($auth, 'https://example.com.attacker.test'), 'Attacker suffix accepted');

$auth->createAuth('user-id', 'user@example.com', 'Test User');
$first = $auth->getChallenge()->getBinaryString();
$auth->createAuth('user-id', 'user@example.com', 'Test User');
$second = $auth->getChallenge()->getBinaryString();
expect(strlen($first) >= 32 && $first !== $second, 'Registration challenge was reused');

try {
    $auth->queryFidoMetaDataService(__DIR__);
    throw new RuntimeException('Unsigned FIDO MDS data import must fail closed');
} catch (Exception $e) {
    expect(str_contains($e->getMessage(), 'MDS'), 'Unexpected MDS failure');
}

echo "WebAuthn trust boundary regressions: OK\n";
