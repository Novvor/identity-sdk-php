<?php

namespace Novvor\IdentitySdk\Tests;

use Novvor\IdentitySdk\Oidc\DpopKey;
use PHPUnit\Framework\TestCase;

final class DpopKeyTest extends TestCase
{
    public function test_generates_a_fresh_es256_key_without_private_jwk_material(): void
    {
        $first = DpopKey::generateEs256();
        $second = DpopKey::generateEs256();

        self::assertSame('ES256', $first->algorithm);
        self::assertSame('EC', $first->publicJwk['kty']);
        self::assertSame('P-256', $first->publicJwk['crv']);
        self::assertArrayNotHasKey('d', $first->publicJwk);
        self::assertNotSame($first->privateKey, $second->privateKey);
        self::assertNotSame($first->publicThumbprint(), $second->publicThumbprint());
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $first->publicThumbprint());
    }
}
