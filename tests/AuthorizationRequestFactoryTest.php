<?php

declare(strict_types=1);

namespace Novvor\IdentitySdk\Tests;

use Novvor\IdentitySdk\Oidc\AuthorizationRequestFactory;
use Novvor\IdentitySdk\Oidc\OidcClientConfiguration;
use Novvor\IdentitySdk\Oidc\OidcException;
use PHPUnit\Framework\TestCase;

final class AuthorizationRequestFactoryTest extends TestCase
{
    public function test_creates_pkce_request_and_validates_state(): void
    {
        $factory = new AuthorizationRequestFactory();
        $request = $factory->create($this->configuration(), 'urn:novvor:acr:mfa', 300);
        parse_str((string) parse_url($request['url'], PHP_URL_QUERY), $query);

        self::assertSame('S256', $query['code_challenge_method']);
        self::assertSame($request['state'], $query['state']);
        self::assertNotSame($request['nonce'], $request['state']);
        self::assertSame(43, strlen($request['code_verifier']));
        $factory->assertState($request['state'], $request['state']);
    }

    public function test_rejects_mismatched_state(): void
    {
        $this->expectException(OidcException::class);
        (new AuthorizationRequestFactory())->assertState('expected', 'attacker');
    }

    private function configuration(): OidcClientConfiguration
    {
        return new OidcClientConfiguration(
            'https://identity.example.com', 'client', 'https://app.example.com/callback',
            'https://identity.example.com/authorize', 'https://identity.example.com/token',
            'https://identity.example.com/jwks',
        );
    }
}
