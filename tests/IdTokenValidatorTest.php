<?php

declare(strict_types=1);

namespace Novvor\IdentitySdk\Tests;

use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Novvor\IdentitySdk\Oidc\BackChannelLogoutValidator;
use Novvor\IdentitySdk\Oidc\IdTokenValidator;
use Novvor\IdentitySdk\Oidc\OidcClientConfiguration;
use Novvor\IdentitySdk\Oidc\OidcException;
use PHPUnit\Framework\TestCase;

final class IdTokenValidatorTest extends TestCase
{
    private string $privateKey;
    /** @var array<string, string> */
    private array $jwk;

    protected function setUp(): void
    {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($resource);
        $privateKey = '';
        self::assertTrue(openssl_pkey_export($resource, $privateKey));
        $this->privateKey = $privateKey;
        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);
        $this->jwk = [
            'kty' => 'RSA', 'kid' => 'test-key', 'use' => 'sig', 'alg' => 'RS256',
            'n' => $this->base64Url($details['rsa']['n']),
            'e' => $this->base64Url($details['rsa']['e']),
        ];
    }

    public function test_validates_signature_issuer_audience_nonce_and_time(): void
    {
        $claims = $this->baseClaims() + ['sub' => 'user-1', 'nonce' => 'nonce-1', 'exp' => time() + 300];
        $validated = $this->validator()->validate($this->configuration(), $this->token($claims), 'nonce-1');

        self::assertSame('user-1', $validated['sub']);
    }

    public function test_rejects_wrong_nonce(): void
    {
        $this->expectException(OidcException::class);
        $claims = $this->baseClaims() + ['sub' => 'user-1', 'nonce' => 'nonce-1', 'exp' => time() + 300];
        $this->validator()->validate($this->configuration(), $this->token($claims), 'attacker');
    }

    public function test_validates_backchannel_logout_and_rejects_nonce(): void
    {
        $claims = $this->baseClaims() + [
            'jti' => 'logout-1', 'sid' => 'session-1',
            'events' => ['http://schemas.openid.net/event/backchannel-logout' => new \stdClass()],
            'nonce' => 'forbidden',
        ];

        $this->expectException(OidcException::class);
        (new BackChannelLogoutValidator($this->validator()))->validate($this->configuration(), $this->token($claims));
    }

    public function test_validates_backchannel_logout_with_json_object_events_claim(): void
    {
        $claims = $this->baseClaims() + [
            'jti' => 'logout-1', 'sid' => 'session-1',
            'events' => ['http://schemas.openid.net/event/backchannel-logout' => new \stdClass()],
        ];

        $validated = (new BackChannelLogoutValidator($this->validator()))
            ->validate($this->configuration(), $this->token($claims));

        self::assertSame('session-1', $validated['sid']);
    }

    private function validator(): IdTokenValidator
    {
        $handler = new MockHandler([new Response(200, ['Content-Type' => 'application/json'], json_encode(['keys' => [$this->jwk]], JSON_THROW_ON_ERROR))]);
        return new IdTokenValidator(new Client(['handler' => HandlerStack::create($handler)]));
    }

    /** @param array<string, mixed> $claims */
    private function token(array $claims): string
    {
        return JWT::encode($claims, $this->privateKey, 'RS256', 'test-key');
    }

    /** @return array<string, mixed> */
    private function baseClaims(): array
    {
        return ['iss' => 'https://identity.example.com', 'aud' => 'client', 'iat' => time()];
    }

    private function configuration(): OidcClientConfiguration
    {
        return new OidcClientConfiguration(
            'https://identity.example.com', 'client', 'https://app.example.com/callback',
            'https://identity.example.com/authorize', 'https://identity.example.com/token',
            'https://identity.example.com/jwks',
        );
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
