<?php

namespace Novvor\IdentitySdk\Tests;

use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Novvor\IdentitySdk\Oidc\OidcException;
use Novvor\IdentitySdk\Oidc\WorkloadAccessTokenValidator;
use Novvor\IdentitySdk\Oidc\WorkloadClientConfiguration;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class WorkloadAccessTokenValidatorTest extends TestCase
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
            'kty' => 'RSA',
            'kid' => 'key-1',
            'alg' => 'RS256',
            'use' => 'sig',
            'n' => $this->base64Url($details['rsa']['n']),
            'e' => $this->base64Url($details['rsa']['e']),
        ];
    }

    public function test_it_validates_authority_temporal_scope_and_tenant_claims(): void
    {
        $validator = $this->validator([$this->jwksResponse()]);
        $claims = $validator->validate(
            $this->config(),
            $this->token(['tenant_id' => 'tenant-a']),
            ['orbit.execute'],
            requiredTenantId: 'tenant-a',
        );

        self::assertSame('orbit-client', $claims['client_id']);
    }

    /** @param array<string, mixed> $claims */
    #[DataProvider('invalidClaimProvider')]
    public function test_it_rejects_wrong_or_inactive_claims(array $claims, ?string $tenant = null): void
    {
        $this->expectException(OidcException::class);
        $this->validator([$this->jwksResponse(), $this->jwksResponse()])
            ->validate($this->config(), $this->token($claims), ['orbit.execute'], requiredTenantId: $tenant);
    }

    /** @return array<string, array{array<string, mixed>, 1?: string}> */
    public static function invalidClaimProvider(): array
    {
        return [
            'wrong issuer' => [['iss' => 'https://attacker.example.test']],
            'wrong audience' => [['aud' => 'other-product']],
            'wrong client' => [['client_id' => 'other', 'azp' => 'other']],
            'revoked workload' => [['workload_status' => 'revoked']],
            'tenant mismatch' => [['tenant_id' => 'tenant-a'], 'tenant-b'],
            'expired' => [['exp' => time() - 300]],
            'not before' => [['nbf' => time() + 300]],
            'scope' => [['scope' => 'other.scope']],
        ];
    }

    public function test_unknown_kid_forces_one_rotation_refresh_then_fails_closed(): void
    {
        $unknown = $this->jwk;
        $unknown['kid'] = 'other-key';
        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('signing key is unknown');

        $this->validator([
            new Response(200, [], json_encode(['keys' => [$unknown]], JSON_THROW_ON_ERROR)),
            new Response(200, [], json_encode(['keys' => [$unknown]], JSON_THROW_ON_ERROR)),
        ])->validate($this->config(), $this->token());
    }

    /** @param list<Response> $responses */
    private function validator(array $responses): WorkloadAccessTokenValidator
    {
        return new WorkloadAccessTokenValidator(new Client([
            'handler' => HandlerStack::create(new MockHandler($responses)),
        ]));
    }

    private function jwksResponse(): Response
    {
        return new Response(200, [], json_encode(['keys' => [$this->jwk]], JSON_THROW_ON_ERROR));
    }

    /** @param array<string, mixed> $overrides */
    private function token(array $overrides = []): string
    {
        $now = time();
        $claims = array_merge([
            'iss' => 'https://identity.example.test',
            'aud' => 'enix-platform',
            'client_id' => 'orbit-client',
            'azp' => 'orbit-client',
            'token_use' => 'access',
            'sub_type' => 'client',
            'jti' => 'token-1',
            'scope' => 'orbit.execute',
            'iat' => $now,
            'nbf' => $now - 1,
            'exp' => $now + 300,
        ], $overrides);

        return JWT::encode($claims, $this->privateKey, 'RS256', 'key-1');
    }

    private function config(): WorkloadClientConfiguration
    {
        return new WorkloadClientConfiguration(
            'https://identity.example.test',
            'orbit-client',
            'secret',
            'https://identity.example.test/oauth/token',
            'https://identity.example.test/.well-known/jwks.json',
            'enix-platform',
            ['orbit.execute'],
        );
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
