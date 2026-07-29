<?php

declare(strict_types=1);

namespace Novvor\IdentitySdk\Tests;

use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Novvor\IdentitySdk\Oidc\AuthorizationRequestFactory;
use Novvor\IdentitySdk\Oidc\AuthorizationResponseProcessor;
use Novvor\IdentitySdk\Oidc\ClientAssertionFactory;
use Novvor\IdentitySdk\Oidc\DpopKey;
use Novvor\IdentitySdk\Oidc\DpopProofFactory;
use Novvor\IdentitySdk\Oidc\JarmAuthorizationResponseValidator;
use Novvor\IdentitySdk\Oidc\OidcClientConfiguration;
use Novvor\IdentitySdk\Oidc\OidcException;
use Novvor\IdentitySdk\Oidc\PushedAuthorizationClient;
use Novvor\IdentitySdk\Oidc\RefreshTokenClient;
use Novvor\IdentitySdk\Oidc\TokenIntrospectionClient;
use Novvor\IdentitySdk\Oidc\TokenRevocationClient;
use Novvor\IdentitySdk\Oidc\UserInfoClient;
use PHPUnit\Framework\TestCase;

final class EnterpriseOidcProfileTest extends TestCase
{
    public function test_par_uses_private_key_jwt_and_returns_typed_request(): void
    {
        [$privateKey] = $this->rsaKey();
        $history = [];
        $stack = HandlerStack::create(new MockHandler([new Response(201, [], '{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":90}')]));
        $stack->push(\GuzzleHttp\Middleware::history($history));
        $http = new Client(['handler' => $stack]);
        $configuration = $this->configuration($privateKey);
        $transaction = (new AuthorizationRequestFactory())->transaction($configuration);

        $pushed = (new PushedAuthorizationClient($http))->push(
            $configuration,
            $transaction,
            'https://identity.example.com/oauth/par',
            'correlation-1',
        );

        self::assertSame('urn:ietf:params:oauth:request_uri:abc', $pushed->requestUri);
        self::assertSame(90, $pushed->expiresIn);
        parse_str((string) $history[0]['request']->getBody(), $body);
        $request = $history[0]['request'];
        self::assertSame($configuration->clientId, $body['client_id']);
        self::assertArrayHasKey('client_assertion', $body);
        self::assertArrayNotHasKey('client_secret', $body);
        self::assertSame('correlation-1', $request->getHeaderLine('X-Correlation-ID'));
        $assertionJwt = $body['client_assertion'] ?? null;
        self::assertIsString($assertionJwt);
        [, $assertion] = $this->decode($assertionJwt);
        self::assertSame('https://identity.example.com/oauth/par', $assertion['aud']);
    }

    public function test_rfc9207_requires_exact_issuer_and_state(): void
    {
        $processor = new AuthorizationResponseProcessor();
        $result = $processor->process($this->configuration(), [
            'code' => 'code-1',
            'state' => 'state-1',
            'iss' => 'https://identity.example.com',
        ], 'state-1');
        self::assertTrue($result->succeeded());

        $this->expectException(OidcException::class);
        $processor->process($this->configuration(), [
            'code' => 'code-1',
            'state' => 'state-1',
            'iss' => 'https://attacker.example',
        ], 'state-1');
    }

    public function test_jarm_validates_signature_issuer_audience_expiry_and_state(): void
    {
        [$privateKey, $jwk] = $this->rsaKey();
        $jwt = JWT::encode([
            'iss' => 'https://identity.example.com',
            'aud' => 'client',
            'iat' => time(),
            'exp' => time() + 60,
            'code' => 'code-1',
            'state' => 'state-1',
        ], $privateKey, 'RS256', 'test-key');
        $http = $this->http([new Response(200, [], json_encode(['keys' => [$jwk]], JSON_THROW_ON_ERROR))]);

        $result = (new AuthorizationResponseProcessor(new JarmAuthorizationResponseValidator($http)))
            ->process($this->configuration(), ['response' => $jwt], 'state-1');

        self::assertSame('code-1', $result->code);
    }

    public function test_dpop_proof_is_bound_to_method_uri_and_access_token(): void
    {
        [$privateKey, $jwk] = $this->rsaKey();
        $jwt = (new DpopProofFactory())->create(
            new DpopKey($privateKey, $jwk, 'RS256'),
            'post',
            'https://api.example.com/token?ignored=1',
            'access-token',
            'nonce-1',
            1700000000,
        );
        [$header, $claims] = $this->decode($jwt);

        self::assertSame('dpop+jwt', $header['typ']);
        self::assertSame('POST', $claims['htm']);
        self::assertSame('https://api.example.com/token', $claims['htu']);
        self::assertSame('nonce-1', $claims['nonce']);
        self::assertSame(rtrim(strtr(base64_encode(hash('sha256', 'access-token', true)), '+/', '-_'), '='), $claims['ath']);
        self::assertArrayNotHasKey('d', $header['jwk']);
    }

    public function test_high_assurance_profile_rejects_secret_authentication_downgrade(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new OidcClientConfiguration(
            'https://identity.example.com', 'client', 'https://app.example.com/callback',
            'https://identity.example.com/authorize', 'https://identity.example.com/token',
            'https://identity.example.com/jwks', 'secret', 5, 'client_secret_post',
            profile: 'novvor-high-assurance-v1',
        );
    }

    public function test_high_assurance_profile_rejects_direct_authorization(): void
    {
        [$privateKey] = $this->rsaKey();
        $this->expectException(OidcException::class);
        (new AuthorizationRequestFactory())->create($this->configuration($privateKey));
    }

    public function test_high_assurance_profile_rejects_plain_callback(): void
    {
        [$privateKey] = $this->rsaKey();
        $this->expectException(OidcException::class);
        (new AuthorizationResponseProcessor())->process($this->configuration($privateKey), [
            'code' => 'code-1',
            'state' => 'state-1',
            'iss' => 'https://identity.example.com',
        ], 'state-1');
    }

    public function test_auto_authentication_keeps_v1_secret_compatibility(): void
    {
        $configuration = new OidcClientConfiguration(
            'https://identity.example.com', 'client', 'https://app.example.com/callback',
            'https://identity.example.com/authorize', 'https://identity.example.com/token',
            'https://identity.example.com/jwks', 'legacy-secret',
        );
        $form = [];
        (new ClientAssertionFactory())->authenticate($configuration, $form);
        self::assertSame('legacy-secret', $form['client_secret']);
    }

    public function test_refresh_rotation_requires_and_returns_a_new_refresh_token(): void
    {
        [$privateKey, $jwk] = $this->rsaKey();
        $history = [];
        $stack = HandlerStack::create(new MockHandler([new Response(200, [], json_encode([
            'access_token' => 'access-2',
            'refresh_token' => 'refresh-2',
            'token_type' => 'DPoP',
            'expires_in' => 300,
            'scope' => 'openid profile',
        ], JSON_THROW_ON_ERROR))]));
        $stack->push(\GuzzleHttp\Middleware::history($history));
        $tokens = (new RefreshTokenClient(new Client(['handler' => $stack])))->rotate(
            $this->configuration($privateKey),
            'refresh-1',
            'correlation-refresh',
            new DpopKey($privateKey, $jwk, 'RS256'),
        );

        self::assertSame('refresh-2', $tokens->refreshToken);
        self::assertSame('DPoP', $tokens->tokenType);
        self::assertSame('openid profile', $tokens->scope);
        parse_str((string) $history[0]['request']->getBody(), $body);
        self::assertSame('refresh_token', $body['grant_type']);
        self::assertSame('refresh-1', $body['refresh_token']);
        self::assertNotSame('', $history[0]['request']->getHeaderLine('DPoP'));
    }

    public function test_token_exchange_retries_one_valid_dpop_nonce_challenge(): void
    {
        [$privateKey, $jwk] = $this->rsaKey();
        $history = [];
        $stack = HandlerStack::create(new MockHandler([
            new Response(400, ['DPoP-Nonce' => 'server-nonce'], '{"error":"use_dpop_nonce"}'),
            new Response(200, [], '{"access_token":"access-1","id_token":"id-1","token_type":"DPoP","expires_in":300}'),
        ]));
        $stack->push(\GuzzleHttp\Middleware::history($history));

        $tokens = (new \Novvor\IdentitySdk\Oidc\AuthorizationCodeClient(new Client(['handler' => $stack])))->exchange(
            $this->configuration($privateKey),
            'authorization-code',
            str_repeat('v', 64),
            dpopKey: new DpopKey($privateKey, $jwk, 'RS256'),
        );

        self::assertSame('access-1', $tokens->accessToken);
        self::assertArrayHasKey(1, $history);
        self::assertArrayNotHasKey(2, $history);
        self::assertArrayNotHasKey('nonce', $this->dpopPayload($history[0]['request']->getHeaderLine('DPoP')));
        self::assertSame('server-nonce', $this->dpopPayload($history[1]['request']->getHeaderLine('DPoP'))['nonce']);
    }

    public function test_refresh_rotation_retries_one_valid_dpop_nonce_challenge(): void
    {
        [$privateKey, $jwk] = $this->rsaKey();
        $history = [];
        $stack = HandlerStack::create(new MockHandler([
            new Response(400, ['DPoP-Nonce' => 'refresh-nonce'], '{"error":"use_dpop_nonce"}'),
            new Response(200, [], '{"access_token":"access-2","refresh_token":"refresh-2","token_type":"DPoP","expires_in":300}'),
        ]));
        $stack->push(\GuzzleHttp\Middleware::history($history));

        $tokens = (new RefreshTokenClient(new Client(['handler' => $stack])))->rotate(
            $this->configuration($privateKey),
            'refresh-1',
            dpopKey: new DpopKey($privateKey, $jwk, 'RS256'),
        );

        self::assertSame('refresh-2', $tokens->refreshToken);
        self::assertArrayHasKey(1, $history);
        self::assertArrayNotHasKey(2, $history);
        self::assertSame('refresh-nonce', $this->dpopPayload($history[1]['request']->getHeaderLine('DPoP'))['nonce']);
    }

    public function test_userinfo_binds_dpop_proof_and_checks_subject(): void
    {
        [$privateKey, $jwk] = $this->rsaKey();
        $history = [];
        $stack = HandlerStack::create(new MockHandler([new Response(200, [], '{"sub":"user-1","email":"user@example.com"}')]));
        $stack->push(\GuzzleHttp\Middleware::history($history));

        $result = (new UserInfoClient(new Client(['handler' => $stack])))->fetch(
            $this->configuration($privateKey),
            'access-1',
            'DPoP',
            'user-1',
            'correlation-userinfo',
            new DpopKey($privateKey, $jwk, 'RS256'),
        );

        self::assertSame('user-1', $result->subject);
        self::assertSame('DPoP access-1', $history[0]['request']->getHeaderLine('Authorization'));
        self::assertNotSame('', $history[0]['request']->getHeaderLine('DPoP'));
        self::assertSame('correlation-userinfo', $history[0]['request']->getHeaderLine('X-Correlation-ID'));
    }

    public function test_userinfo_retries_one_valid_dpop_nonce_challenge(): void
    {
        [$privateKey, $jwk] = $this->rsaKey();
        $history = [];
        $stack = HandlerStack::create(new MockHandler([
            new Response(401, ['DPoP-Nonce' => 'userinfo-nonce'], '{"error":"use_dpop_nonce"}'),
            new Response(200, [], '{"sub":"user-1"}'),
        ]));
        $stack->push(\GuzzleHttp\Middleware::history($history));

        $result = (new UserInfoClient(new Client(['handler' => $stack])))->fetch(
            $this->configuration($privateKey),
            'access-1',
            'DPoP',
            'user-1',
            dpopKey: new DpopKey($privateKey, $jwk, 'RS256'),
        );

        self::assertSame('user-1', $result->subject);
        self::assertArrayHasKey(1, $history);
        self::assertArrayNotHasKey(2, $history);
        self::assertSame('userinfo-nonce', $this->dpopPayload($history[1]['request']->getHeaderLine('DPoP'))['nonce']);
    }

    public function test_dpop_nonce_challenge_is_never_retried_more_than_once(): void
    {
        [$privateKey, $jwk] = $this->rsaKey();
        $history = [];
        $stack = HandlerStack::create(new MockHandler([
            new Response(400, ['DPoP-Nonce' => 'nonce-1'], '{"error":"use_dpop_nonce"}'),
            new Response(400, ['DPoP-Nonce' => 'nonce-2'], '{"error":"use_dpop_nonce"}'),
        ]));
        $stack->push(\GuzzleHttp\Middleware::history($history));

        try {
            (new RefreshTokenClient(new Client(['handler' => $stack])))->rotate(
                $this->configuration($privateKey),
                'refresh-1',
                dpopKey: new DpopKey($privateKey, $jwk, 'RS256'),
            );
            self::fail('A repeated DPoP nonce challenge must fail closed.');
        } catch (\Novvor\IdentitySdk\Oidc\OAuthEndpointException $exception) {
            self::assertSame('use_dpop_nonce', $exception->oauthError);
            self::assertSame('nonce-2', $exception->dpopNonce);
        }

        self::assertArrayHasKey(1, $history);
        self::assertArrayNotHasKey(2, $history);
    }

    public function test_userinfo_rejects_subject_substitution(): void
    {
        $client = new UserInfoClient($this->http([new Response(200, [], '{"sub":"attacker"}')]));
        $this->expectException(OidcException::class);
        $client->fetch($this->configuration(), 'access-1', expectedSubject: 'user-1');
    }

    public function test_introspection_uses_endpoint_specific_private_key_assertion(): void
    {
        [$privateKey] = $this->rsaKey();
        $history = [];
        $stack = HandlerStack::create(new MockHandler([new Response(200, [], '{"active":true,"sub":"user-1"}')]));
        $stack->push(\GuzzleHttp\Middleware::history($history));

        $result = (new TokenIntrospectionClient(new Client(['handler' => $stack])))->introspect(
            $this->configuration($privateKey),
            'access-1',
            'access_token',
        );

        self::assertTrue($result->active);
        parse_str((string) $history[0]['request']->getBody(), $body);
        self::assertArrayHasKey('client_assertion', $body);
        $clientAssertion = $body['client_assertion'];
        if (! is_string($clientAssertion)) {
            self::fail('Client assertion must be a JWT string.');
        }
        [, $claims] = $this->decode($clientAssertion);
        self::assertSame('https://identity.example.com/oauth/introspect', $claims['aud']);
    }

    public function test_revocation_is_idempotent_for_success_response(): void
    {
        [$privateKey] = $this->rsaKey();
        $history = [];
        $stack = HandlerStack::create(new MockHandler([new Response(200)]));
        $stack->push(\GuzzleHttp\Middleware::history($history));

        (new TokenRevocationClient(new Client(['handler' => $stack])))->revoke(
            $this->configuration($privateKey),
            'refresh-1',
            'refresh_token',
        );

        parse_str((string) $history[0]['request']->getBody(), $body);
        self::assertSame('refresh_token', $body['token_type_hint']);
        self::assertSame('refresh-1', $body['token']);
    }

    private function configuration(?string $privateKey = null): OidcClientConfiguration
    {
        return new OidcClientConfiguration(
            'https://identity.example.com', 'client', 'https://app.example.com/callback',
            'https://identity.example.com/authorize', 'https://identity.example.com/token',
            'https://identity.example.com/jwks', null, 5,
            $privateKey === null ? 'none' : 'private_key_jwt',
            $privateKey,
            $privateKey === null ? null : 'client-key',
            profile: $privateKey === null ? 'standard' : 'novvor-high-assurance-v1',
            userinfoEndpoint: 'https://identity.example.com/oauth/userinfo',
            introspectionEndpoint: 'https://identity.example.com/oauth/introspect',
            revocationEndpoint: 'https://identity.example.com/oauth/revoke',
        );
    }

    /** @return array{0: string, 1: array<string, string>} */
    private function rsaKey(): array
    {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($resource);
        $privateKey = '';
        self::assertTrue(openssl_pkey_export($resource, $privateKey));
        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);

        return [$privateKey, [
            'kty' => 'RSA',
            'kid' => 'test-key',
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => $this->base64Url($details['rsa']['n']),
            'e' => $this->base64Url($details['rsa']['e']),
        ]];
    }

    /** @param list<Response> $responses */
    private function http(array $responses): Client
    {
        $stack = HandlerStack::create(new MockHandler($responses));

        return new Client(['handler' => $stack]);
    }

    /** @return array<string, mixed> */
    private function dpopPayload(string $proof): array
    {
        $parts = explode('.', $proof);
        self::assertCount(3, $parts);
        $decoded = base64_decode(strtr($parts[1], '-_', '+/'), true);
        self::assertIsString($decoded);
        $payload = json_decode($decoded, true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($payload);

        return $payload;
    }

    /** @return array{0: array<string, mixed>, 1: array<string, mixed>} */
    private function decode(string $jwt): array
    {
        $parts = explode('.', $jwt);
        return [json_decode($this->base64UrlDecode($parts[0]), true, flags: JSON_THROW_ON_ERROR), json_decode($this->base64UrlDecode($parts[1]), true, flags: JSON_THROW_ON_ERROR)];
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $value): string
    {
        return (string) base64_decode(strtr($value.str_repeat('=', (4 - strlen($value) % 4) % 4), '-_', '+/'), true);
    }
}
