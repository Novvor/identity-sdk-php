<?php

declare(strict_types=1);

namespace Novvor\IdentitySdk\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use Novvor\IdentitySdk\Oidc\AuthorizationCodeClient;
use Novvor\IdentitySdk\Oidc\OidcClientConfiguration;
use Novvor\IdentitySdk\Oidc\OidcDiscoveryClient;
use Novvor\IdentitySdk\Oidc\OidcException;
use Novvor\IdentitySdk\Oidc\OidcHttpRequestOptions;
use PHPUnit\Framework\TestCase;

final class OidcTransportSecurityTest extends TestCase
{
    public function test_discovery_requires_https_endpoints(): void
    {
        $client = $this->client([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'issuer' => 'https://identity.example.com',
                'authorization_endpoint' => 'https://identity.example.com/oauth/authorize',
                'token_endpoint' => 'https://identity.example.com/oauth/token',
                'jwks_uri' => 'https://identity.example.com/.well-known/jwks.json',
            ], JSON_THROW_ON_ERROR)),
        ]);

        $document = (new OidcDiscoveryClient($client))->discover('https://identity.example.com');

        self::assertSame('https://identity.example.com/oauth/token', $document->tokenEndpoint);
    }

    public function test_token_exchange_and_strict_transport_options_reject_invalid_correlation_id(): void
    {
        $client = $this->client([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'access_token' => 'access-token',
                'id_token' => 'id-token',
                'token_type' => 'Bearer',
                'expires_in' => 300,
            ], JSON_THROW_ON_ERROR)),
        ]);

        $tokens = (new AuthorizationCodeClient($client))->exchange($this->configuration(), 'code', str_repeat('a', 43));

        self::assertSame('access-token', $tokens->accessToken);
        self::assertSame([
            'timeout' => 5,
            'connect_timeout' => 5,
            'http_errors' => false,
            'allow_redirects' => false,
            'verify' => true,
            'headers' => ['Accept' => 'application/json', 'X-Correlation-ID' => 'corr-456'],
        ], OidcHttpRequestOptions::strict(5, ['Accept' => 'application/json'], 'corr-456'));

        $this->expectException(OidcException::class);
        OidcHttpRequestOptions::strict(5, [], "invalid\nheader");
    }

    /** @param list<Response> $responses */
    private function client(array $responses): Client
    {
        return new Client(['handler' => \GuzzleHttp\HandlerStack::create(new MockHandler($responses))]);
    }

    private function configuration(): OidcClientConfiguration
    {
        return new OidcClientConfiguration(
            'https://identity.example.com',
            'client',
            'https://app.example.com/auth/oidc/callback',
            'https://identity.example.com/oauth/authorize',
            'https://identity.example.com/oauth/token',
            'https://identity.example.com/.well-known/jwks.json',
            'client-secret',
        );
    }
}
