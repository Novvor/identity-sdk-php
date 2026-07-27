<?php

namespace Novvor\IdentitySdk\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Novvor\IdentitySdk\Oidc\ClientCredentialsClient;
use Novvor\IdentitySdk\Oidc\OidcException;
use Novvor\IdentitySdk\Oidc\WorkloadClientConfiguration;
use PHPUnit\Framework\TestCase;

final class ClientCredentialsClientTest extends TestCase
{
    public function test_it_requests_a_bearer_workload_token_with_the_requested_audience(): void
    {
        $history = []; $stack = HandlerStack::create(new MockHandler([new Response(200, [], json_encode(['access_token' => 'token', 'token_type' => 'Bearer', 'expires_in' => 60, 'scope' => 'orbit.execute'], JSON_THROW_ON_ERROR))]));
        $stack->push(\GuzzleHttp\Middleware::history($history));
        $token = (new ClientCredentialsClient(new Client(['handler' => $stack])))->issue($this->config());
        $this->assertSame('token', $token->accessToken);
        $this->assertStringContainsString('grant_type=client_credentials', (string) $history[0]['request']->getBody());
        $this->assertStringContainsString('audience=enix-platform', (string) $history[0]['request']->getBody());
    }
    public function test_it_rejects_a_non_bearer_response(): void
    {
        $client = new Client(['handler' => HandlerStack::create(new MockHandler([new Response(200, [], json_encode(['access_token' => 'token', 'token_type' => 'MAC'], JSON_THROW_ON_ERROR))]))]);
        $this->expectException(OidcException::class);
        (new ClientCredentialsClient($client))->issue($this->config());
    }

    public function test_it_can_prepare_private_key_jwt_without_sending_a_secret(): void
    {
        $privateKey = '';
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $this->assertNotFalse($resource);
        $this->assertTrue(openssl_pkey_export($resource, $privateKey));
        $history = [];
        $stack = HandlerStack::create(new MockHandler([new Response(200, [], json_encode(['access_token' => 'token', 'token_type' => 'Bearer', 'expires_in' => 60], JSON_THROW_ON_ERROR))]));
        $stack->push(\GuzzleHttp\Middleware::history($history));
        $configuration = new WorkloadClientConfiguration(
            'https://identity.example.test',
            'orbit-intelligence',
            null,
            'https://identity.example.test/oauth/token',
            'https://identity.example.test/.well-known/jwks.json',
            'enix-platform',
            ['orbit.execute'],
            credentialMethod: 'private_key_jwt',
            privateKey: $privateKey,
            privateKeyId: 'orbit-key-1',
        );

        (new ClientCredentialsClient(new Client(['handler' => $stack])))->issue($configuration);
        parse_str((string) $history[0]['request']->getBody(), $body);

        $this->assertArrayNotHasKey('client_secret', $body);
        $this->assertSame('urn:ietf:params:oauth:client-assertion-type:jwt-bearer', $body['client_assertion_type']);
        $this->assertIsString($body['client_assertion']);
        $this->assertCount(3, explode('.', $body['client_assertion']));
    }
    private function config(): WorkloadClientConfiguration { return new WorkloadClientConfiguration('https://identity.example.test', 'orbit-intelligence', 'secret', 'https://identity.example.test/oauth/token', 'https://identity.example.test/.well-known/jwks.json', 'enix-platform', ['orbit.execute']); }
}
