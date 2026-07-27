<?php

namespace Novvor\IdentitySdk\Oidc;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GuzzleHttp\ClientInterface;

/** Validates machine access tokens; deliberately does not accept ID tokens. */
final class WorkloadAccessTokenValidator
{
    /** @var array<string, array{keys: list<array<string, mixed>>}> */
    private array $jwks = [];
    public function __construct(private readonly ClientInterface $http) {}
    /** @return array<string, mixed> */
    /**
     * @param list<string> $requiredScopes
     * @return array<string, mixed>
     */
    public function validate(WorkloadClientConfiguration $config, string $token, array $requiredScopes = [], ?string $correlationId = null): array
    {
        $parts = explode('.', $token); if (count($parts) !== 3) throw new OidcException('Workload access token is malformed.');
        $header = json_decode((string) base64_decode(strtr($parts[0].str_repeat('=', (4 - strlen($parts[0]) % 4) % 4), '-_', '+/'), true), true);
        if (! is_array($header) || ($header['alg'] ?? null) !== 'RS256' || ! is_string($header['kid'] ?? null) || $header['kid'] === '') throw new OidcException('Workload access token algorithm or key is invalid.');
        $keys = JWK::parseKeySet($this->keys($config, false, $correlationId)); $key = $keys[$header['kid']] ?? null;
        if (! $key instanceof Key) { $keys = JWK::parseKeySet($this->keys($config, true, $correlationId)); $key = $keys[$header['kid']] ?? null; }
        if (! $key instanceof Key) throw new OidcException('Workload access token signing key is unknown.');
        try { $claims = (array) JWT::decode($token, $key); } catch (\Throwable $exception) { throw new OidcException('Workload access token signature is invalid.', 0, $exception); }
        if (rtrim((string) ($claims['iss'] ?? ''), '/') !== rtrim($config->issuer, '/') || ($claims['aud'] ?? null) !== $config->audience || ($claims['client_id'] ?? null) !== $config->clientId || ($claims['azp'] ?? null) !== $config->clientId || ($claims['token_use'] ?? null) !== 'access' || ($claims['sub_type'] ?? null) !== 'client' || ! is_string($claims['jti'] ?? null) || $claims['jti'] === '') throw new OidcException('Workload access token claims are invalid.');
        $scopes = preg_split('/\s+/', trim((string) ($claims['scope'] ?? ''))) ?: [];
        foreach ($requiredScopes as $scope) if (! in_array($scope, $scopes, true)) throw new OidcException('Workload access token scope is insufficient.');
        return $claims;
    }
    /** @return array{keys: list<array<string, mixed>>} */
    private function keys(WorkloadClientConfiguration $config, bool $refresh, ?string $correlationId): array
    {
        if (! $refresh && isset($this->jwks[$config->jwksUri])) return $this->jwks[$config->jwksUri];
        try { $response = $this->http->request('GET', $config->jwksUri, OidcHttpRequestOptions::strict($config->httpTimeoutSeconds, [], $correlationId)); } catch (\Throwable $exception) { throw new OidcException('Workload JWKS request failed.', 0, $exception); }
        $document = json_decode((string) $response->getBody(), true);
        if ($response->getStatusCode() !== 200 || ! is_array($document) || ! is_array($document['keys'] ?? null) || ! array_is_list($document['keys'])) throw new OidcException('Workload JWKS document is invalid.');
        $keys = [];
        foreach ($document['keys'] as $key) { if (! is_array($key)) throw new OidcException('Workload JWKS document is invalid.'); $keys[] = $key; }
        return $this->jwks[$config->jwksUri] = ['keys' => $keys];
    }
}
