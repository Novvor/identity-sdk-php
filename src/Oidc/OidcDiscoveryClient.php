<?php

namespace Novvor\IdentitySdk\Oidc;

use GuzzleHttp\ClientInterface;

final class OidcDiscoveryClient
{
    public function __construct(private readonly ClientInterface $http)
    {
    }

    public function discover(string $issuer, int $timeoutSeconds = 5): OidcDiscoveryDocument
    {
        $issuer = rtrim($issuer, '/');
        if (filter_var($issuer, FILTER_VALIDATE_URL) === false || parse_url($issuer, PHP_URL_SCHEME) !== 'https') {
            throw new OidcException('OIDC issuer must be an explicit HTTPS URL.');
        }

        try {
            $response = $this->http->request('GET', $issuer.'/.well-known/openid-configuration', [
                'timeout' => $timeoutSeconds,
                'connect_timeout' => $timeoutSeconds,
                'http_errors' => false,
                'headers' => ['Accept' => 'application/json'],
            ]);
        } catch (\Throwable $exception) {
            throw new OidcException('OIDC discovery request failed.', 0, $exception);
        }

        $document = json_decode((string) $response->getBody(), true);
        if ($response->getStatusCode() !== 200 || ! is_array($document) || rtrim((string) ($document['issuer'] ?? ''), '/') !== $issuer) {
            throw new OidcException('OIDC discovery document is invalid or issuer does not match.');
        }

        foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $field) {
            if (! is_string($document[$field] ?? null) || $document[$field] === '') {
                throw new OidcException('OIDC discovery document is missing '.$field.'.');
            }
        }

        return new OidcDiscoveryDocument(
            issuer: $issuer,
            authorizationEndpoint: (string) $document['authorization_endpoint'],
            tokenEndpoint: (string) $document['token_endpoint'],
            jwksUri: (string) $document['jwks_uri'],
            userinfoEndpoint: is_string($document['userinfo_endpoint'] ?? null) ? $document['userinfo_endpoint'] : null,
            endSessionEndpoint: is_string($document['end_session_endpoint'] ?? null) ? $document['end_session_endpoint'] : null,
        );
    }
}
