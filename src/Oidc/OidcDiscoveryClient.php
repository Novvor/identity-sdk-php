<?php

namespace Novvor\IdentitySdk\Oidc;

use GuzzleHttp\ClientInterface;

final class OidcDiscoveryClient
{
    public function __construct(private readonly ClientInterface $http)
    {
    }

    public function discover(string $issuer, int $timeoutSeconds = 5, ?string $correlationId = null): OidcDiscoveryDocument
    {
        $issuer = rtrim($issuer, '/');
        if (filter_var($issuer, FILTER_VALIDATE_URL) === false || parse_url($issuer, PHP_URL_SCHEME) !== 'https') {
            throw new OidcException('OIDC issuer must be an explicit HTTPS URL.');
        }

        try {
            $response = $this->http->request('GET', $issuer.'/.well-known/openid-configuration', OidcHttpRequestOptions::strict(
                $timeoutSeconds,
                ['Accept' => 'application/json'],
                $correlationId,
            ));
        } catch (\Throwable $exception) {
            throw new OidcException('OIDC discovery request failed.', 0, $exception);
        }

        $document = json_decode((string) $response->getBody(), true);
        if ($response->getStatusCode() !== 200 || ! is_array($document) || rtrim((string) ($document['issuer'] ?? ''), '/') !== $issuer) {
            throw new OidcException('OIDC discovery document is invalid or issuer does not match.');
        }

        foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $field) {
            if (! is_string($document[$field] ?? null) || ! self::isHttpsUrl($document[$field])) {
                throw new OidcException('OIDC discovery document is missing '.$field.'.');
            }
        }

        foreach (['userinfo_endpoint', 'end_session_endpoint', 'pushed_authorization_request_endpoint'] as $field) {
            if (isset($document[$field]) && (! is_string($document[$field]) || ! self::isHttpsUrl($document[$field]))) {
                throw new OidcException('OIDC discovery document contains an invalid '.$field.'.');
            }
        }

        return new OidcDiscoveryDocument(
            issuer: $issuer,
            authorizationEndpoint: (string) $document['authorization_endpoint'],
            tokenEndpoint: (string) $document['token_endpoint'],
            jwksUri: (string) $document['jwks_uri'],
            userinfoEndpoint: is_string($document['userinfo_endpoint'] ?? null) ? $document['userinfo_endpoint'] : null,
            endSessionEndpoint: is_string($document['end_session_endpoint'] ?? null) ? $document['end_session_endpoint'] : null,
            pushedAuthorizationRequestEndpoint: is_string($document['pushed_authorization_request_endpoint'] ?? null) ? $document['pushed_authorization_request_endpoint'] : null,
            responseModesSupported: self::stringList($document['response_modes_supported'] ?? []),
            grantTypesSupported: self::stringList($document['grant_types_supported'] ?? []),
            tokenEndpointAuthMethodsSupported: self::stringList($document['token_endpoint_auth_methods_supported'] ?? []),
            dpopSigningAlgValuesSupported: self::stringList($document['dpop_signing_alg_values_supported'] ?? []),
            authorizationResponseIssuerParameterSupported: ($document['authorization_response_iss_parameter_supported'] ?? false) === true,
            metadata: $document,
        );
    }

    private static function isHttpsUrl(string $url): bool
    {
        return filter_var($url, FILTER_VALIDATE_URL) !== false && parse_url($url, PHP_URL_SCHEME) === 'https';
    }

    /** @return list<string> */
    private static function stringList(mixed $value): array
    {
        if (! is_array($value) || ! array_is_list($value)) {
            return [];
        }

        return array_values(array_filter($value, static fn (mixed $item): bool => is_string($item) && $item !== ''));
    }
}
