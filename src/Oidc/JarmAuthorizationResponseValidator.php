<?php

namespace Novvor\IdentitySdk\Oidc;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GuzzleHttp\ClientInterface;

final class JarmAuthorizationResponseValidator
{
    public function __construct(private readonly ClientInterface $http)
    {
    }

    /** @return array<string, mixed> */
    public function validate(OidcClientConfiguration $configuration, string $responseJwt, ?string $correlationId = null): array
    {
        $parts = explode('.', $responseJwt);
        $header = count($parts) === 3 ? json_decode((string) base64_decode(strtr($parts[0].str_repeat('=', (4 - strlen($parts[0]) % 4) % 4), '-_', '+/'), true), true) : null;
        if (! is_array($header) || ($header['alg'] ?? null) !== 'RS256' || ! is_string($header['kid'] ?? null) || $header['kid'] === '') {
            throw new OidcException('JARM response does not use an allowed signing algorithm.');
        }

        try {
            $httpResponse = $this->http->request('GET', $configuration->jwksUri, OidcHttpRequestOptions::strict($configuration->httpTimeoutSeconds, [], $correlationId));
            $jwks = json_decode((string) $httpResponse->getBody(), true);
            $keys = is_array($jwks) ? JWK::parseKeySet($jwks) : [];
            $key = $keys[$header['kid']] ?? null;
            if ($httpResponse->getStatusCode() !== 200 || ! $key instanceof Key) {
                throw new OidcException('JARM signing key is unknown.');
            }
            $claims = (array) JWT::decode($responseJwt, $key);
        } catch (OidcException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new OidcException('JARM signature is invalid.', 0, $exception);
        }

        $aud = $claims['aud'] ?? null;
        $audiences = is_string($aud) ? [$aud] : (is_array($aud) ? $aud : []);
        $now = time();
        if (rtrim((string) ($claims['iss'] ?? ''), '/') !== rtrim($configuration->issuer, '/')
            || ! in_array($configuration->clientId, $audiences, true)
            || ! is_numeric($claims['exp'] ?? null)
            || (int) $claims['exp'] <= $now
            || ! is_numeric($claims['iat'] ?? null)
            || (int) $claims['iat'] > $now + 30) {
            throw new OidcException('JARM protocol claims are invalid.');
        }

        return $claims;
    }
}
