<?php

namespace Novvor\IdentitySdk\Oidc;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GuzzleHttp\ClientInterface;

final class IdTokenValidator
{
    /** @var array<string, array<string, mixed>> */
    private array $jwksByUri = [];

    public function __construct(private readonly ClientInterface $http)
    {
    }

    /** @return array<string, mixed> */
    /** @return array<string, mixed> */
    public function validate(OidcClientConfiguration $configuration, string $idToken, ?string $expectedNonce = null): array
    {
        $payload = $this->verifiedClaims($configuration, $idToken);
        $this->assertIssuerAndAudience($configuration, $payload);
        if (trim((string) ($payload['sub'] ?? '')) === '') {
            throw new OidcException('ID token subject is missing.');
        }
        if ($expectedNonce !== null && ($expectedNonce === '' || ! hash_equals($expectedNonce, (string) ($payload['nonce'] ?? '')))) {
            throw new OidcException('ID token nonce does not match the authorization session.');
        }
        $now = time();
        if (! is_numeric($payload['exp'] ?? null) || (int) $payload['exp'] <= $now || ! is_numeric($payload['iat'] ?? null) || (int) $payload['iat'] > $now + 30 || (isset($payload['nbf']) && (int) $payload['nbf'] > $now + 30)) {
            throw new OidcException('ID token time claims are invalid.');
        }

        return $payload;
    }

    /** @return array<string, mixed> */
    public function validateLogoutToken(OidcClientConfiguration $configuration, string $logoutToken): array
    {
        $payload = $this->verifiedClaims($configuration, $logoutToken);
        $this->assertIssuerAndAudience($configuration, $payload);
        if (! is_numeric($payload['iat'] ?? null) || (int) $payload['iat'] > time() + 30 || trim((string) ($payload['jti'] ?? '')) === '') {
            throw new OidcException('Back-channel logout token time or identifier claims are invalid.');
        }

        return $payload;
    }

    /** @return array<string, mixed> */
    private function verifiedClaims(OidcClientConfiguration $configuration, string $token): array
    {
        $header = $this->decodeHeader($token);
        if (($header['alg'] ?? null) !== 'RS256' || ! is_string($header['kid'] ?? null) || $header['kid'] === '') {
            throw new OidcException('JWT header does not use an allowed signing algorithm.');
        }

        $keys = $this->jwks($configuration->jwksUri, $configuration->httpTimeoutSeconds, false);
        $keySet = JWK::parseKeySet($keys);
        $kid = $header['kid'];
        if (! isset($keySet[$kid])) {
            $keySet = JWK::parseKeySet($this->jwks($configuration->jwksUri, $configuration->httpTimeoutSeconds, true));
        }
        $key = $keySet[$kid] ?? null;
        if (! $key instanceof Key) {
            throw new OidcException('ID token signing key is unknown.');
        }
        try {
            $payload = (array) JWT::decode($token, $key);
        } catch (\Throwable $exception) {
            throw new OidcException('JWT signature is invalid.', 0, $exception);
        }

        return $payload;
    }

    /** @param array<string, mixed> $payload */
    private function assertIssuerAndAudience(OidcClientConfiguration $configuration, array $payload): void
    {
        if (rtrim((string) ($payload['iss'] ?? ''), '/') !== rtrim($configuration->issuer, '/')) {
            throw new OidcException('JWT issuer does not match discovery.');
        }
        $audience = $payload['aud'] ?? null;
        $audiences = is_string($audience) ? [$audience] : (is_array($audience) ? $audience : []);
        if (! in_array($configuration->clientId, $audiences, true)) {
            throw new OidcException('JWT audience does not match the client.');
        }
        if ((count($audiences) > 1 || isset($payload['azp'])) && ($payload['azp'] ?? null) !== $configuration->clientId) {
            throw new OidcException('JWT authorized party does not match the client.');
        }
    }

    /** @return array<string, mixed> */
    /** @return array<string, mixed> */
    private function jwks(string $uri, int $timeoutSeconds, bool $refresh): array
    {
        if (! $refresh && isset($this->jwksByUri[$uri])) {
            return $this->jwksByUri[$uri];
        }
        try {
            $response = $this->http->request('GET', $uri, ['timeout' => $timeoutSeconds, 'connect_timeout' => $timeoutSeconds, 'http_errors' => false]);
        } catch (\Throwable $exception) {
            throw new OidcException('JWKS request failed.', 0, $exception);
        }
        $jwks = json_decode((string) $response->getBody(), true);
        if ($response->getStatusCode() !== 200 || ! is_array($jwks) || ! is_array($jwks['keys'] ?? null)) {
            throw new OidcException('JWKS document is invalid.');
        }

        return $this->jwksByUri[$uri] = $jwks;
    }

    /** @return array{0: array<string, mixed>, 1: array<string, mixed>} */
    /** @return array<string, mixed> */
    private function decodeHeader(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new OidcException('ID token is malformed.');
        }
        $decode = static function (string $value): mixed {
            $value .= str_repeat('=', (4 - strlen($value) % 4) % 4);
            return json_decode((string) base64_decode(strtr($value, '-_', '+/'), true), true);
        };
        $header = $decode($parts[0]);
        if (! is_array($header)) {
            throw new OidcException('JWT is malformed.');
        }

        return $header;
    }
}
