<?php

namespace Novvor\IdentitySdk\Oidc;

final readonly class DpopKey
{
    /** @param array<string, mixed> $publicJwk */
    public function __construct(
        public string $privateKey,
        public array $publicJwk,
        public string $algorithm = 'ES256',
    ) {
        if ($privateKey === '' || ! in_array($algorithm, ['ES256', 'RS256'], true)) {
            throw new OidcException('DPoP requires an ES256 or RS256 private key.');
        }
        foreach (['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'] as $privateParameter) {
            if (array_key_exists($privateParameter, $publicJwk)) {
                throw new OidcException('DPoP public JWK contains private key material.');
            }
        }
        if (! isset($publicJwk['kty'])) {
            throw new OidcException('DPoP public JWK is incomplete.');
        }
    }

    public static function generateEs256(): self
    {
        if (! extension_loaded('openssl')) {
            throw new OidcException('The OpenSSL extension is required to generate a DPoP key.');
        }

        $resource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        if ($resource === false || ! openssl_pkey_export($resource, $privateKey)) {
            throw new OidcException('Unable to generate an ES256 DPoP key.');
        }

        $details = openssl_pkey_get_details($resource);
        $ec = is_array($details) && is_array($details['ec'] ?? null) ? $details['ec'] : null;
        if (! is_array($ec) || ! is_string($ec['x'] ?? null) || ! is_string($ec['y'] ?? null)) {
            throw new OidcException('Generated DPoP key is missing its public coordinates.');
        }

        return new self($privateKey, [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => self::base64Url($ec['x']),
            'y' => self::base64Url($ec['y']),
        ]);
    }

    public function publicThumbprint(): string
    {
        $canonical = json_encode([
            'crv' => $this->publicJwk['crv'] ?? null,
            'kty' => $this->publicJwk['kty'] ?? null,
            'x' => $this->publicJwk['x'] ?? null,
            'y' => $this->publicJwk['y'] ?? null,
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        return self::base64Url(hash('sha256', $canonical, true));
    }

    private static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
