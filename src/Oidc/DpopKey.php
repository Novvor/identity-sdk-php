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
}
