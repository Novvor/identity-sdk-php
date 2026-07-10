<?php

namespace Novvor\IdentitySdk\Oidc;

use InvalidArgumentException;

final readonly class OidcClientConfiguration
{
    public function __construct(
        public string $issuer,
        public string $clientId,
        public string $redirectUri,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public string $jwksUri,
        public ?string $clientSecret = null,
        public int $httpTimeoutSeconds = 5,
    ) {
        foreach ([$issuer, $redirectUri, $authorizationEndpoint, $tokenEndpoint, $jwksUri] as $url) {
            if (filter_var($url, FILTER_VALIDATE_URL) === false || parse_url($url, PHP_URL_SCHEME) !== 'https') {
                throw new InvalidArgumentException('Identity SDK requires explicit absolute URLs.');
            }
        }
        if ($clientId === '') {
            throw new InvalidArgumentException('Identity client ID is required.');
        }
        if ($httpTimeoutSeconds < 1 || $httpTimeoutSeconds > 30) {
            throw new InvalidArgumentException('Identity HTTP timeout must be between one and thirty seconds.');
        }
    }
}
