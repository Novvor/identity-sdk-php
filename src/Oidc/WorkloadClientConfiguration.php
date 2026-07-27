<?php

namespace Novvor\IdentitySdk\Oidc;

use InvalidArgumentException;

final readonly class WorkloadClientConfiguration
{
    /** @param list<string> $scopes */
    public function __construct(
        public string $issuer,
        public string $clientId,
        public ?string $clientSecret,
        public string $tokenEndpoint,
        public string $jwksUri,
        public string $audience,
        public array $scopes = [],
        public int $httpTimeoutSeconds = 5,
        public int $clockSkewSeconds = 30,
        public int $jwksCacheTtlSeconds = 300,
        public string $credentialMethod = 'client_secret_post',
        public ?string $privateKey = null,
        public ?string $privateKeyId = null,
    ) {
        foreach ([$issuer, $tokenEndpoint, $jwksUri] as $url) {
            if (filter_var($url, FILTER_VALIDATE_URL) === false || parse_url($url, PHP_URL_SCHEME) !== 'https') {
                throw new InvalidArgumentException('Identity SDK requires explicit HTTPS workload URLs.');
            }
        }
        if ($clientId === '' || $audience === '') {
            throw new InvalidArgumentException('Workload client and audience are required.');
        }
        if ($httpTimeoutSeconds < 1 || $httpTimeoutSeconds > 30) {
            throw new InvalidArgumentException('Identity HTTP timeout must be between one and thirty seconds.');
        }
        if ($clockSkewSeconds < 0 || $clockSkewSeconds > 120) {
            throw new InvalidArgumentException('Identity clock skew must be between zero and 120 seconds.');
        }
        if ($jwksCacheTtlSeconds < 30 || $jwksCacheTtlSeconds > 86400) {
            throw new InvalidArgumentException('Identity JWKS cache TTL must be between 30 seconds and one day.');
        }
        if (! in_array($credentialMethod, ['client_secret_post', 'private_key_jwt'], true)) {
            throw new InvalidArgumentException('Unsupported workload credential method.');
        }
        if ($credentialMethod === 'private_key_jwt' && ($privateKey === null || $privateKeyId === null)) {
            throw new InvalidArgumentException('private_key_jwt requires a private key and key id.');
        }
    }
}
