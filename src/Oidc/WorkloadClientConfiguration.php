<?php

namespace Novvor\IdentitySdk\Oidc;

use InvalidArgumentException;

final readonly class WorkloadClientConfiguration
{
    /** @param list<string> $scopes */
    public function __construct(public string $issuer, public string $clientId, public ?string $clientSecret, public string $tokenEndpoint, public string $jwksUri, public string $audience, public array $scopes = [], public int $httpTimeoutSeconds = 5)
    {
        foreach ([$issuer, $tokenEndpoint, $jwksUri] as $url) if (filter_var($url, FILTER_VALIDATE_URL) === false || parse_url($url, PHP_URL_SCHEME) !== 'https') throw new InvalidArgumentException('Identity SDK requires explicit HTTPS workload URLs.');
        if ($clientId === '' || $audience === '') throw new InvalidArgumentException('Workload client and audience are required.');
        if ($httpTimeoutSeconds < 1 || $httpTimeoutSeconds > 30) throw new InvalidArgumentException('Identity HTTP timeout must be between one and thirty seconds.');
    }
}
