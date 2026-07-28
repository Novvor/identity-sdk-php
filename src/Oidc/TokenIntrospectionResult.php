<?php

namespace Novvor\IdentitySdk\Oidc;

final readonly class TokenIntrospectionResult
{
    /** @param array<string, mixed> $claims */
    public function __construct(public bool $active, public array $claims) {}
}
