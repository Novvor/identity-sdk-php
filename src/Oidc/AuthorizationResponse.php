<?php

namespace Novvor\IdentitySdk\Oidc;

final readonly class AuthorizationResponse
{
    public function __construct(
        public ?string $code,
        public ?string $error,
        public ?string $errorDescription,
        public string $issuer,
        public string $state,
    ) {
    }

    public function succeeded(): bool
    {
        return $this->code !== null;
    }
}
