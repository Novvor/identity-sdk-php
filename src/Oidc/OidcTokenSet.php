<?php

namespace Novvor\IdentitySdk\Oidc;

final readonly class OidcTokenSet
{
    public function __construct(
        public string $accessToken,
        public ?string $idToken,
        public ?string $refreshToken,
        public int $expiresIn,
        public string $tokenType,
        public ?string $scope = null,
    ) {
    }
}
