<?php

namespace Novvor\IdentitySdk\Oidc;

final readonly class PushedAuthorizationRequest
{
    public function __construct(public string $requestUri, public int $expiresIn)
    {
        if ($requestUri === '' || $expiresIn < 1) {
            throw new OidcException('PAR response is missing a valid request_uri or expires_in.');
        }
    }
}
