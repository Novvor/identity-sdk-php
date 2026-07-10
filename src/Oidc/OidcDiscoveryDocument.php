<?php

namespace Novvor\IdentitySdk\Oidc;

final readonly class OidcDiscoveryDocument
{
    public function __construct(
        public string $issuer,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public string $jwksUri,
        public ?string $userinfoEndpoint = null,
        public ?string $endSessionEndpoint = null,
    ) {
    }

    public function configureClient(string $clientId, string $redirectUri, ?string $clientSecret = null, int $timeoutSeconds = 5): OidcClientConfiguration
    {
        return new OidcClientConfiguration(
            issuer: $this->issuer,
            clientId: $clientId,
            redirectUri: $redirectUri,
            authorizationEndpoint: $this->authorizationEndpoint,
            tokenEndpoint: $this->tokenEndpoint,
            jwksUri: $this->jwksUri,
            clientSecret: $clientSecret,
            httpTimeoutSeconds: $timeoutSeconds,
        );
    }
}
