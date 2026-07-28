<?php

namespace Novvor\IdentitySdk\Oidc;

final readonly class OidcDiscoveryDocument
{
    /**
     * @param list<string> $responseModesSupported
     * @param list<string> $grantTypesSupported
     * @param list<string> $tokenEndpointAuthMethodsSupported
     * @param list<string> $dpopSigningAlgValuesSupported
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        public string $issuer,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public string $jwksUri,
        public ?string $userinfoEndpoint = null,
        public ?string $endSessionEndpoint = null,
        public ?string $pushedAuthorizationRequestEndpoint = null,
        public array $responseModesSupported = [],
        public array $grantTypesSupported = [],
        public array $tokenEndpointAuthMethodsSupported = [],
        public array $dpopSigningAlgValuesSupported = [],
        public bool $authorizationResponseIssuerParameterSupported = false,
        public array $metadata = [],
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

    public function supportsHighAssuranceProfile(): bool
    {
        return $this->pushedAuthorizationRequestEndpoint !== null
            && in_array('query.jwt', $this->responseModesSupported, true)
            && in_array('private_key_jwt', $this->tokenEndpointAuthMethodsSupported, true)
            && $this->dpopSigningAlgValuesSupported !== []
            && $this->authorizationResponseIssuerParameterSupported;
    }
}
