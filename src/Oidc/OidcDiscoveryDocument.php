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

    /**
     * @param array<int, string> $scopes
     */
    public function environmentTemplate(
        string $clientId,
        string $redirectUri,
        array $scopes = ['openid', 'profile', 'email'],
        string $profile = 'standard',
    ): OidcEnvironmentTemplate {
        if ($profile === 'novvor-high-assurance-v1' && ! $this->supportsHighAssuranceProfile()) {
            throw new OidcException('Identity Discovery does not prove the requested high-assurance profile.');
        }

        $configuration = $this->configureClient($clientId, $redirectUri);

        return new OidcEnvironmentTemplate(
            issuer: $configuration->issuer,
            clientId: $configuration->clientId,
            redirectUri: $configuration->redirectUri,
            authorizationEndpoint: $configuration->authorizationEndpoint,
            tokenEndpoint: $configuration->tokenEndpoint,
            jwksUri: $configuration->jwksUri,
            scopes: $scopes,
            profile: $profile,
            clientAuthenticationMethod: $profile === 'novvor-high-assurance-v1' ? 'private_key_jwt' : 'auto',
            userinfoEndpoint: $this->userinfoEndpoint,
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
