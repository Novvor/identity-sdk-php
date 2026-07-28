<?php

namespace Novvor\IdentitySdk\Oidc;

use GuzzleHttp\ClientInterface;

final class AuthorizationCodeClient
{
    public function __construct(private readonly ClientInterface $http)
    {
    }

    public function exchange(
        OidcClientConfiguration $configuration,
        string $code,
        string $codeVerifier,
        ?string $correlationId = null,
        ?DpopKey $dpopKey = null,
        ?string $dpopNonce = null,
    ): OidcTokenSet
    {
        if ($code === '' || $codeVerifier === '') {
            throw new OidcException('Authorization code and PKCE verifier are required.');
        }

        $form = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $configuration->redirectUri,
            'client_id' => $configuration->clientId,
            'code_verifier' => $codeVerifier,
        ];
        (new ClientAssertionFactory())->authenticate($configuration, $form);

        $headers = ['Accept' => 'application/json'];
        if ($dpopKey !== null) {
            $headers['DPoP'] = (new DpopProofFactory())->create($dpopKey, 'POST', $configuration->tokenEndpoint, nonce: $dpopNonce);
        }
        if ($configuration->profile === 'novvor-high-assurance-v1' && $dpopKey === null) {
            throw new OidcException('The high-assurance profile requires a DPoP key.');
        }

        try {
            $response = $this->http->request('POST', $configuration->tokenEndpoint, [
                ...OidcHttpRequestOptions::strict(
                    $configuration->httpTimeoutSeconds,
                    $headers,
                    $correlationId,
                ),
                'form_params' => $form,
            ]);
        } catch (\Throwable $exception) {
            throw new OidcException('OIDC token exchange failed.', 0, $exception);
        }

        $payload = json_decode((string) $response->getBody(), true);
        if ($response->getStatusCode() < 200 || $response->getStatusCode() >= 300 || ! is_array($payload)) {
            throw new OidcException('OIDC token endpoint rejected the authorization code.');
        }

        $tokenSet = TokenEndpointResponse::tokenSet($payload);
        $tokenType = $tokenSet->tokenType;
        if ($configuration->profile === 'novvor-high-assurance-v1' && strcasecmp($tokenType, 'DPoP') !== 0) {
            throw new OidcException('The high-assurance profile requires a DPoP-bound access token.');
        }

        return $tokenSet;
    }
}
