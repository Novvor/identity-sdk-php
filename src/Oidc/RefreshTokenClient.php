<?php

namespace Novvor\IdentitySdk\Oidc;

use GuzzleHttp\ClientInterface;

final class RefreshTokenClient
{
    public function __construct(private readonly ClientInterface $http) {}

    public function rotate(
        OidcClientConfiguration $configuration,
        string $refreshToken,
        ?string $correlationId = null,
        ?DpopKey $dpopKey = null,
        ?string $dpopNonce = null,
    ): OidcTokenSet {
        if ($refreshToken === '') {
            throw new OidcException('Refresh token is required.');
        }
        if ($configuration->profile === 'novvor-high-assurance-v1' && $dpopKey === null) {
            throw new OidcException('The high-assurance profile requires a DPoP key.');
        }

        $form = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $configuration->clientId,
        ];
        (new ClientAssertionFactory())->authenticate($configuration, $form);
        $nonce = $dpopNonce;
        for ($attempt = 0; $attempt < 2; $attempt++) {
            $headers = ['Accept' => 'application/json'];
            if ($dpopKey !== null) {
                $headers['DPoP'] = (new DpopProofFactory())->create($dpopKey, 'POST', $configuration->tokenEndpoint, nonce: $nonce);
            }

            try {
                $response = $this->http->request('POST', $configuration->tokenEndpoint, [
                    ...OidcHttpRequestOptions::strict($configuration->httpTimeoutSeconds, $headers, $correlationId),
                    'form_params' => $form,
                ]);
            } catch (\Throwable $exception) {
                throw new OidcException('OIDC refresh token request failed.', 0, $exception);
            }

            $payload = OAuthJsonResponse::decode((string) $response->getBody());
            if ($response->getStatusCode() >= 200 && $response->getStatusCode() < 300 && $payload !== null) {
                break;
            }

            $challengedNonce = $dpopKey === null ? null : DpopNonceChallenge::from($response, $payload, $nonce);
            if ($attempt === 0 && $challengedNonce !== null) {
                $nonce = $challengedNonce;

                continue;
            }

            throw new OAuthEndpointException(
                'OIDC token endpoint rejected the refresh token.',
                is_string($payload['error'] ?? null) ? $payload['error'] : null,
                is_string($payload['error_description'] ?? null) ? $payload['error_description'] : null,
                $response->getHeaderLine('X-Correlation-ID') ?: $correlationId,
                $response->getHeaderLine('DPoP-Nonce') ?: null,
            );
        }

        if ($payload === null) {
            throw new OidcException('OIDC token endpoint returned an invalid refresh response.');
        }

        $tokens = TokenEndpointResponse::tokenSet($payload, false);
        if ($tokens->refreshToken === null) {
            throw new OidcException('Refresh rotation did not return a replacement refresh token.');
        }
        if ($configuration->profile === 'novvor-high-assurance-v1' && strcasecmp($tokens->tokenType, 'DPoP') !== 0) {
            throw new OidcException('The high-assurance profile requires a DPoP-bound access token.');
        }

        return $tokens;
    }
}
