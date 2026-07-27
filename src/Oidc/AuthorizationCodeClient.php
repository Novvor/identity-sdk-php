<?php

namespace Novvor\IdentitySdk\Oidc;

use GuzzleHttp\ClientInterface;

final class AuthorizationCodeClient
{
    public function __construct(private readonly ClientInterface $http)
    {
    }

    public function exchange(OidcClientConfiguration $configuration, string $code, string $codeVerifier, ?string $correlationId = null): OidcTokenSet
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
        if ($configuration->clientSecret !== null && $configuration->clientSecret !== '') {
            $form['client_secret'] = $configuration->clientSecret;
        }

        try {
            $response = $this->http->request('POST', $configuration->tokenEndpoint, [
                ...OidcHttpRequestOptions::strict(
                    $configuration->httpTimeoutSeconds,
                    ['Accept' => 'application/json'],
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

        $accessToken = is_string($payload['access_token'] ?? null) ? $payload['access_token'] : '';
        $idToken = is_string($payload['id_token'] ?? null) ? $payload['id_token'] : '';
        if ($accessToken === '' || $idToken === '') {
            throw new OidcException('OIDC token response is missing an access token or ID token.');
        }

        return new OidcTokenSet(
            accessToken: $accessToken,
            idToken: $idToken,
            refreshToken: is_string($payload['refresh_token'] ?? null) ? $payload['refresh_token'] : null,
            expiresIn: max(0, (int) ($payload['expires_in'] ?? 0)),
            tokenType: is_string($payload['token_type'] ?? null) ? $payload['token_type'] : 'Bearer',
        );
    }
}
