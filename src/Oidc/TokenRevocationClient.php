<?php

namespace Novvor\IdentitySdk\Oidc;

use GuzzleHttp\ClientInterface;

final class TokenRevocationClient
{
    public function __construct(private readonly ClientInterface $http) {}

    public function revoke(
        OidcClientConfiguration $configuration,
        string $token,
        ?string $tokenTypeHint = null,
        ?string $correlationId = null,
    ): void {
        $endpoint = $configuration->revocationEndpoint;
        if ($endpoint === null) {
            throw new OidcException('Token revocation endpoint is not configured.');
        }
        if ($token === '') {
            throw new OidcException('A token is required for revocation.');
        }
        $form = ['token' => $token, 'client_id' => $configuration->clientId];
        if ($tokenTypeHint !== null) {
            $form['token_type_hint'] = $tokenTypeHint;
        }
        (new ClientAssertionFactory())->authenticate($configuration, $form, $endpoint);

        try {
            $response = $this->http->request('POST', $endpoint, [
                ...OidcHttpRequestOptions::strict($configuration->httpTimeoutSeconds, ['Accept' => 'application/json'], $correlationId),
                'form_params' => $form,
            ]);
        } catch (\Throwable $exception) {
            throw new OidcException('OIDC token revocation request failed.', 0, $exception);
        }
        if ($response->getStatusCode() < 200 || $response->getStatusCode() >= 300) {
            $payload = json_decode((string) $response->getBody(), true);
            throw new OAuthEndpointException(
                'OIDC token revocation endpoint rejected the request.',
                is_array($payload) && is_string($payload['error'] ?? null) ? $payload['error'] : null,
                is_array($payload) && is_string($payload['error_description'] ?? null) ? $payload['error_description'] : null,
                $response->getHeaderLine('X-Correlation-ID') ?: $correlationId,
            );
        }
    }
}
