<?php

namespace Novvor\IdentitySdk\Oidc;

use GuzzleHttp\ClientInterface;

final class TokenIntrospectionClient
{
    public function __construct(private readonly ClientInterface $http) {}

    public function introspect(
        OidcClientConfiguration $configuration,
        string $token,
        ?string $tokenTypeHint = null,
        ?string $correlationId = null,
    ): TokenIntrospectionResult {
        $endpoint = $configuration->introspectionEndpoint;
        if ($endpoint === null) {
            throw new OidcException('Token introspection endpoint is not configured.');
        }
        if ($token === '') {
            throw new OidcException('A token is required for introspection.');
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
            throw new OidcException('OIDC token introspection request failed.', 0, $exception);
        }
        $payload = json_decode((string) $response->getBody(), true);
        if ($response->getStatusCode() !== 200 || ! is_array($payload) || ! is_bool($payload['active'] ?? null)) {
            throw new OAuthEndpointException(
                'OIDC token introspection endpoint rejected the request.',
                is_array($payload) && is_string($payload['error'] ?? null) ? $payload['error'] : null,
                is_array($payload) && is_string($payload['error_description'] ?? null) ? $payload['error_description'] : null,
                $response->getHeaderLine('X-Correlation-ID') ?: $correlationId,
            );
        }

        return new TokenIntrospectionResult($payload['active'], $payload);
    }
}
