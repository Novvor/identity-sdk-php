<?php

namespace Novvor\IdentitySdk\Oidc;

use GuzzleHttp\ClientInterface;

final readonly class PushedAuthorizationClient
{
    public function __construct(private ClientInterface $http)
    {
    }

    public function push(
        OidcClientConfiguration $configuration,
        AuthorizationTransaction $transaction,
        string $endpoint,
        ?string $correlationId = null,
    ): PushedAuthorizationRequest {
        if (filter_var($endpoint, FILTER_VALIDATE_URL) === false || parse_url($endpoint, PHP_URL_SCHEME) !== 'https') {
            throw new OidcException('PAR endpoint must be an absolute HTTPS URL.');
        }

        $form = array_map(static fn (string|int $value): string => (string) $value, $transaction->parameters);
        (new ClientAssertionFactory())->authenticate($configuration, $form, $endpoint);

        try {
            $response = $this->http->request('POST', $endpoint, [
                ...OidcHttpRequestOptions::strict(
                    $configuration->httpTimeoutSeconds,
                    ['Accept' => 'application/json'],
                    $correlationId,
                ),
                'form_params' => $form,
            ]);
        } catch (\Throwable $exception) {
            throw new OidcException('Pushed authorization request failed.', 0, $exception);
        }

        $payload = json_decode((string) $response->getBody(), true);
        if (! in_array($response->getStatusCode(), [200, 201], true) || ! is_array($payload)) {
            throw new OidcException('Authorization server rejected the pushed authorization request.');
        }

        return new PushedAuthorizationRequest(
            is_string($payload['request_uri'] ?? null) ? $payload['request_uri'] : '',
            (int) ($payload['expires_in'] ?? 0),
        );
    }
}
