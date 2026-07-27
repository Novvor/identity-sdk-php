<?php

namespace Novvor\IdentitySdk\Oidc;

use Firebase\JWT\JWT;
use GuzzleHttp\ClientInterface;

final class ClientCredentialsClient
{
    public function __construct(private readonly ClientInterface $http) {}

    public function issue(WorkloadClientConfiguration $configuration, ?string $correlationId = null): WorkloadToken
    {
        $form = [
            'grant_type' => 'client_credentials',
            'client_id' => $configuration->clientId,
            'audience' => $configuration->audience,
            'scope' => implode(' ', $configuration->scopes),
        ];
        if ($configuration->credentialMethod === 'client_secret_post') {
            if ($configuration->clientSecret === null || $configuration->clientSecret === '') {
                throw new OidcException('Identity workload client secret is required to issue a token.');
            }
            $form['client_secret'] = $configuration->clientSecret;
        } else {
            $now = time();
            $form['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
            $form['client_assertion'] = JWT::encode([
                'iss' => $configuration->clientId,
                'sub' => $configuration->clientId,
                'aud' => $configuration->tokenEndpoint,
                'iat' => $now,
                'exp' => $now + 60,
                'jti' => bin2hex(random_bytes(16)),
            ], (string) $configuration->privateKey, 'RS256', $configuration->privateKeyId);
        }
        try {
            $response = $this->http->request('POST', $configuration->tokenEndpoint, [
                ...OidcHttpRequestOptions::strict($configuration->httpTimeoutSeconds, ['Accept' => 'application/json'], $correlationId),
                'form_params' => $form,
            ]);
        } catch (\Throwable $exception) {
            throw new OidcException('Identity workload token request failed.', 0, $exception);
        }
        $payload = json_decode((string) $response->getBody(), true);
        if ($response->getStatusCode() < 200 || $response->getStatusCode() >= 300 || ! is_array($payload) || ! is_string($payload['access_token'] ?? null) || $payload['access_token'] === '') {
            throw new OidcException('Identity workload token endpoint rejected the client.');
        }
        if (strcasecmp((string) ($payload['token_type'] ?? 'Bearer'), 'Bearer') !== 0) {
            throw new OidcException('Identity workload token type is invalid.');
        }

        return new WorkloadToken($payload['access_token'], max(0, (int) ($payload['expires_in'] ?? 0)), (string) ($payload['scope'] ?? ''), 'Bearer');
    }
}
