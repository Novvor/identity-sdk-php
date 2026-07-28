<?php

namespace Novvor\IdentitySdk\Oidc;

use GuzzleHttp\ClientInterface;

final class UserInfoClient
{
    public function __construct(private readonly ClientInterface $http) {}

    public function fetch(
        OidcClientConfiguration $configuration,
        string $accessToken,
        string $tokenType = 'Bearer',
        ?string $expectedSubject = null,
        ?string $correlationId = null,
        ?DpopKey $dpopKey = null,
        ?string $dpopNonce = null,
    ): UserInfoResponse {
        $endpoint = $configuration->userinfoEndpoint;
        if ($endpoint === null) {
            throw new OidcException('UserInfo endpoint is not configured.');
        }
        if ($accessToken === '') {
            throw new OidcException('UserInfo requires an access token.');
        }
        $isDpop = strcasecmp($tokenType, 'DPoP') === 0;
        if ($isDpop && $dpopKey === null) {
            throw new OidcException('A DPoP-bound token requires its DPoP key.');
        }
        $headers = [
            'Accept' => 'application/json',
            'Authorization' => ($isDpop ? 'DPoP' : 'Bearer').' '.$accessToken,
        ];
        if ($dpopKey !== null) {
            $headers['DPoP'] = (new DpopProofFactory())->create($dpopKey, 'GET', $endpoint, $accessToken, $dpopNonce);
        }

        try {
            $response = $this->http->request('GET', $endpoint, OidcHttpRequestOptions::strict(
                $configuration->httpTimeoutSeconds,
                $headers,
                $correlationId,
            ));
        } catch (\Throwable $exception) {
            throw new OidcException('OIDC UserInfo request failed.', 0, $exception);
        }
        $claims = json_decode((string) $response->getBody(), true);
        if ($response->getStatusCode() !== 200 || ! is_array($claims) || ! is_string($claims['sub'] ?? null) || $claims['sub'] === '') {
            throw new OAuthEndpointException(
                'OIDC UserInfo endpoint rejected the access token.',
                is_array($claims) && is_string($claims['error'] ?? null) ? $claims['error'] : null,
                is_array($claims) && is_string($claims['error_description'] ?? null) ? $claims['error_description'] : null,
                $response->getHeaderLine('X-Correlation-ID') ?: $correlationId,
                $response->getHeaderLine('DPoP-Nonce') ?: null,
            );
        }
        if ($expectedSubject !== null && ! hash_equals($expectedSubject, $claims['sub'])) {
            throw new OidcException('UserInfo subject does not match the ID token subject.');
        }

        return new UserInfoResponse($claims['sub'], $claims);
    }
}
