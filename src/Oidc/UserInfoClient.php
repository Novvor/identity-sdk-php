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
        $nonce = $dpopNonce;
        for ($attempt = 0; $attempt < 2; $attempt++) {
            $headers = [
                'Accept' => 'application/json',
                'Authorization' => ($isDpop ? 'DPoP' : 'Bearer').' '.$accessToken,
            ];
            if ($dpopKey !== null) {
                $headers['DPoP'] = (new DpopProofFactory())->create($dpopKey, 'GET', $endpoint, $accessToken, $nonce);
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
            $claims = OAuthJsonResponse::decode((string) $response->getBody());
            $subject = $claims['sub'] ?? null;
            if ($response->getStatusCode() === 200 && is_string($subject) && $subject !== '') {
                break;
            }

            $challengedNonce = $dpopKey === null ? null : DpopNonceChallenge::from($response, $claims, $nonce);
            if ($attempt === 0 && $challengedNonce !== null) {
                $nonce = $challengedNonce;

                continue;
            }

            throw new OAuthEndpointException(
                'OIDC UserInfo endpoint rejected the access token.',
                is_string($claims['error'] ?? null) ? $claims['error'] : null,
                is_string($claims['error_description'] ?? null) ? $claims['error_description'] : null,
                $response->getHeaderLine('X-Correlation-ID') ?: $correlationId,
                $response->getHeaderLine('DPoP-Nonce') ?: null,
            );
        }

        if ($claims === null || ! is_string($claims['sub'] ?? null) || $claims['sub'] === '') {
            throw new OidcException('OIDC UserInfo endpoint returned an invalid response.');
        }

        $subject = $claims['sub'];
        if ($expectedSubject !== null && ! hash_equals($expectedSubject, $subject)) {
            throw new OidcException('UserInfo subject does not match the ID token subject.');
        }

        return new UserInfoResponse($subject, $claims);
    }
}
