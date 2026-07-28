<?php

namespace Novvor\IdentitySdk\Oidc;

final class AuthorizationRequestFactory
{
    /** @return array{url: string, state: string, nonce: string, code_verifier: string} */
    public function create(OidcClientConfiguration $configuration, ?string $requiredAcr = null, ?int $maxAge = null): array
    {
        $transaction = $this->transaction($configuration, $requiredAcr, $maxAge);

        return [
            'url' => $configuration->authorizationEndpoint.'?'.http_build_query($transaction->parameters),
            'state' => $transaction->state,
            'nonce' => $transaction->nonce,
            'code_verifier' => $transaction->codeVerifier,
        ];
    }

    public function transaction(OidcClientConfiguration $configuration, ?string $requiredAcr = null, ?int $maxAge = null): AuthorizationTransaction
    {
        $state = $this->randomToken();
        $nonce = $this->randomToken();
        $verifier = $this->randomToken();
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $query = array_filter([
            'response_type' => 'code',
            'client_id' => $configuration->clientId,
            'redirect_uri' => $configuration->redirectUri,
            'scope' => implode(' ', $configuration->scopes),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
            'acr_values' => $requiredAcr,
            'max_age' => $maxAge,
        ], static fn (mixed $value): bool => $value !== null && $value !== '');

        if ($configuration->profile === 'novvor-high-assurance-v1') {
            $query['response_mode'] = 'query.jwt';
        }

        return new AuthorizationTransaction($state, $nonce, $verifier, $query);
    }

    public function pushedAuthorizationUrl(OidcClientConfiguration $configuration, string $requestUri): string
    {
        if ($requestUri === '' || ! str_starts_with($requestUri, 'urn:ietf:params:oauth:request_uri:')) {
            throw new OidcException('PAR request URI is invalid.');
        }

        return $configuration->authorizationEndpoint.'?'.http_build_query([
            'client_id' => $configuration->clientId,
            'request_uri' => $requestUri,
        ]);
    }

    public function assertState(string $expectedState, string $returnedState): void
    {
        if ($expectedState === '' || $returnedState === '' || ! hash_equals($expectedState, $returnedState)) {
            throw new OidcException('OIDC state does not match the authorization session.');
        }
    }

    private function randomToken(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }
}
