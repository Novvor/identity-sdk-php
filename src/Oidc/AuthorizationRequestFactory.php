<?php

namespace Novvor\IdentitySdk\Oidc;

final class AuthorizationRequestFactory
{
    /** @return array{url: string, state: string, nonce: string, code_verifier: string} */
    public function create(OidcClientConfiguration $configuration, ?string $requiredAcr = null, ?int $maxAge = null): array
    {
        $state = $this->randomToken();
        $nonce = $this->randomToken();
        $verifier = $this->randomToken();
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $query = array_filter([
            'response_type' => 'code',
            'client_id' => $configuration->clientId,
            'redirect_uri' => $configuration->redirectUri,
            'scope' => 'openid profile email',
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
            'acr_values' => $requiredAcr,
            'max_age' => $maxAge,
        ], static fn (mixed $value): bool => $value !== null && $value !== '');

        return ['url' => $configuration->authorizationEndpoint.'?'.http_build_query($query), 'state' => $state, 'nonce' => $nonce, 'code_verifier' => $verifier];
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
