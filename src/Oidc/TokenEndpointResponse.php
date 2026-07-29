<?php

namespace Novvor\IdentitySdk\Oidc;

final class TokenEndpointResponse
{
    /** @param array<string, mixed> $payload */
    public static function tokenSet(array $payload, bool $idTokenRequired = true): OidcTokenSet
    {
        $accessToken = is_string($payload['access_token'] ?? null) ? $payload['access_token'] : '';
        $idToken = is_string($payload['id_token'] ?? null) ? $payload['id_token'] : null;
        if ($accessToken === '' || ($idTokenRequired && ($idToken === null || $idToken === ''))) {
            throw new OidcException('OIDC token response is missing required tokens.');
        }

        return new OidcTokenSet(
            accessToken: $accessToken,
            idToken: $idToken,
            refreshToken: is_string($payload['refresh_token'] ?? null) && $payload['refresh_token'] !== '' ? $payload['refresh_token'] : null,
            expiresIn: max(0, (int) ($payload['expires_in'] ?? 0)),
            tokenType: is_string($payload['token_type'] ?? null) ? $payload['token_type'] : 'Bearer',
            scope: is_string($payload['scope'] ?? null) ? $payload['scope'] : null,
        );
    }
}
