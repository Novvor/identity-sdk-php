<?php

namespace Novvor\IdentitySdk\Oidc;

use Firebase\JWT\JWT;

final class ClientAssertionFactory
{
    public function create(OidcClientConfiguration $configuration, ?int $now = null): string
    {
        if ($configuration->clientAuthenticationMethod !== 'private_key_jwt') {
            throw new OidcException('Client is not configured for private_key_jwt.');
        }

        $now ??= time();

        return JWT::encode([
            'iss' => $configuration->clientId,
            'sub' => $configuration->clientId,
            'aud' => $configuration->tokenEndpoint,
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + 60,
            'jti' => bin2hex(random_bytes(16)),
        ], (string) $configuration->privateKey, 'RS256', $configuration->privateKeyId);
    }

    /** @param array<string, string> $form */
    public function authenticate(OidcClientConfiguration $configuration, array &$form): void
    {
        $method = $configuration->clientAuthenticationMethod;
        if ($method === 'auto') {
            $method = ($configuration->clientSecret ?? '') !== '' ? 'client_secret_post' : 'none';
        }

        if ($method === 'none') {
            return;
        }
        if ($method === 'client_secret_post') {
            $form['client_secret'] = (string) $configuration->clientSecret;

            return;
        }

        $form['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        $form['client_assertion'] = $this->create($configuration);
    }
}
