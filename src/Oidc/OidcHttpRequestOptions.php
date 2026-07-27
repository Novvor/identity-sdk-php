<?php

namespace Novvor\IdentitySdk\Oidc;

/**
 * Builds the non-negotiable transport options for OIDC protocol calls.
 *
 * Consumers may choose a custom CA bundle on their HTTP client, but protocol
 * calls can never opt out of certificate or hostname verification.
 */
final class OidcHttpRequestOptions
{
    /**
     * @param array<string, string> $headers
     * @return array<string, mixed>
     */
    public static function strict(int $timeoutSeconds, array $headers = [], ?string $correlationId = null): array
    {
        if ($timeoutSeconds < 1 || $timeoutSeconds > 30) {
            throw new OidcException('OIDC HTTP timeout must be between one and thirty seconds.');
        }

        if ($correlationId !== null) {
            $correlationId = trim($correlationId);
            if ($correlationId === '' || strlen($correlationId) > 128 || preg_match('/^[A-Za-z0-9._:-]+$/', $correlationId) !== 1) {
                throw new OidcException('OIDC correlation ID is invalid.');
            }

            $headers['X-Correlation-ID'] = $correlationId;
        }

        return [
            'timeout' => $timeoutSeconds,
            'connect_timeout' => $timeoutSeconds,
            'http_errors' => false,
            'allow_redirects' => false,
            'verify' => true,
            'headers' => $headers,
        ];
    }
}
