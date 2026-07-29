<?php

namespace Novvor\IdentitySdk\Oidc;

use Psr\Http\Message\ResponseInterface;

final class DpopNonceChallenge
{
    /** @param array<string, mixed>|null $payload */
    public static function from(ResponseInterface $response, ?array $payload, ?string $previousNonce): ?string
    {
        if (($payload['error'] ?? null) !== 'use_dpop_nonce') {
            return null;
        }

        $nonce = $response->getHeaderLine('DPoP-Nonce');
        if ($nonce === '' || strlen($nonce) > 512 || preg_match('/[^\x21-\x7E]/', $nonce) === 1) {
            return null;
        }

        if ($previousNonce !== null && hash_equals($previousNonce, $nonce)) {
            return null;
        }

        return $nonce;
    }
}
