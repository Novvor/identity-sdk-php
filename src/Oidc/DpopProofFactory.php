<?php

namespace Novvor\IdentitySdk\Oidc;

use Firebase\JWT\JWT;

final class DpopProofFactory
{
    public function create(
        DpopKey $key,
        string $method,
        string $uri,
        ?string $accessToken = null,
        ?string $nonce = null,
        ?int $now = null,
    ): string {
        $method = strtoupper(trim($method));
        $scheme = parse_url($uri, PHP_URL_SCHEME);
        $host = parse_url($uri, PHP_URL_HOST);
        if ($method === '' || $scheme !== 'https' || ! is_string($host) || $host === '') {
            throw new OidcException('DPoP proof requires an HTTPS target and HTTP method.');
        }
        $port = parse_url($uri, PHP_URL_PORT);
        $path = parse_url($uri, PHP_URL_PATH) ?: '/';
        $htu = strtolower($scheme).'://'.strtolower($host).($port === null ? '' : ':'.$port).$path;
        $claims = [
            'jti' => bin2hex(random_bytes(16)),
            'htm' => $method,
            'htu' => $htu,
            'iat' => $now ?? time(),
        ];
        if ($accessToken !== null && $accessToken !== '') {
            $claims['ath'] = rtrim(strtr(base64_encode(hash('sha256', $accessToken, true)), '+/', '-_'), '=');
        }
        if ($nonce !== null && $nonce !== '') {
            $claims['nonce'] = $nonce;
        }

        return JWT::encode($claims, $key->privateKey, $key->algorithm, null, [
            'typ' => 'dpop+jwt',
            'jwk' => $key->publicJwk,
        ]);
    }
}
