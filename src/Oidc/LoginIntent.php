<?php

declare(strict_types=1);

namespace Novvor\IdentitySdk\Oidc;

final readonly class LoginIntent
{
    public function __construct(
        public string $handle,
        public string $state,
        public string $nonce,
        public string $codeVerifier,
        public string $returnPath,
        public string $browserBinding,
        public string $correlationId,
        public int $createdAt,
        public int $expiresAt,
    ) {
        if (! preg_match('/^[A-Za-z0-9_-]{43,128}$/', $handle)) {
            throw new OidcException('Login intent handle is invalid.');
        }
        if ($state === '' || $nonce === '' || $codeVerifier === '') {
            throw new OidcException('Login intent protocol values are required.');
        }
        if ($returnPath === '' || $returnPath[0] !== '/' || str_starts_with($returnPath, '//')) {
            throw new OidcException('Login intent return path must be application-relative.');
        }
        if ($browserBinding === '' || $correlationId === '') {
            throw new OidcException('Login intent binding and correlation are required.');
        }
        if ($expiresAt <= $createdAt) {
            throw new OidcException('Login intent lifetime is invalid.');
        }
    }

    public function isExpired(int $now): bool
    {
        return $now >= $this->expiresAt;
    }
}
