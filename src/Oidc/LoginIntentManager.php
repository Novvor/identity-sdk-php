<?php

declare(strict_types=1);

namespace Novvor\IdentitySdk\Oidc;

final readonly class LoginIntentManager
{
    public function __construct(
        private LoginIntentStore $store,
        private int $ttlSeconds = 600,
    ) {
        if ($ttlSeconds < 60 || $ttlSeconds > 1800) {
            throw new OidcException('Login intent TTL must be between 60 and 1800 seconds.');
        }
    }

    public function begin(
        AuthorizationTransaction $transaction,
        string $returnPath,
        string $browserBinding,
        string $correlationId,
        ?int $now = null,
    ): LoginIntent {
        $now ??= time();
        $intent = new LoginIntent(
            $this->token(),
            $transaction->state,
            $transaction->nonce,
            $transaction->codeVerifier,
            $returnPath,
            $this->fingerprint($browserBinding),
            $correlationId,
            $now,
            $now + $this->ttlSeconds,
        );
        $this->store->put($intent);

        return $intent;
    }

    public function consume(string $handle, string $browserBinding, ?int $now = null): LoginIntent
    {
        $intent = $this->store->consume($handle);
        if ($intent === null) {
            throw new OidcException('Login intent is unknown or was already consumed.');
        }
        if ($intent->isExpired($now ?? time())) {
            throw new OidcException('Login intent has expired.');
        }
        if (! hash_equals($intent->browserBinding, $this->fingerprint($browserBinding))) {
            throw new OidcException('Login intent does not belong to this browser session.');
        }
        return $intent;
    }

    private function fingerprint(string $binding): string
    {
        if ($binding === '') {
            throw new OidcException('Browser session binding is required.');
        }

        return hash('sha256', $binding);
    }

    private function token(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }
}
