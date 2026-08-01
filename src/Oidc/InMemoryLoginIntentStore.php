<?php

declare(strict_types=1);

namespace Novvor\IdentitySdk\Oidc;

/**
 * Testing/local adapter only. Production consumers must provide a durable,
 * shared implementation backed by their database or transactional cache.
 */
final class InMemoryLoginIntentStore implements LoginIntentStore
{
    /** @var array<string, LoginIntent> */
    private array $intents = [];

    public function put(LoginIntent $intent): void
    {
        if (isset($this->intents[$intent->handle])) {
            throw new OidcException('Login intent handle already exists.');
        }

        $this->intents[$intent->handle] = $intent;
    }

    public function get(string $handle): ?LoginIntent
    {
        return $this->intents[$handle] ?? null;
    }

    public function consume(string $handle): ?LoginIntent
    {
        $intent = $this->intents[$handle] ?? null;
        unset($this->intents[$handle]);

        return $intent;
    }
}
