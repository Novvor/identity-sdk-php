<?php

declare(strict_types=1);

namespace Novvor\IdentitySdk\Oidc;

interface LoginIntentStore
{
    public function put(LoginIntent $intent): void;

    public function get(string $handle): ?LoginIntent;

    /**
     * Atomically returns and removes the intent. Implementations shared by
     * multiple application nodes MUST use a transaction, lock, or atomic
     * compare-and-delete operation.
     */
    public function consume(string $handle): ?LoginIntent;
}
