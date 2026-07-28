<?php

namespace Novvor\IdentitySdk\Oidc;

final readonly class UserInfoResponse
{
    /** @param array<string, mixed> $claims */
    public function __construct(public string $subject, public array $claims) {}
}
