<?php

namespace Novvor\IdentitySdk\Oidc;

final class OAuthJsonResponse
{
    /** @return array<string, mixed>|null */
    public static function decode(string $body): ?array
    {
        $payload = json_decode($body, true);
        if (! is_array($payload)) {
            return null;
        }

        $normalized = [];
        foreach ($payload as $key => $value) {
            if (is_string($key)) {
                $normalized[$key] = $value;
            }
        }

        return $normalized;
    }
}
