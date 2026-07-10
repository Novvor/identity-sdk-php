<?php

namespace Novvor\IdentitySdk\Oidc;

final class BackChannelLogoutValidator
{
    public function __construct(private readonly IdTokenValidator $idTokens)
    {
    }

    /** @return array<string, mixed> */
    public function validate(OidcClientConfiguration $configuration, string $logoutToken): array
    {
        if ($logoutToken === '') {
            throw new OidcException('Back-channel logout token is required.');
        }

        $claims = $this->idTokens->validate($configuration, $logoutToken);
        $events = $claims['events'] ?? null;
        $logoutEvent = 'http://schemas.openid.net/event/backchannel-logout';
        if (! is_array($events) || ! array_key_exists($logoutEvent, $events)) {
            throw new OidcException('JWT is not a back-channel logout token.');
        }
        if (trim((string) ($claims['sid'] ?? '')) === '' && trim((string) ($claims['sub'] ?? '')) === '') {
            throw new OidcException('Back-channel logout token is missing sid and sub.');
        }

        return $claims;
    }
}
