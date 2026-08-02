<?php

declare(strict_types=1);

namespace Novvor\IdentitySdk\Oidc;

/**
 * A non-secret, discovery-derived configuration handoff for a relying party.
 *
 * This deliberately does not write a .env file. Application configuration is
 * environment-owned and may be cached, while credentials must stay in the
 * deployment secret manager.
 */
final readonly class OidcEnvironmentTemplate
{
    /**
     * @param array<int, string> $scopes
     */
    public function __construct(
        public string $issuer,
        public string $clientId,
        public string $redirectUri,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public string $jwksUri,
        public array $scopes,
        public string $profile,
        public string $clientAuthenticationMethod,
        public ?string $userinfoEndpoint = null,
    ) {
    }

    /**
     * @return array<string, string>
     */
    public function values(): array
    {
        $values = [
            'IDENTITY_ISSUER' => $this->issuer,
            'IDENTITY_CLIENT_ID' => $this->clientId,
            'IDENTITY_REDIRECT_URI' => $this->redirectUri,
            'IDENTITY_AUTHORIZATION_ENDPOINT' => $this->authorizationEndpoint,
            'IDENTITY_TOKEN_ENDPOINT' => $this->tokenEndpoint,
            'IDENTITY_JWKS_URI' => $this->jwksUri,
            'IDENTITY_SCOPES' => implode(' ', $this->scopes),
            'IDENTITY_OIDC_PROFILE' => $this->profile,
            'IDENTITY_CLIENT_AUTH_METHOD' => $this->clientAuthenticationMethod,
        ];

        if ($this->userinfoEndpoint !== null) {
            $values['IDENTITY_USERINFO_ENDPOINT'] = $this->userinfoEndpoint;
        }

        return $values;
    }

    /**
     * Produces a copy/paste template containing only public configuration.
     * Secrets are named as deployment responsibilities, never emitted.
     */
    public function toDotenv(): string
    {
        $lines = [
            '# Generated from verified OpenID Connect Discovery metadata.',
            '# Do not commit this file. Set credentials only in the environment secret manager.',
        ];

        foreach ($this->values() as $name => $value) {
            $lines[] = $name.'='.$this->escape($value);
        }

        $lines[] = '# Required secret reference: IDENTITY_CLIENT_SECRET (or private_key_jwt key material).';

        return implode("\n", $lines)."\n";
    }

    /**
     * @return array<string, string>
     */
    public function laravelValues(string $intentCacheStore): array
    {
        $intentCacheStore = trim($intentCacheStore);
        if ($intentCacheStore === '') {
            throw new OidcException('Laravel integrations require an explicit shared OIDC intent cache store.');
        }

        $values = [
            'IDENTITY_OIDC_ISSUER' => $this->issuer,
            'IDENTITY_OIDC_CLIENT_ID' => $this->clientId,
            'IDENTITY_OIDC_REDIRECT_URI' => $this->redirectUri,
            'IDENTITY_OIDC_AUTHORIZATION_ENDPOINT' => $this->authorizationEndpoint,
            'IDENTITY_OIDC_TOKEN_ENDPOINT' => $this->tokenEndpoint,
            'IDENTITY_OIDC_JWKS_URI' => $this->jwksUri,
            'IDENTITY_OIDC_SCOPES' => implode(' ', $this->scopes),
            'IDENTITY_OIDC_PROFILE' => $this->profile,
            'IDENTITY_OIDC_CLIENT_AUTH_METHOD' => $this->clientAuthenticationMethod,
            'IDENTITY_OIDC_INTENT_CACHE_STORE' => $intentCacheStore,
        ];

        if ($this->userinfoEndpoint !== null) {
            $values['IDENTITY_OIDC_USERINFO_ENDPOINT'] = $this->userinfoEndpoint;
        }

        return $values;
    }

    /**
     * Produces the public configuration names consumed by novvor/identity-laravel.
     *
     * The cache store is intentionally an explicit argument: Discovery cannot
     * determine whether a relying party has a shared, atomic Laravel cache
     * driver configured. The caller must select a reviewed deployment store.
     */
    public function toLaravelDotenv(string $intentCacheStore): string
    {
        $lines = [
            '# Generated from verified OpenID Connect Discovery metadata for novvor/identity-laravel.',
            '# Do not commit this file. The intent cache store must be shared and atomic across application nodes.',
        ];

        foreach ($this->laravelValues($intentCacheStore) as $name => $value) {
            $lines[] = $name.'='.$this->escape($value);
        }

        if ($this->clientAuthenticationMethod === 'private_key_jwt') {
            $lines[] = '# Required secret references: IDENTITY_OIDC_PRIVATE_KEY and IDENTITY_OIDC_PRIVATE_KEY_ID.';
        } else {
            $lines[] = '# Required secret reference when this client is confidential: IDENTITY_OIDC_CLIENT_SECRET.';
        }

        return implode("\n", $lines)."\n";
    }

    private function escape(string $value): string
    {
        $escaped = str_replace(
            ["\\", '"', "\r", "\n"],
            ["\\\\", '\\"', '', ''],
            $value,
        );

        return '"'.$escaped.'"';
    }
}
