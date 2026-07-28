<?php

namespace Novvor\IdentitySdk\Oidc;

use InvalidArgumentException;

final readonly class OidcClientConfiguration
{
    /** @param list<string> $scopes */
    public function __construct(
        public string $issuer,
        public string $clientId,
        public string $redirectUri,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public string $jwksUri,
        public ?string $clientSecret = null,
        public int $httpTimeoutSeconds = 5,
        public string $clientAuthenticationMethod = 'auto',
        public ?string $privateKey = null,
        public ?string $privateKeyId = null,
        public array $scopes = ['openid', 'profile', 'email'],
        public string $profile = 'standard',
    ) {
        foreach ([$issuer, $redirectUri, $authorizationEndpoint, $tokenEndpoint, $jwksUri] as $url) {
            if (filter_var($url, FILTER_VALIDATE_URL) === false || parse_url($url, PHP_URL_SCHEME) !== 'https') {
                throw new InvalidArgumentException('Identity SDK requires explicit absolute URLs.');
            }
        }
        if ($clientId === '') {
            throw new InvalidArgumentException('Identity client ID is required.');
        }
        if ($httpTimeoutSeconds < 1 || $httpTimeoutSeconds > 30) {
            throw new InvalidArgumentException('Identity HTTP timeout must be between one and thirty seconds.');
        }
        if (! in_array($clientAuthenticationMethod, ['auto', 'none', 'client_secret_post', 'private_key_jwt'], true)) {
            throw new InvalidArgumentException('Unsupported OIDC client authentication method.');
        }
        if ($clientAuthenticationMethod === 'client_secret_post' && ($clientSecret === null || $clientSecret === '')) {
            throw new InvalidArgumentException('client_secret_post requires a client secret.');
        }
        if ($clientAuthenticationMethod === 'private_key_jwt' && (($privateKey ?? '') === '' || ($privateKeyId ?? '') === '')) {
            throw new InvalidArgumentException('private_key_jwt requires a private key and key ID.');
        }
        if ($scopes === [] || in_array('openid', $scopes, true) === false) {
            throw new InvalidArgumentException('OIDC scopes must include openid.');
        }
        if (! in_array($profile, ['standard', 'novvor-high-assurance-v1'], true)) {
            throw new InvalidArgumentException('Unsupported OIDC security profile.');
        }
        if ($profile === 'novvor-high-assurance-v1' && $clientAuthenticationMethod !== 'private_key_jwt') {
            throw new InvalidArgumentException('The Novvor high-assurance profile requires private_key_jwt.');
        }
    }
}
