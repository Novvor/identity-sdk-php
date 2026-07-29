<?php

namespace Novvor\IdentitySdk\Oidc;

final readonly class AuthorizationResponseProcessor
{
    public function __construct(private ?JarmAuthorizationResponseValidator $jarm = null)
    {
    }

    /** @param array<string, mixed> $parameters */
    public function process(
        OidcClientConfiguration $configuration,
        array $parameters,
        string $expectedState,
        ?string $correlationId = null,
    ): AuthorizationResponse {
        if ($configuration->profile === 'novvor-high-assurance-v1' && ! is_string($parameters['response'] ?? null)) {
            throw new OidcException('The high-assurance profile requires a JARM authorization response.');
        }
        if (is_string($parameters['response'] ?? null)) {
            if ($this->jarm === null) {
                throw new OidcException('JARM response received without a configured validator.');
            }

            $parameters = $this->jarm->validate($configuration, $parameters['response'], $correlationId);
        }

        $state = is_string($parameters['state'] ?? null) ? $parameters['state'] : '';
        $issuer = is_string($parameters['iss'] ?? null) ? rtrim($parameters['iss'], '/') : '';
        if ($state === '' || ! hash_equals($expectedState, $state)) {
            throw new OidcException('Authorization response state does not match the transaction.');
        }
        if ($issuer === '' || ! hash_equals(rtrim($configuration->issuer, '/'), $issuer)) {
            throw new OidcException('Authorization response issuer does not match discovery.');
        }

        $code = is_string($parameters['code'] ?? null) && $parameters['code'] !== '' ? $parameters['code'] : null;
        $error = is_string($parameters['error'] ?? null) && $parameters['error'] !== '' ? $parameters['error'] : null;
        if (($code === null) === ($error === null)) {
            throw new OidcException('Authorization response must contain exactly one code or error.');
        }

        return new AuthorizationResponse(
            $code,
            $error,
            is_string($parameters['error_description'] ?? null) ? $parameters['error_description'] : null,
            $issuer,
            $state,
        );
    }
}
