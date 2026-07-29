<?php

namespace Novvor\IdentitySdk\Oidc;

final class EnterpriseProfileValidator
{
    public function assertSupported(OidcClientConfiguration $configuration, OidcDiscoveryDocument $discovery): void
    {
        if ($configuration->profile !== 'novvor-high-assurance-v1') {
            return;
        }
        if (! $discovery->supportsHighAssuranceProfile()) {
            throw new OidcException('Identity provider does not prove the Novvor high-assurance profile.');
        }
    }
}
