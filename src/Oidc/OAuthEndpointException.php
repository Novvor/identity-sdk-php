<?php

namespace Novvor\IdentitySdk\Oidc;

final class OAuthEndpointException extends \RuntimeException
{
    public function __construct(
        string $message,
        public readonly ?string $oauthError = null,
        public readonly ?string $errorDescription = null,
        public readonly ?string $correlationId = null,
        public readonly ?string $dpopNonce = null,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
