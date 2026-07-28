<?php

namespace Novvor\IdentitySdk\Oidc;

final readonly class AuthorizationTransaction
{
    /** @param array<string, string|int> $parameters */
    public function __construct(
        public string $state,
        public string $nonce,
        public string $codeVerifier,
        public array $parameters,
    ) {
    }

    /** @return array{state:string,nonce:string,code_verifier:string,parameters:array<string,string|int>} */
    public function toArray(): array
    {
        return [
            'state' => $this->state,
            'nonce' => $this->nonce,
            'code_verifier' => $this->codeVerifier,
            'parameters' => $this->parameters,
        ];
    }
}
