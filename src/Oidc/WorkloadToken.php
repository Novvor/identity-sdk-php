<?php
namespace Novvor\IdentitySdk\Oidc;
final readonly class WorkloadToken { public function __construct(public string $accessToken, public int $expiresIn, public string $scope, public string $tokenType) {} }
