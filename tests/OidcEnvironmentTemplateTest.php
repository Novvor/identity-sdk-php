<?php

declare(strict_types=1);

namespace Novvor\IdentitySdk\Tests;

use Novvor\IdentitySdk\Oidc\OidcDiscoveryDocument;
use Novvor\IdentitySdk\Oidc\OidcException;
use PHPUnit\Framework\TestCase;

final class OidcEnvironmentTemplateTest extends TestCase
{
    public function test_it_generates_only_public_discovery_derived_values(): void
    {
        $template = $this->discovery()->environmentTemplate(
            clientId: 'platform-web',
            redirectUri: 'https://platform.example.com/auth/callback',
        );

        self::assertSame([
            'IDENTITY_ISSUER' => 'https://identity.example.com',
            'IDENTITY_CLIENT_ID' => 'platform-web',
            'IDENTITY_REDIRECT_URI' => 'https://platform.example.com/auth/callback',
            'IDENTITY_AUTHORIZATION_ENDPOINT' => 'https://identity.example.com/oauth/authorize',
            'IDENTITY_TOKEN_ENDPOINT' => 'https://identity.example.com/oauth/token',
            'IDENTITY_JWKS_URI' => 'https://identity.example.com/.well-known/jwks.json',
            'IDENTITY_SCOPES' => 'openid profile email',
            'IDENTITY_OIDC_PROFILE' => 'standard',
            'IDENTITY_CLIENT_AUTH_METHOD' => 'auto',
            'IDENTITY_USERINFO_ENDPOINT' => 'https://identity.example.com/oauth/userinfo',
        ], $template->values());
        self::assertStringContainsString('IDENTITY_ISSUER="https://identity.example.com"', $template->toDotenv());
        self::assertStringNotContainsString('IDENTITY_CLIENT_SECRET=', $template->toDotenv());
        self::assertStringContainsString('secret manager', $template->toDotenv());
    }

    public function test_dotenv_export_prevents_multiline_value_injection(): void
    {
        $template = $this->discovery()->environmentTemplate(
            clientId: "platform-web\nMALICIOUS_VALUE=1",
            redirectUri: 'https://platform.example.com/auth/callback',
        );

        self::assertStringContainsString('IDENTITY_CLIENT_ID="platform-webMALICIOUS_VALUE=1"', $template->toDotenv());
        self::assertStringNotContainsString("\nMALICIOUS_VALUE=1", $template->toDotenv());
    }

    public function test_laravel_export_uses_the_adapter_contract_and_requires_an_explicit_shared_store(): void
    {
        $template = $this->discovery()->environmentTemplate(
            clientId: 'platform-web',
            redirectUri: 'https://platform.example.com/auth/callback',
        );

        self::assertSame([
            'IDENTITY_OIDC_ISSUER' => 'https://identity.example.com',
            'IDENTITY_OIDC_CLIENT_ID' => 'platform-web',
            'IDENTITY_OIDC_REDIRECT_URI' => 'https://platform.example.com/auth/callback',
            'IDENTITY_OIDC_AUTHORIZATION_ENDPOINT' => 'https://identity.example.com/oauth/authorize',
            'IDENTITY_OIDC_TOKEN_ENDPOINT' => 'https://identity.example.com/oauth/token',
            'IDENTITY_OIDC_JWKS_URI' => 'https://identity.example.com/.well-known/jwks.json',
            'IDENTITY_OIDC_SCOPES' => 'openid profile email',
            'IDENTITY_OIDC_PROFILE' => 'standard',
            'IDENTITY_OIDC_CLIENT_AUTH_METHOD' => 'auto',
            'IDENTITY_OIDC_INTENT_CACHE_STORE' => 'redis',
            'IDENTITY_OIDC_USERINFO_ENDPOINT' => 'https://identity.example.com/oauth/userinfo',
        ], $template->laravelValues('redis'));
        self::assertStringContainsString('IDENTITY_OIDC_INTENT_CACHE_STORE="redis"', $template->toLaravelDotenv('redis'));
        self::assertStringNotContainsString('IDENTITY_OIDC_CLIENT_SECRET=', $template->toLaravelDotenv('redis'));

        $this->expectException(OidcException::class);
        $template->laravelValues('  ');
    }

    public function test_high_assurance_template_requires_discovery_proof(): void
    {
        $this->expectException(OidcException::class);

        (new OidcDiscoveryDocument(
            issuer: 'https://identity.example.com',
            authorizationEndpoint: 'https://identity.example.com/oauth/authorize',
            tokenEndpoint: 'https://identity.example.com/oauth/token',
            jwksUri: 'https://identity.example.com/.well-known/jwks.json',
        ))->environmentTemplate('platform-web', 'https://platform.example.com/auth/callback', profile: 'novvor-high-assurance-v1');
    }

    private function discovery(): OidcDiscoveryDocument
    {
        return new OidcDiscoveryDocument(
            issuer: 'https://identity.example.com',
            authorizationEndpoint: 'https://identity.example.com/oauth/authorize',
            tokenEndpoint: 'https://identity.example.com/oauth/token',
            jwksUri: 'https://identity.example.com/.well-known/jwks.json',
            userinfoEndpoint: 'https://identity.example.com/oauth/userinfo',
            pushedAuthorizationRequestEndpoint: 'https://identity.example.com/oauth/par',
            responseModesSupported: ['query.jwt'],
            tokenEndpointAuthMethodsSupported: ['private_key_jwt'],
            dpopSigningAlgValuesSupported: ['ES256'],
            authorizationResponseIssuerParameterSupported: true,
        );
    }
}
