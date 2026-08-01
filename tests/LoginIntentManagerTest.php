<?php

declare(strict_types=1);

namespace Novvor\IdentitySdk\Tests;

use Novvor\IdentitySdk\Oidc\AuthorizationTransaction;
use Novvor\IdentitySdk\Oidc\InMemoryLoginIntentStore;
use Novvor\IdentitySdk\Oidc\LoginIntentManager;
use Novvor\IdentitySdk\Oidc\OidcException;
use PHPUnit\Framework\TestCase;

final class LoginIntentManagerTest extends TestCase
{
    public function test_stores_protocol_state_and_internal_destination_server_side(): void
    {
        $store = new InMemoryLoginIntentStore();
        $manager = new LoginIntentManager($store, 600);
        $intent = $manager->begin($this->transaction(), '/manage/dashboard?tab=security', 'session-secret', 'correlation-1', 1000);

        self::assertSame('/manage/dashboard?tab=security', $intent->returnPath);
        self::assertNotSame('session-secret', $intent->browserBinding);
        self::assertSame($intent, $store->get($intent->handle));
    }

    public function test_consumes_exactly_once_and_checks_browser_binding(): void
    {
        $manager = new LoginIntentManager(new InMemoryLoginIntentStore());
        $intent = $manager->begin($this->transaction(), '/admin', 'browser-a', 'correlation-1', 1000);

        self::assertSame($intent->handle, $manager->consume($intent->handle, 'browser-a', 1001)->handle);

        $this->expectException(OidcException::class);
        $manager->consume($intent->handle, 'browser-a', 1002);
    }

    public function test_binding_mismatch_fails_closed_and_burns_intent(): void
    {
        $manager = new LoginIntentManager(new InMemoryLoginIntentStore());
        $intent = $manager->begin($this->transaction(), '/admin', 'browser-a', 'correlation-1', 1000);

        try {
            $manager->consume($intent->handle, 'attacker', 1001);
            self::fail('A mismatched browser binding must fail.');
        } catch (OidcException $exception) {
            self::assertSame('Login intent does not belong to this browser session.', $exception->getMessage());
        }

        $this->expectException(OidcException::class);
        $manager->consume($intent->handle, 'browser-a', 1002);
    }

    public function test_expired_intent_fails_closed(): void
    {
        $manager = new LoginIntentManager(new InMemoryLoginIntentStore(), 60);
        $intent = $manager->begin($this->transaction(), '/admin', 'browser-a', 'correlation-1', 1000);

        $this->expectException(OidcException::class);
        $manager->consume($intent->handle, 'browser-a', 1060);
    }

    public function test_rejects_external_return_urls(): void
    {
        $this->expectException(OidcException::class);
        (new LoginIntentManager(new InMemoryLoginIntentStore()))
            ->begin($this->transaction(), 'https://attacker.example', 'browser-a', 'correlation-1');
    }

    private function transaction(): AuthorizationTransaction
    {
        return new AuthorizationTransaction('state', 'nonce', str_repeat('v', 43), ['client_id' => 'client']);
    }
}
