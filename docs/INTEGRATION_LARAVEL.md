# Laravel integration

## Ownership

The SDK owns protocol construction and validation. Laravel owns configuration,
session storage, cache, redirects, logging, dependency injection and secret
retrieval.

Bind one `OidcClientConfiguration` from `config/identity.php`. Do not call
`env()` in controllers and do not provide `.test`, localhost or HTTP defaults
when `APP_ENV=production`.

Use `LoginIntentManager` with a shared, atomic `LoginIntentStore` to retain
`state`, `nonce`, `code_verifier`, the allowlisted intended destination and a
correlation ID. The browser-facing Laravel session may retain only the opaque
intent handle and a browser-session binding. Do not serialize protocol secrets,
private keys, tokens or authorization codes into a session or cookie.

## High-assurance sequence

```php
$transaction = $requests->transaction($configuration);
$intent = $loginIntents->begin(
    transaction: $transaction,
    returnPath: $allowlistedReturnPath,
    browserBinding: session()->getId(),
    correlationId: $correlationId,
);
$par = $pushed->push($configuration, $transaction, $discovery->pushedAuthorizationRequestEndpoint);

session()->put('identity.intent_handle', $intent->handle);

return redirect()->away($requests->pushedAuthorizationUrl($configuration, $par->requestUri));
```

The callback must obtain the intent handle from its server-side session,
atomically consume the intent before the code exchange, and use
`AuthorizationResponseProcessor`. It then exchanges the code with
`AuthorizationCodeClient`, validates the ID token nonce, regenerates the
Laravel session ID, binds the authenticated tenant and only then restores the
allowlisted destination. A consumed, expired or browser-binding-mismatched
intent must fail closed.

## Operational requirements

- HTTPS and certificate verification are mandatory.
- Use shared cache for one-time transaction consumption and replay detection.
- Redact tokens, assertions, codes and private keys from logs and telemetry.
- Propagate a validated correlation ID.
- Treat Identity unavailability as a bounded error surface, not a redirect
  loop.
- Readiness must verify configuration and key presence without exposing values.
- Use `novvor/identity-laravel` v2.0.1 for SDK 2.0 integrations. Do not claim
  its 2.5 contract until its durable-login-intent upgrade is published; never
  duplicate protocol orchestration in controllers.
