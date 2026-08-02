# Laravel integration

## Ownership

The SDK owns protocol construction and validation. Laravel owns configuration,
session storage, cache, redirects, logging, dependency injection and secret
retrieval.

Bind one `OidcClientConfiguration` from `config/identity.php`. Do not call
`env()` in controllers and do not provide `.test`, localhost or HTTP defaults
when `APP_ENV=production`.

## Public configuration handoff

After validating Discovery and registering the exact redirect URI, an installer
or control-plane UI may generate copy/paste values without ever touching the
application's `.env` file:

```php
$discovery = $oidcDiscoveryClient->fetch('https://identity.example.com');
$template = $discovery->environmentTemplate(
    clientId: 'your-client-id',
    redirectUri: 'https://app.example.com/auth/oidc/callback',
);

// Display or save this as a reviewed deployment artifact, not as a secret.
$publicEnvironment = $template->toLaravelDotenv(intentCacheStore: 'redis');
```

`toLaravelDotenv()` emits the exact public variable names consumed by
`novvor/identity-laravel`, including `IDENTITY_OIDC_INTENT_CACHE_STORE`. The
store name is mandatory and supplied by the deployment owner because Discovery
cannot prove that a particular Laravel cache driver is shared and atomic. Use a
reviewed shared store such as Redis in multi-node environments.

The template contains the issuer, endpoints, client ID, redirect URI, scopes
and selected profile. It intentionally excludes client secrets and private key
material. A deployment operator must place those only in the environment's
secret manager, then run the application's configuration/readiness gate.

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
- Use an adapter release that requires `novvor/identity-sdk-php ^2.5` and
  exposes durable opaque login intents. Do not duplicate protocol
  orchestration in controllers or place PKCE, nonce, DPoP or PAR state in a
  browser session.
