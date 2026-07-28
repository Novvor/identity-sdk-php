# Laravel integration

## Ownership

The SDK owns protocol construction and validation. Laravel owns configuration,
session storage, cache, redirects, logging, dependency injection and secret
retrieval.

Bind one `OidcClientConfiguration` from `config/identity.php`. Do not call
`env()` in controllers and do not provide `.test`, localhost or HTTP defaults
when `APP_ENV=production`.

Persist `state`, `nonce`, `code_verifier`, the intended destination and a
correlation ID in the encrypted server-side session. Do not serialize private
keys, tokens or authorization codes into the session.

## High-assurance sequence

```php
$transaction = $requests->transaction($configuration);
$par = $pushed->push($configuration, $transaction, $discovery->pushedAuthorizationRequestEndpoint);

session()->put('identity.transaction', [
    'state' => $transaction->state,
    'nonce' => $transaction->nonce,
    'code_verifier' => $transaction->codeVerifier,
]);

return redirect()->away($requests->pushedAuthorizationUrl($configuration, $par->requestUri));
```

The callback must use `AuthorizationResponseProcessor`, consume the transaction
once, exchange the code with `AuthorizationCodeClient`, validate the ID token
nonce, regenerate the Laravel session ID, bind the authenticated tenant and
only then restore the allowlisted destination.

## Operational requirements

- HTTPS and certificate verification are mandatory.
- Use shared cache for one-time transaction consumption and replay detection.
- Redact tokens, assertions, codes and private keys from logs and telemetry.
- Propagate a validated correlation ID.
- Treat Identity unavailability as a bounded error surface, not a redirect
  loop.
- Readiness must verify configuration and key presence without exposing values.
