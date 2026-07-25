# Novvor Identity SDK for PHP

Official server-side relying-party SDK for Novvor Cloud Identity. It provides OIDC
discovery, Authorization Code plus PKCE, state and nonce validation, signed ID token
validation, JWKS rotation, assurance claims, and logout validation.

It is not an Identity server or an administrative API client.

## Installation

```bash
composer require novvor/identity-sdk-php
```

Use Authorization Code with PKCE for every interactive login. Persist `state`,
`nonce`, and `code_verifier` in a short-lived server-side session, validate the
returned state before exchanging the code, and pass the expected nonce to the ID
token validator. Never expose a client secret or token in browser code.

The administrative API is intentionally excluded from this package.

## Transport and correlation

All discovery, token, and JWKS requests enforce certificate and hostname
verification, reject HTTP redirects, and use bounded connect/read timeouts.
Callers may pass a safe correlation identifier as the optional final argument
to `discover`, `exchange`, and ID-token validation methods; the SDK propagates
it as `X-Correlation-ID`. The SDK rejects malformed values and never logs
authorization codes, client secrets, or tokens.

## Security

Only explicit HTTPS endpoints are accepted. JWT signing is pinned to RS256, keys
are resolved by `kid`, and issuer, audience, authorized party, nonce, time, and
back-channel logout claims are validated. Consumers must prevent replay of logout
`jti` values in their shared cache. See [`SECURITY.md`](SECURITY.md).
