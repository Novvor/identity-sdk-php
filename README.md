# Novvor Identity SDK for PHP

Official server-side relying-party SDK for Novvor Cloud Identity. It provides OIDC
discovery, Authorization Code plus PKCE, state and nonce validation, signed ID token
validation, JWKS rotation, assurance claims, and logout validation.

The 2.x line provides an opt-in high-assurance profile:
Authorization Code + PKCE S256 + PAR + JARM + RFC 9207 + DPoP +
`private_key_jwt`. It is designed for government and regulated enterprise
integrations without weakening the interoperable standard profile.

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

## Durable login intents (SDK 2.5)

`LoginIntentManager` preserves the internal application destination together
with `state`, `nonce`, and the PKCE verifier under an opaque, one-time handle.
Production applications must implement `LoginIntentStore` using a shared,
transactional database or cache. Cookies and callback query strings carry only
the opaque handle; they are never the authority for the return destination.

The included `InMemoryLoginIntentStore` exists only for tests and local
experiments. It is intentionally unsuitable for multiple processes or nodes.

## Security profiles

- `standard`: interoperable OIDC relying-party behavior. Existing 1.x
  configurations remain compatible; `auto` uses `client_secret_post` only when
  a secret was supplied.
- `novvor-high-assurance-v1`: fail-closed profile requiring PAR, JARM,
  `private_key_jwt`, RFC 9207 issuer binding and a DPoP-bound access token.

Token, refresh and UserInfo clients automatically answer one valid RFC 9449
`use_dpop_nonce` challenge. Repeated, unchanged, malformed or oversized nonce
challenges fail closed, so a broken server cannot create an unbounded retry
loop.

Never infer high-assurance support from a successful login. Discover metadata,
run `EnterpriseProfileValidator`, store the authorization transaction
server-side, and process callbacks through `AuthorizationResponseProcessor`.
See [the Laravel integration guide](docs/INTEGRATION_LARAVEL.md).
There is not yet a published first-party Laravel adapter package. Laravel
applications must keep protocol orchestration in a tested application adapter
that follows [the Laravel integration guide](docs/INTEGRATION_LARAVEL.md), not
in controllers. The cross-package adoption audit and 2.5 release gates are in
[`docs/SDK_2_ADOPTION_AUDIT.md`](docs/SDK_2_ADOPTION_AUDIT.md) and
[`docs/RELEASE_2_5_PLAN.md`](docs/RELEASE_2_5_PLAN.md).

## Workload authentication

`ClientCredentialsClient` issues server-to-server access tokens using the
currently supported `client_secret_post` method. `WorkloadAccessTokenValidator`
validates the token at the receiving service and refreshes cached JWKS once for
an unknown `kid`.

`WorkloadClientConfiguration` can prepare `private_key_jwt`, but consumers must
not enable that method unless the Identity server advertises and provisions it.
The SDK does not imply that server-side support exists.

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
The capability truth table and downgrade boundaries are documented in
[`docs/SECURITY_PROFILE.md`](docs/SECURITY_PROFILE.md).
