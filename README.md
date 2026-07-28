# Novvor Identity SDK for PHP

Official server-side relying-party SDK for Novvor Cloud Identity. It provides OIDC
discovery, Authorization Code plus PKCE, state and nonce validation, signed ID token
validation, JWKS rotation, assurance claims, and logout validation.

The upcoming 2.0 line also provides an opt-in high-assurance profile:
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

## Security profiles

- `standard`: interoperable OIDC relying-party behavior. Existing 1.x
  configurations remain compatible; `auto` uses `client_secret_post` only when
  a secret was supplied.
- `novvor-high-assurance-v1`: fail-closed profile requiring PAR, JARM,
  `private_key_jwt`, RFC 9207 issuer binding and a DPoP-bound access token.

Never infer high-assurance support from a successful login. Discover metadata,
run `EnterpriseProfileValidator`, store the authorization transaction
server-side, and process callbacks through `AuthorizationResponseProcessor`.
See [the Laravel integration guide](docs/INTEGRATION_LARAVEL.md).

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
