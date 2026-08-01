# Identity SDK 2.5 adoption audit

Date: 2026-07-28

## Executive verdict

The PHP core covers the relying-party protocol surface needed by Laravel and
framework-neutral backend consumers. It now includes durable, opaque login
intents so applications can keep a return destination, PKCE verifier, nonce and
state on the server under exact-once consumption semantics.

The first-party Laravel adapter exists and is released as `v2.0.1`. It uses an
encrypted Laravel session transaction and has not adopted the SDK 2.5 durable,
opaque login-intent contract. Therefore a consumer-wide Laravel upgrade to 2.5
is not releasable until the adapter is updated, tested and released.

This is `PASS_LOCAL_INTEGRATION`, not OpenID certification or production proof.

## Package boundary

| Package | Public contract | Must not contain |
|---|---|---|
| `identity-contracts` | claim names and security profiles | transport, secrets |
| `identity-sdk-php` | framework-neutral OAuth/OIDC protocol | Laravel session, admin APIs |
| `identity-laravel` | Laravel config, DI and transaction lifecycle; published `v2.0.1`, 2.5 durable-intent upgrade pending | tenant authorization policy |
| `identity-admin-sdk-php` | privileged control-plane transport | user login/session logic |
| `identity-sdk-testing` | truthful fakes and negative fixtures | real keys, tokens, customer data |

## Required consumer flow

1. Resolve an explicit canonical issuer and endpoints.
2. Discover metadata and compare the issuer exactly.
3. Validate the selected profile before browser redirect.
4. Generate state, nonce and PKCE S256.
5. For high assurance, create a per-session DPoP key and push the request with
   PAR authenticated by `private_key_jwt`.
6. Redirect using only `client_id` and the PAR `request_uri`.
7. Validate JARM RS256, RFC 9207 issuer and state.
8. Consume the one-time transaction before exchanging the code.
9. Exchange with the exact redirect URI, PKCE verifier and DPoP proof.
10. Validate ID Token issuer, audience, `azp`, signature, time and nonce.
11. Bind UserInfo `sub` to the ID Token `sub`.
12. Map tenant and permissions in the application, then regenerate its session.

Laravel consumers must use the published adapter for SDK 2.0 or one tested
application integration service. The adapter requires a 2.5 update and release
against `LoginIntentManager` before it can be treated as the consumer-wide 2.5
contract; controllers must not reconstruct this flow.

## Capability truth

| Capability | Core | Laravel integration boundary | Server evidence required |
|---|---:|---:|---|
| Authorization Code | yes | shared app service required | response type |
| PKCE S256 | yes | shared app service required | S256 metadata |
| state / nonce | yes | durable login intent required | runtime callback |
| RFC 9207 | yes | shared app service required | issuer parameter |
| PAR | yes | shared app service required | PAR endpoint |
| JARM | yes | shared app service required | query.jwt + RS256 |
| DPoP | yes | per-session ES256 key required | ES256 + DPoP token |
| private_key_jwt | yes | configured by app | registered public key |
| refresh rotation | yes | bound client | replacement refresh token |
| UserInfo | yes | subject-bound | endpoint |
| introspection/revocation | yes | bound clients | endpoints |
| DPoP nonce challenge | yes | delegated to core | `use_dpop_nonce` + `DPoP-Nonce` |
| front-channel logout | no | no | do not advertise |
| dynamic registration | no | no | use admin control plane |

## Remaining release blockers

1. Complete the 2.5 core release gate and publish an immutable `v2.5.0` tag.
2. Update, release and test the first-party Laravel adapter against durable
   `LoginIntentManager` storage; retain its current 2.0 contract until then.
3. Run a clean Composer install using tags only.
4. Validate Platform and FilaSign as reference consumers end to end.
5. Migrate Console from the v1 line as a separate, explicitly reviewed change.
6. Run negative issuer, callback replay, tenant mismatch and key-rotation tests.
7. Validate staging runtime and an external OpenID conformance profile.

No package should claim `PASS_RUNTIME` until those external gates have evidence.
