# Identity SDK 2.0 adoption audit

Date: 2026-07-28

## Executive verdict

The PHP core now covers the relying-party protocol surface needed by Laravel
and framework-neutral backend consumers. Adoption was previously fragile
because consumers had to assemble transaction state and advanced protocol
features themselves. The official Laravel adapter now owns that orchestration.

This is `PASS_LOCAL_INTEGRATION`, not OpenID certification or production proof.

## Package boundary

| Package | Public contract | Must not contain |
|---|---|---|
| `identity-contracts` | claim names and security profiles | transport, secrets |
| `identity-sdk-php` | framework-neutral OAuth/OIDC protocol | Laravel session, admin APIs |
| `identity-laravel` | Laravel config, DI and transaction lifecycle | tenant authorization policy |
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

Laravel consumers should use `novvor/identity-laravel` rather than reproduce
these steps in controllers.

## Capability truth

| Capability | Core | Laravel adapter | Server evidence required |
|---|---:|---:|---|
| Authorization Code | yes | orchestrated | response type |
| PKCE S256 | yes | orchestrated | S256 metadata |
| state / nonce | yes | encrypted session | runtime callback |
| RFC 9207 | yes | enforced | issuer parameter |
| PAR | yes | orchestrated | PAR endpoint |
| JARM | yes | orchestrated | query.jwt + RS256 |
| DPoP | yes | per-session ES256 key | ES256 + DPoP token |
| private_key_jwt | yes | configured | registered public key |
| refresh rotation | yes | bound client | replacement refresh token |
| UserInfo | yes | subject-bound | endpoint |
| introspection/revocation | yes | bound clients | endpoints |
| DPoP nonce challenge | yes | delegated to core | `use_dpop_nonce` + `DPoP-Nonce` |
| front-channel logout | no | no | do not advertise |
| dynamic registration | no | no | use admin control plane |

## Remaining release blockers

1. Tag `identity-contracts` 2.0.
2. Tag `identity-sdk-php` 2.0.
3. Replace the Laravel adapter's temporary Draft-branch constraint with `^2.0`.
4. Tag `identity-sdk-testing` and `identity-admin-sdk-php` 2.0.
5. Run a clean Composer install using tags only.
6. Validate one Laravel reference consumer end to end.
7. Run negative issuer, callback replay, tenant mismatch and key-rotation tests.
8. Validate staging runtime and an external OpenID conformance profile.

No package should claim `PASS_RUNTIME` until those external gates have evidence.
