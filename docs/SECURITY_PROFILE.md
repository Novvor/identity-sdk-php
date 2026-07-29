# Novvor Identity SDK 2.0 security profile

## Profile contract

The `novvor-high-assurance-v1` profile is an explicit, fail-closed contract:

1. Authorization Code Flow only.
2. PKCE with S256.
3. Pushed Authorization Requests (PAR).
4. JWT Secured Authorization Response Mode (JARM, `query.jwt`).
5. RFC 9207 authorization-response issuer binding.
6. `private_key_jwt` client authentication.
7. DPoP proof at the token endpoint and a `DPoP` token type.
8. Exact redirect URI, state, nonce, issuer, audience, expiry and signing-key
   validation.

The SDK does not silently downgrade to an ordinary query response, bearer
token, shared secret, missing issuer, unknown algorithm or unknown signing key.

## Threat boundaries

| Threat | Control |
| --- | --- |
| Authorization request tampering | PAR and server-side transaction state |
| Callback mix-up | RFC 9207 exact issuer plus state |
| Response tampering | JARM RS256 signature and claims |
| Code interception | PKCE S256 |
| Client impersonation | short-lived `private_key_jwt` with unique `jti` |
| Access-token replay | DPoP proof bound to method, URI and token hash |
| Key confusion | RS256 allowlist and exact `kid` |
| Redirect abuse | exact redirect URI registered at Identity |

DPoP is defense in depth, not a replacement for TLS, strict redirect
registration, short token lifetimes or server-side replay controls.

## Key custody

The SDK accepts private key material from the host application but never
persists it. Production applications should obtain keys from their secret
manager or KMS integration, keep distinct keys per client and environment, and
rotate using overlapping public keys. No private key belongs in Git, logs,
exceptions, cache payloads or browser code.
