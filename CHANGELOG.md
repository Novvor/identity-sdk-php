# Changelog

## Next

- Add a Discovery-derived, non-secret environment template for reviewed
  Laravel integration handoffs, including an explicit shared intent-cache
  store. The SDK never writes application `.env` files.

## 2.5.0 - 2026-08-01

- Add durable, opaque, exact-once login intents for state, nonce, PKCE verifier,
  allowlisted return paths, browser binding and correlation IDs.
- Require a shared atomic `LoginIntentStore` outside test and local-only
  experiments; the in-memory store is explicitly unsuitable for production.
- Preserve the SDK 2.0 protocol surface while aligning the 2.5 Laravel guidance
  with the published adapter's pending durable-intent upgrade.

## 2.0.0 - Unreleased

- Add typed PAR transactions and strict HTTPS transport.
- Add JARM validation pinned to RS256, exact issuer and client audience.
- Require RFC 9207 `iss` and exact `state` on authorization responses.
- Add DPoP proof creation with `htu`, `htm`, `jti`, `iat`, `ath` and nonce.
- Retry one valid RFC 9449 `use_dpop_nonce` challenge at token, refresh and
  UserInfo endpoints; repeated or malformed challenges fail closed.
- Add interactive `private_key_jwt` client authentication.
- Add typed refresh rotation, UserInfo, token introspection and revocation clients.
- Bind refresh and UserInfo requests to DPoP keys and enforce UserInfo subject matching.
- Surface OAuth errors with redacted correlation and DPoP nonce metadata.
- Add an opt-in Novvor high-assurance profile with downgrade prevention.
- Preserve 1.x secret/no-secret behavior through the `auto` compatibility mode.
- Expand Discovery parsing without advertising capabilities on behalf of the
  authorization server.

## 1.2.0 - 2026-07-27

- Add confidential workload client-credentials issuance.
- Add strict workload access-token validation for issuer, audience, client,
  authorized party, scope, expiry, not-before, token type and tenant binding.
- Add bounded clock skew and TTL-based JWKS caching.
- Refresh JWKS once when a token uses an unknown key ID, enabling safe key
  rotation while failing closed for unknown keys.
- Reject revoked, suspended or disabled workload claims.
- Add optional `private_key_jwt` client authentication. This is a client-side
  capability only and must not be enabled until the Identity token endpoint is
  confirmed to support and provision it.

## 1.0.0 - 2026-07-10

Initial private, versioned package release.
