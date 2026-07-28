# Changelog

## 2.0.0 - Unreleased

- Add typed PAR transactions and strict HTTPS transport.
- Add JARM validation pinned to RS256, exact issuer and client audience.
- Require RFC 9207 `iss` and exact `state` on authorization responses.
- Add DPoP proof creation with `htu`, `htm`, `jti`, `iat`, `ath` and nonce.
- Add interactive `private_key_jwt` client authentication.
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
