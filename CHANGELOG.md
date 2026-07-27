# Changelog

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
