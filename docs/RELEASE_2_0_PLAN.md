# Identity SDK 2.0 release plan

## Version and publication order

1. `novvor/identity-contracts` 2.0.0
2. `novvor/identity-sdk-php` 2.0.0
3. `novvor/identity-sdk-testing` 2.0.0
4. `novvor/identity-admin-sdk-php` 2.0.0
5. `novvor/identity-laravel` 2.0.0

Every tag must be immutable, signed when repository policy permits, and created
from a reviewed commit with Composer validation, audit, static analysis and
tests passing. Consumers must depend on semantic tags, never branch aliases.

## Compatibility policy

- 2.x may add optional endpoints and typed methods without breaking callers.
- Protocol downgrade, weaker validation or expanded trust is never a compatible
  change.
- Claim removal, constructor changes and authentication-method changes require
  a major release.
- Security fixes receive a patch release and a coordinated advisory when
  disclosure is warranted.

## Staging gate

- exact issuer and callbacks;
- TLS verification;
- standard and high-assurance positive flow;
- callback replay rejection;
- wrong issuer/audience/nonce rejection;
- DPoP key mismatch rejection;
- refresh reuse family revocation;
- JWKS rollover;
- tenant mismatch rejection;
- sanitized logs and correlation IDs;
- clean install using only release tags.

## Rollback

Keep the previous minor tag installable and retain the previous signing public
key for the governed overlap window. Roll back consumers before retiring a key
or contract version. Never re-tag an existing version.
