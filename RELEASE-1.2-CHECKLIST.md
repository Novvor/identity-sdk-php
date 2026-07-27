# Identity SDK 1.2 Release Checklist

Proposed version: `1.2.0`.

Implementation evidence commit:
`618d3168bfeb5ba2532aa8d019e34294f7123397`.

The final source commit must be replaced with the exact release-candidate commit
after documentation review and before tagging.

## Compatibility matrix

| Component | Supported/prepared |
| --- | --- |
| PHP | 8.2, 8.3, 8.4 |
| `firebase/php-jwt` | `^7.0` |
| Guzzle | `^7.0` |
| Identity interactive OIDC | backward compatible |
| Workload `client_secret_post` | supported by current integration |
| Workload `private_key_jwt` | SDK prepared; server support not validated |
| ORBIT Intelligence | branch alias today; target `^1.2` |
| Enix Platform | branch alias today; target `^1.2` |

## Release gate

- [x] PHPUnit: 21 tests and 76 assertions passing on the prepared source.
- [x] PHPStan: passing on the prepared source.
- [x] Issuer, audience, client, scope, temporal and tenant mismatch tests.
- [x] JWKS refresh and unknown `kid` fail-closed test.
- [x] Revoked workload test.
- [x] Run the full suite and static analysis on the prepared source commit.
- [x] Review changelog and upgrade notes.
- [ ] Confirm Identity supports the selected credential method.
- [ ] Record the exact final source commit.
- [ ] Obtain explicit authorization to tag and publish.
- [ ] Tag `1.2.0`.
- [ ] Publish package metadata.
- [ ] Replace consumer branch aliases with `^1.2`.
- [ ] Run consumer suites and the real control-plane E2E.

ORBIT now exposes the credential method through `orbit:doctor`, supports the
currently installed `client_secret_post` path, and explicitly fails closed with
`workload_private_key_jwt_requires_identity_sdk_1_2` if an operator selects
`private_key_jwt` before this release is installed.

No tag, package publication or consumer constraint change is part of this
preparation commit.
