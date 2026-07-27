# Identity SDK 1.2 Release Checklist

Proposed version: `1.2.0`.

Implementation evidence commit:
`2223212916c58a31c79b5a80316dbad0a0156457`.

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

- [x] PHPUnit: 20 tests and 70 assertions passing before release documentation.
- [x] PHPStan: passing before release documentation.
- [x] Issuer, audience, client, scope, temporal and tenant mismatch tests.
- [x] JWKS refresh and unknown `kid` fail-closed test.
- [x] Revoked workload test.
- [ ] Run the final full suite and static analysis on the final source commit.
- [ ] Review changelog and upgrade notes.
- [ ] Confirm Identity supports the selected credential method.
- [ ] Record the exact final source commit.
- [ ] Obtain explicit authorization to tag and publish.
- [ ] Tag `1.2.0`.
- [ ] Publish package metadata.
- [ ] Replace consumer branch aliases with `^1.2`.
- [ ] Run consumer suites and the real control-plane E2E.

No tag, package publication or consumer constraint change is part of this
preparation commit.
