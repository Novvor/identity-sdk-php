# Upgrade to 1.2

Proposed stable constraint after an explicitly authorized release:

```json
{
  "require": {
    "novvor/identity-sdk-php": "^1.2"
  }
}
```

Until `1.2.0` is tagged and published, ORBIT and Platform continue using the
reviewable branch alias. Do not replace it with a stable constraint before the
package exists.

Existing interactive OIDC APIs remain compatible. Workload callers should:

1. construct `WorkloadClientConfiguration` with the exact issuer, client ID,
   token endpoint, JWKS URI, audience and scopes provisioned by Identity;
2. keep the default bounded 30-second clock skew unless measured infrastructure
   drift justifies a smaller value;
3. retain the default five-minute JWKS cache or choose a measured value between
   30 seconds and one day;
4. continue using `client_secret_post` until Identity explicitly confirms
   `private_key_jwt`;
5. pass the required tenant ID to validation only when the workload token is
   tenant-bound.

Consumers may feature-detect the `credentialMethod` constructor parameter
during the pre-release transition. They must fail closed instead of silently
falling back to `client_secret_post` when `private_key_jwt` was explicitly
selected.

No access token, client secret or private key may be logged.
