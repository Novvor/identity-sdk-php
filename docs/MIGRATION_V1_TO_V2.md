# Migration from 1.x to 2.0

## Compatibility

Existing constructor calls remain valid. The default client authentication mode
is `auto`: a configured secret retains the historical
`client_secret_post` behavior; a client without a secret remains public.

No existing application is automatically promoted to the high-assurance
profile. Promotion must be coordinated with the Identity client registration.

## Governed migration

1. Upgrade the package while retaining `standard`.
2. Replace direct callback parsing with `AuthorizationResponseProcessor`.
3. Require RFC 9207 `iss` in callbacks.
4. Provision a dedicated asymmetric client key and register its public key.
5. Confirm Discovery advertises PAR, `query.jwt`, `private_key_jwt`, DPoP and
   authorization-response issuer support.
6. Enable `novvor-high-assurance-v1`.
7. Push the request with `PushedAuthorizationClient`.
8. Redirect with only `client_id` and `request_uri`.
9. Validate JARM and then exchange the code with a DPoP key.
10. Verify negative tests before production promotion.

Roll back by reverting the client to `standard`; do not retain a partly enabled
profile or selectively disable one of its controls.
