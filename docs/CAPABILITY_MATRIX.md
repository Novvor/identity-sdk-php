# Capability matrix

| Capability | SDK 2.0 | Required server evidence |
| --- | --- | --- |
| Authorization Code | Implemented and tested | `response_types_supported` |
| PKCE S256 | Implemented and tested | `code_challenge_methods_supported` |
| RFC 9207 | Implemented and tested | issuer parameter support |
| PAR | Implemented and tested | PAR endpoint |
| JARM query.jwt | Implemented and tested | response mode and RS256 |
| private_key_jwt | Implemented and tested | auth method plus registered key |
| DPoP | Implemented and tested | signing algorithms and DPoP token type |
| ID token validation | Implemented and tested | issuer, JWKS and RS256 |
| Back-channel logout | Implemented and tested | server metadata and replay store |
| Front-channel logout | Not implemented | must not be inferred |
| Dynamic client registration | Not implemented | use governed admin plane |

“Implemented” describes SDK capability only. Consumers must not advertise or
enable a feature until the target Identity environment proves matching runtime
support.
