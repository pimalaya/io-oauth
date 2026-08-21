---
cairn: spec
capability: jwt-bearer
status: current
---

# JWT bearer profile

The RFC 7523 profile for headless machine-to-machine authentication: a signed JWT is either the authorization grant itself (section 2.1, the Google service account flow) or the client authentication of the client credentials grant (section 2.2, the Microsoft certificate credentials flow).

### Requirement: Assertion claims
The claim set SHALL carry `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti` and `scope`, plus free-form extra claims flattened into the payload. `iss` and `aud` SHALL be required. `exp`, required by the spec, SHALL stay optional in the claim set so a std layer can default it from a clock, and signing SHALL reject a claim set leaving it unset.

### Requirement: Clock-free claims
Time claims and the `jti` identifier SHALL be caller-provided. The claim set SHALL read no clock.

### Requirement: Signing
Signing SHALL produce a compact JWS: base64url header and claims, signed with RS256 (RSASSA-PKCS1-v1_5 over SHA-256), the header advertising exactly the algorithm used. The signing key SHALL be parsable from PKCS#8 or PKCS#1, in PEM or DER.

### Requirement: Certificate thumbprint
The crate SHALL compute the `x5t` header value from DER certificate bytes as the base64url-encoded SHA-1 thumbprint, which Microsoft requires on assertions signed with certificate credentials.

### Requirement: Signing is feature-gated
The claims and the coroutines SHALL be unconditional wire code. Only the signing key and the thumbprint helper SHALL sit behind the `jwt-bearer` feature, since they alone pull the rsa and sha1 crates. A caller signing elsewhere SHALL be able to pass a ready-made assertion without enabling the feature.

### Requirement: JWT as authorization grant
The section 2.1 exchange SHALL send `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` with the assertion, no end user round trip and no client secret involved.

### Requirement: JWT as client authentication
The section 2.2 exchange SHALL send `grant_type=client_credentials` with `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and the assertion. `client_id` SHALL be accepted in the body although the spec makes it optional, Microsoft requiring it.

### Requirement: No refresh token
Neither exchange SHALL expect a refresh token. The caller signs a fresh assertion and repeats the request on expiry.
