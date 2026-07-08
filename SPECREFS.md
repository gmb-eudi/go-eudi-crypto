# Pinned specification versions

| Spec | Version pinned |
|---|---|
| ECCG Agreed Cryptographic Mechanisms | v2.0 (EW-PIO-01-003) |
| JWS / JWE / JWA | RFC 7515 / 7516 / 7518 |
| COSE | RFC 9052 / 9053 |
| X.509 path validation | RFC 5280 §6.1 |
| OpenID4VC High Assurance Interoperability Profile | 1.0 (final) |
| Key confirmation (`cnf`) — EC JWK parse/serialize | RFC 7800 + RFC 7518 §6.2 |
| SD-JWT `_sd_alg` hash names (sha-256/384/512) | IANA "Named Information Hash Algorithm" registry |
| mdoc MSO `digestAlgorithm` (SHA-256/384/512) | ISO/IEC 18013-5 §9.1.2.5 |
| JWK Thumbprint (`JWKThumbprint`) | RFC 7638 §3 (SHA-256 fixed by the RFC, not ECCG-selectable) |
| Structural JWS header peek (`ParseJWSHeader`, `X5CFromHeader`) | RFC 7515 §4.1 (protected header), §4.1.6 (`x5c`) — pre-trust, no signature verification; added 2026-07-07 for WP-09's issuer-key resolution |
