# go-eudi-crypto

ECCG-pinned cryptographic policy and JOSE/COSE/X.509 façades for EUDI Wallet
relying-party and issuer components.

- Algorithm policy pinned to ECCG Agreed Cryptographic Mechanisms v2.0
  (EW-PIO-01-003): ES256/ES384/ES512, ECDH-ES(+A128KW/+A256KW) × A128GCM/A256GCM,
  COSE ES256/ES384/ES512, curves P-256/P-384/P-521. Unknown algorithm = reject.
- `KeyProvider` interface with file-based (dev) and in-memory implementations.
- JWS/JWE façade over lestrrat-go/jwx/v3 (`SignJWS` — incl. `x5c` from
  `[]*x509.Certificate`, `VerifyJWS`, `EncryptJWE`, `DecryptJWE`); COSE_Sign1
  façade over veraison/go-cose; X.509 chain validation against explicit anchors
  only (no system pool).
- Hash-name policy for content formats: `HashForName` (SD-JWT `_sd_alg`,
  e.g. `sha-256`; empty name → baseline `sha-256` per SD-JWT §4.1.1) and
  `HashForMSODigestAlg` (mdoc `digestAlgorithm`, e.g. `SHA-256`) over one ECCG
  allow-list.
- EC JWK helpers: `ParseECPublicKeyJWK([]byte)` / `ECPublicKeyToJWK` →
  `map[string]any` (RFC 7518 §6.2; used for SD-JWT VC `cnf.jwk` holder keys,
  RFC 7800), strict + fuzzed.
- `JWKThumbprint(crypto.PublicKey) (string, error)`: RFC 7638 JWK Thumbprint
  (SHA-256, base64url, no padding) of an EC public key's REQUIRED-members-only
  JWK; used to bind an ephemeral EC key into an mdoc `SessionTranscript`
  (OpenID4VP 1.0 Annex B.2).

Implemented specs: RFC 7515/7516/7518, RFC 9052/9053, RFC 5280, RFC 7638,
RFC 7800, HAIP 1.0 crypto profile; SD-JWT `_sd_alg` (IANA named-hash) and
ISO/IEC 18013-5 MSO `digestAlgorithm`. See SPECREFS.md for pinned versions.

Status: pre-v1. API frozen no earlier than OIDF conformance pass.
