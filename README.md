# go-eudi-crypto

ECCG-pinned cryptographic policy and JOSE/COSE/X.509 façades for EUDI Wallet
relying-party and issuer components.

- Algorithm policy pinned to ECCG Agreed Cryptographic Mechanisms v2.0
  (EW-PIO-01-003): ES256/ES384/ES512, ECDH-ES(+A128KW/+A256KW) × A128GCM/A256GCM,
  COSE ES256/ES384/ES512, curves P-256/P-384/P-521. Unknown algorithm = reject.
- `KeyProvider` interface with file-based (dev) and in-memory implementations.
- JWS/JWE façade over lestrrat-go/jwx/v3; COSE_Sign1 façade over veraison/go-cose;
  X.509 chain validation against explicit anchors only (no system pool).

Implemented specs: RFC 7515/7516/7518, RFC 9052/9053, RFC 5280, HAIP 1.0
crypto profile. See SPECREFS.md for pinned versions.

Status: pre-v1. API frozen no earlier than OIDF conformance pass.
