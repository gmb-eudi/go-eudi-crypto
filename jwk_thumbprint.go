package crypto

import (
	stdcrypto "crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// JWKThumbprint computes the RFC 7638 JWK Thumbprint of an EC public key: the
// base64url-encoded (RawURLEncoding, no padding) SHA-256 digest of the UTF-8
// JSON representation of the JWK's REQUIRED members only — for an EC key
// exactly {"kty","crv","x","y"} — serialized with no whitespace and member
// names in lexicographic order ([RFC 7638 §3, §3.1]). The hash is fixed to
// SHA-256 by RFC 7638 itself, not a caller-configurable ECCG policy choice.
//
// Used to bind an ephemeral EC public key into an mdoc SessionTranscript
// (OpenID4VP 1.0 Annex B.2).
//
// Delegates JWK construction to ECPublicKeyToJWK, which already returns
// exactly the four REQUIRED members for an EC key; this function does not
// reimplement JWK construction. Returns whatever error ECPublicKeyToJWK
// returns for a key that is not a supported EC public key (fail closed).
func JWKThumbprint(pub stdcrypto.PublicKey) (string, error) {
	jwk, err := ECPublicKeyToJWK(pub)
	if err != nil {
		return "", err
	}
	// encoding/json.Marshal on a map[string]any sorts keys lexicographically
	// (ASCII order) and emits no extra whitespace — exactly the [RFC 7638 §3.1]
	// canonical form. Verified byte-for-byte by
	// TestECPublicKeyToJWKMarshalOrder.
	canonical, err := json.Marshal(jwk)
	if err != nil {
		return "", fmt.Errorf("crypto: JWK thumbprint: marshal JWK: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
