package crypto

import (
	stdcrypto "crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// JWKThumbprintBytes computes the RFC 7638 JWK Thumbprint of an EC public key
// as its RAW SHA-256 digest: the hash of the UTF-8 JSON representation of the
// JWK's REQUIRED members only — for an EC key exactly {"kty","crv","x","y"} —
// serialized with no whitespace and member names in lexicographic order
// ([RFC 7638 §3, §3.1]). The hash is fixed to SHA-256 by RFC 7638 itself, not a
// caller-configurable ECCG policy choice.
//
// Use this wherever the thumbprint is consumed as a value rather than shown as
// text — notably binding an ephemeral encryption key into an mdoc
// SessionTranscript, where the wire format is a CBOR byte string
// ([OpenID4VP 1.0 Annex B.2.6]). Callers that need the printable form call
// JWKThumbprint instead; neither is derived from the other by re-parsing.
//
// Delegates JWK construction to ECPublicKeyToJWK, which already returns exactly
// the four REQUIRED members for an EC key; this function does not reimplement
// JWK construction. Returns whatever error ECPublicKeyToJWK returns for a key
// that is not a supported EC public key (fail closed).
func JWKThumbprintBytes(pub stdcrypto.PublicKey) ([]byte, error) {
	jwk, err := ECPublicKeyToJWK(pub)
	if err != nil {
		return nil, err
	}
	// encoding/json.Marshal on a map[string]any sorts keys lexicographically
	// (ASCII order) and emits no extra whitespace — exactly the [RFC 7638 §3.1]
	// canonical form. Verified byte-for-byte by
	// TestECPublicKeyToJWKMarshalOrder.
	canonical, err := json.Marshal(jwk)
	if err != nil {
		return nil, fmt.Errorf("crypto: JWK thumbprint: marshal JWK: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return sum[:], nil
}

// JWKThumbprint computes the RFC 7638 JWK Thumbprint of an EC public key in its
// printable form: the base64url-encoded (RawURLEncoding, no padding) digest
// produced by JWKThumbprintBytes. This is the representation [RFC 7638 §3.1]
// shows and the one to use for identifiers, log fields and JSON members.
//
// For a thumbprint that goes onto the wire as bytes, call JWKThumbprintBytes
// directly rather than decoding this string back.
func JWKThumbprint(pub stdcrypto.PublicKey) (string, error) {
	sum, err := JWKThumbprintBytes(pub)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}
