package crypto

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// ecJWK is the RFC 7518 §6.2 JSON Web Key representation of an EC public key.
type ecJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// curveForJWK maps a JWK `crv` value to its curve, rejecting any curve not on
// the ECCG allow-list (unknown = reject, never fall through).
func curveForJWK(crv string) (elliptic.Curve, error) {
	if !ECCG().AllowedCurve(crv) {
		return nil, fmt.Errorf("%w: %q", ErrCurveNotAllowed, crv)
	}
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrCurveNotAllowed, crv)
	}
}

// ParseECPublicKeyJWK parses an RFC 7518 EC public-key JWK — as carried in an
// SD-JWT VC `cnf.jwk` (RFC 7800) — into a *ecdsa.PublicKey. Strict and
// fail-closed: only kty="EC" on an ECCG-allowed curve is accepted, x/y must be
// fixed-size big-endian coordinates, and the point is fully validated (on-curve,
// non-identity) by ecdsa.ParseUncompressedPublicKey. Malformed input is
// rejected and never panics (fuzzed: FuzzParseECPublicKeyJWK).
func ParseECPublicKeyJWK(jwkJSON []byte) (stdcrypto.PublicKey, error) {
	var j ecJWK
	if err := json.Unmarshal(jwkJSON, &j); err != nil {
		return nil, fmt.Errorf("%w: EC JWK: %v", ErrMalformed, err)
	}
	if j.Kty != "EC" {
		return nil, fmt.Errorf("%w: JWK kty %q, EC required", ErrKeyTypeNotAllowed, j.Kty)
	}
	curve, err := curveForJWK(j.Crv)
	if err != nil {
		return nil, err
	}
	if j.X == "" || j.Y == "" {
		return nil, fmt.Errorf("%w: EC JWK missing x/y", ErrMalformed)
	}
	xb, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("%w: EC JWK x: %v", ErrMalformed, err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, fmt.Errorf("%w: EC JWK y: %v", ErrMalformed, err)
	}
	// RFC 7518 §6.2.1.2/.3: x and y are the fixed-size big-endian field
	// elements; reject wrong-sized inputs (they would silently zero-extend).
	size := (curve.Params().BitSize + 7) / 8
	if len(xb) != size || len(yb) != size {
		return nil, fmt.Errorf("%w: EC JWK coordinate size", ErrMalformed)
	}
	// Assemble the uncompressed SEC 1 point (0x04 || X || Y);
	// ParseUncompressedPublicKey validates it is on the curve and not the
	// identity, and avoids the deprecated raw X/Y coordinate access (Go 1.25+).
	point := make([]byte, 1+2*size)
	point[0] = 0x04
	copy(point[1:], xb)
	copy(point[1+size:], yb)
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, fmt.Errorf("%w: EC JWK point invalid: %v", ErrMalformed, err)
	}
	return pub, nil
}

// ECPublicKeyToJWK serializes an EC public key to an RFC 7518 §6.2 JWK as a
// map (ready to embed as an SD-JWT VC `cnf.jwk` object; RFC 7800). Rejects
// non-EC keys and curves not on the ECCG allow-list.
func ECPublicKeyToJWK(pub stdcrypto.PublicKey) (map[string]any, error) {
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: JWK subject must be *ecdsa.PublicKey, got %T", ErrKeyTypeNotAllowed, pub)
	}
	if ec.Curve == nil {
		return nil, fmt.Errorf("%w: EC public key has no curve", ErrCurveNotAllowed)
	}
	crv := ec.Curve.Params().Name
	if !ECCG().AllowedCurve(crv) {
		return nil, fmt.Errorf("%w: %q", ErrCurveNotAllowed, crv)
	}
	// SEC 1 uncompressed point 0x04 || X || Y with fixed-width coordinates
	// (Go 1.25+ encoder; avoids deprecated raw X/Y access).
	raw, err := ec.Bytes()
	if err != nil {
		return nil, fmt.Errorf("%w: EC public key: %v", ErrMalformed, err)
	}
	size := (ec.Curve.Params().BitSize + 7) / 8
	if len(raw) != 1+2*size || raw[0] != 0x04 {
		return nil, fmt.Errorf("%w: unexpected EC point encoding", ErrMalformed)
	}
	return map[string]any{
		"kty": "EC",
		"crv": crv,
		"x":   base64.RawURLEncoding.EncodeToString(raw[1 : 1+size]),
		"y":   base64.RawURLEncoding.EncodeToString(raw[1+size:]),
	}, nil
}
