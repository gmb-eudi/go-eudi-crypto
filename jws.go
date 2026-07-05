package crypto

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// algForECKey maps the key's curve to the single ECCG-allowed JWS alg for
// that curve (RFC 7518 §3.4). The token never chooses the algorithm.
func algForECKey(pub *ecdsa.PublicKey) (string, error) {
	switch pub.Curve {
	case elliptic.P256():
		return "ES256", nil
	case elliptic.P384():
		return "ES384", nil
	case elliptic.P521():
		return "ES512", nil
	default:
		return "", fmt.Errorf("%w: %s", ErrCurveNotAllowed, pub.Curve.Params().Name)
	}
}

func sigAlg(alg string) (jwa.SignatureAlgorithm, error) {
	switch alg {
	case "ES256":
		return jwa.ES256(), nil
	case "ES384":
		return jwa.ES384(), nil
	case "ES512":
		return jwa.ES512(), nil
	default:
		return jwa.SignatureAlgorithm{}, fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, alg)
	}
}

// SignJWS signs payload as a compact JWS (RFC 7515). The alg header is
// derived from the key; callers must not set it (algorithms are derived from
// keys, never chosen by callers or tokens).
func SignJWS(ctx context.Context, kp KeyProvider, keyID string, protected map[string]any, payload []byte) ([]byte, error) {
	signer, err := kp.Signer(ctx, keyID)
	if err != nil {
		return nil, err
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: signer key is %T, EC required", ErrKeyTypeNotAllowed, signer.Public())
	}
	alg, err := algForECKey(pub)
	if err != nil {
		return nil, err
	}
	a, err := sigAlg(alg)
	if err != nil {
		return nil, err
	}
	hdrs := jws.NewHeaders()
	for k, v := range protected {
		if k == "alg" || k == "crit" {
			return nil, fmt.Errorf("%w: %q is not caller-settable", ErrProtectedHeader, k)
		}
		if k == "x5c" {
			// jwx types x5c as *cert.Chain; accept the caller's certificates as
			// []*x509.Certificate (leaf first) and convert here so services never
			// import jwx (ADR-0004). RFC 7515 §4.1.6.
			chain, ok := v.([]*x509.Certificate)
			if !ok {
				return nil, fmt.Errorf("%w: x5c must be []*x509.Certificate, got %T", ErrMalformed, v)
			}
			cc, err := certChain(chain)
			if err != nil {
				return nil, err
			}
			if err := hdrs.Set("x5c", cc); err != nil {
				return nil, fmt.Errorf("%w: header x5c: %v", ErrMalformed, err)
			}
			continue
		}
		if err := hdrs.Set(k, v); err != nil {
			return nil, fmt.Errorf("%w: header %q: %v", ErrMalformed, k, err)
		}
	}
	out, err := jws.Sign(payload, jws.WithKey(a, signer, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return out, nil
}

// VerifyJWS verifies a compact JWS against an explicitly supplied key.
// The expected algorithm is derived from the key, never taken from the token
// (RFC 8725 §3.1 / §3.2); jku/x5u are never dereferenced — key resolution
// belongs to the trust layer, not this library.
func VerifyJWS(token []byte, key stdcrypto.PublicKey) ([]byte, Header, error) {
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("%w: verification key is %T, EC required", ErrKeyTypeNotAllowed, key)
	}
	expected, err := algForECKey(pub)
	if err != nil {
		return nil, nil, err
	}
	if !ECCG().AllowedJWSAlg(expected) {
		return nil, nil, fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, expected)
	}
	hdr, err := parseProtectedSegment(token, 3)
	if err != nil {
		return nil, nil, err
	}
	alg, _ := hdr["alg"].(string)
	if !ECCG().AllowedJWSAlg(alg) {
		return nil, nil, fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, alg)
	}
	if alg != expected {
		return nil, nil, fmt.Errorf("%w: token alg %q, key requires %q", ErrAlgKeyMismatch, alg, expected)
	}
	if err := checkCrit(hdr); err != nil {
		return nil, nil, err
	}
	a, err := sigAlg(expected)
	if err != nil {
		return nil, nil, err
	}
	payload, err := jws.Verify(token, jws.WithKey(a, pub))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}
	return payload, hdr, nil
}

// certChain builds the jwx *cert.Chain required for the JWS x5c header from DER
// certificates (leaf first), each serialized as base64 (standard, not URL) DER
// per RFC 7515 §4.1.6.
func certChain(chain []*x509.Certificate) (*cert.Chain, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("%w: x5c is empty", ErrMalformed)
	}
	cc := &cert.Chain{}
	for i, c := range chain {
		if c == nil {
			return nil, fmt.Errorf("%w: x5c[%d] is nil", ErrMalformed, i)
		}
		if err := cc.AddString(base64.StdEncoding.EncodeToString(c.Raw)); err != nil {
			return nil, fmt.Errorf("%w: x5c[%d]: %v", ErrMalformed, i, err)
		}
	}
	return cc, nil
}
