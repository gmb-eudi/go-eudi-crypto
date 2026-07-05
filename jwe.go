package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
)

func keyEncAlg(alg string) (jwa.KeyEncryptionAlgorithm, error) {
	switch alg {
	case "ECDH-ES":
		return jwa.ECDH_ES(), nil
	case "ECDH-ES+A128KW":
		return jwa.ECDH_ES_A128KW(), nil
	case "ECDH-ES+A256KW":
		return jwa.ECDH_ES_A256KW(), nil
	default:
		return jwa.KeyEncryptionAlgorithm{}, fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, alg)
	}
}

// DecryptJWE decrypts a compact JWE (RFC 7516) addressed to keyID. The
// protected header's alg/enc pair is checked against the ECCG policy BEFORE
// any decryption is attempted (HAIP: ECDH-ES with AES-GCM only).
func DecryptJWE(ctx context.Context, kp KeyProvider, keyID string, token []byte) ([]byte, Header, error) {
	hdr, err := parseProtectedSegment(token, 5)
	if err != nil {
		return nil, nil, err
	}
	alg, _ := hdr["alg"].(string)
	enc, _ := hdr["enc"].(string)
	if !ECCG().AllowedJWEAlg(alg, enc) {
		return nil, nil, fmt.Errorf("%w: alg=%q enc=%q", ErrAlgorithmNotAllowed, alg, enc)
	}
	if _, ok := hdr["zip"]; ok {
		// jwx silently inflates a "zip":"DEF" payload before we ever see the
		// plaintext (~1000:1 amplification); DEFLATE is not an ECCG/HAIP
		// mechanism, so any compression request is rejected outright.
		return nil, nil, fmt.Errorf("%w: compression (zip) not allowed", ErrAlgorithmNotAllowed)
	}
	if err := checkCrit(hdr); err != nil {
		return nil, nil, err
	}
	dec, err := kp.Decrypter(ctx, keyID)
	if err != nil {
		return nil, nil, err
	}
	priv, ok := dec.PrivateKey().(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("%w: decryption key is %T, EC required", ErrKeyTypeNotAllowed, dec.PrivateKey())
	}
	ka, err := keyEncAlg(alg)
	if err != nil {
		return nil, nil, err
	}
	pt, err := jwe.Decrypt(token, jwe.WithKey(ka, priv))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	return pt, hdr, nil
}

// GenerateEphemeralKey creates a fresh EC keypair for per-session response
// encryption (HAIP response encryption; OID4VP §8.3 direct_post.jwt). The
// curve must be ECCG-allowed.
func GenerateEphemeralKey(crv string) (*ecdsa.PrivateKey, error) {
	if !ECCG().AllowedCurve(crv) {
		return nil, fmt.Errorf("%w: %q", ErrCurveNotAllowed, crv)
	}
	var c elliptic.Curve
	switch crv {
	case "P-256":
		c = elliptic.P256()
	case "P-384":
		c = elliptic.P384()
	case "P-521":
		c = elliptic.P521()
	default:
		return nil, fmt.Errorf("%w: %q", ErrCurveNotAllowed, crv)
	}
	return ecdsa.GenerateKey(c, rand.Reader)
}
