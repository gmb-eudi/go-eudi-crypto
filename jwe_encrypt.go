package crypto

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
)

// EncryptJWE encrypts payload to an EC recipient key using ECDH-ES key
// agreement with A256GCM content encryption (RFC 7516; ECCG Agreed
// Mechanisms / HAIP 1.0 encrypted-response profile). Compact serialization.
// The protected map may carry additional header params (e.g. OID4VP Annex B.2
// apu = base64url(mdocGeneratedNonce)); alg/enc/epk are set by the library from
// policy and must not be supplied by the caller. The pair is never taken from
// the caller — algorithms are policy-driven, never chosen by callers or tokens.
func EncryptJWE(recipient stdcrypto.PublicKey, protected map[string]any, payload []byte) ([]byte, error) {
	pub, ok := recipient.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: JWE recipient must be *ecdsa.PublicKey, got %T", ErrKeyTypeNotAllowed, recipient)
	}
	if pub.Curve == nil {
		return nil, fmt.Errorf("%w: recipient key has no curve", ErrCurveNotAllowed)
	}
	if !ECCG().AllowedCurve(pub.Curve.Params().Name) {
		return nil, fmt.Errorf("%w: %s", ErrCurveNotAllowed, pub.Curve.Params().Name)
	}
	// Policy self-check: the fixed alg/enc pair must be on the allow-list.
	if !ECCG().AllowedJWEAlg("ECDH-ES", "A256GCM") {
		return nil, fmt.Errorf("%w: ECDH-ES/A256GCM", ErrAlgorithmNotAllowed)
	}
	hdrs := jwe.NewHeaders()
	for k, v := range protected {
		switch k {
		case "alg", "enc", "epk":
			return nil, fmt.Errorf("%w: %q is library-owned", ErrProtectedHeader, k)
		case "apu", "apv":
			// RFC 7518 §4.6.1.2/.3: apu/apv are base64url-encoded octet strings
			// on the wire. jwx models them as raw []byte (and re-encodes when
			// serializing), so accept the base64url string form and decode it.
			if s, ok := v.(string); ok {
				raw, err := base64.RawURLEncoding.DecodeString(s)
				if err != nil {
					return nil, fmt.Errorf("%w: header %q: %v", ErrMalformed, k, err)
				}
				if err := hdrs.Set(k, raw); err != nil {
					return nil, fmt.Errorf("%w: header %q: %v", ErrMalformed, k, err)
				}
				continue
			}
		}
		if err := hdrs.Set(k, v); err != nil {
			return nil, fmt.Errorf("%w: header %q: %v", ErrMalformed, k, err)
		}
	}
	// apu/apv and any caller headers go in the key-agreement (per-recipient)
	// headers so ECDH-ES uses apu/apv in the Concat KDF; for compact
	// serialization jwx merges them into the protected header, so DecryptJWE
	// reads the same values and derives the same key.
	token, err := jwe.Encrypt(payload,
		jwe.WithKey(jwa.ECDH_ES(), pub, jwe.WithPerRecipientHeaders(hdrs)),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		return nil, fmt.Errorf("crypto: encrypt jwe: %w", err)
	}
	return token, nil
}
