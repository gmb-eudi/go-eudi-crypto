package crypto

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/veraison/go-cose"
)

// COSEHeader carries integer-labeled COSE header parameters ([RFC 9052 §3]).
// EUDI profiles (ISO 18013-5 IssuerAuth/DeviceAuth) use integer labels only;
// string labels are not surfaced by this façade.
type COSEHeader map[int64]any

const coseLabelAlg = int64(1) // [RFC 9052 §3.1]

// coseAlgForKey maps the key's curve to the single ECCG-allowed COSE alg
// ([RFC 9053 §2.1]). The message never chooses the algorithm.
func coseAlgForKey(pub *ecdsa.PublicKey) (cose.Algorithm, error) {
	switch pub.Curve {
	case elliptic.P256():
		return cose.AlgorithmES256, nil
	case elliptic.P384():
		return cose.AlgorithmES384, nil
	case elliptic.P521():
		return cose.AlgorithmES512, nil
	default:
		return 0, fmt.Errorf("%w: %s", ErrCurveNotAllowed, pub.Curve.Params().Name)
	}
}

// VerifyCOSESign1 verifies a COSE_Sign1 message ([RFC 9052 §4.2]) against an
// explicitly supplied key. The expected algorithm is derived from the key;
// a mismatching protected alg is rejected.
func VerifyCOSESign1(raw []byte, key stdcrypto.PublicKey) ([]byte, COSEHeader, error) {
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("%w: verification key is %T, EC required", ErrKeyTypeNotAllowed, key)
	}
	expected, err := coseAlgForKey(pub)
	if err != nil {
		return nil, nil, err
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(raw); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: protected alg: %v", ErrMalformed, err)
	}
	if !ECCG().AllowedCOSEAlg(int64(alg)) {
		return nil, nil, fmt.Errorf("%w: COSE alg %d", ErrAlgorithmNotAllowed, int64(alg))
	}
	if alg != expected {
		return nil, nil, fmt.Errorf("%w: message alg %d, key requires %d", ErrAlgKeyMismatch, int64(alg), int64(expected))
	}
	verifier, err := cose.NewVerifier(alg, pub)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrKeyTypeNotAllowed, err)
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}
	return msg.Payload, protectedToMap(msg.Headers.Protected), nil
}

func protectedToMap(p cose.ProtectedHeader) COSEHeader {
	out := make(COSEHeader, len(p))
	for k, v := range p {
		var label int64
		switch kk := k.(type) {
		case int64:
			label = kk
		case int:
			label = int64(kk)
		default:
			continue // string labels not surfaced
		}
		if a, ok := v.(cose.Algorithm); ok {
			out[label] = int64(a)
			continue
		}
		out[label] = v
	}
	return out
}

// SignCOSESign1 signs payload as COSE_Sign1 ([RFC 9052 §4.2]). The alg label
// is derived from the key; callers must not set label 1 (algorithms are
// derived from keys, never chosen by callers or messages).
func SignCOSESign1(ctx context.Context, kp KeyProvider, keyID string, protected COSEHeader, payload []byte) ([]byte, error) {
	signer, err := kp.Signer(ctx, keyID)
	if err != nil {
		return nil, err
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: signer key is %T, EC required", ErrKeyTypeNotAllowed, signer.Public())
	}
	alg, err := coseAlgForKey(pub)
	if err != nil {
		return nil, err
	}
	hdrs := cose.Headers{Protected: cose.ProtectedHeader{cose.HeaderLabelAlgorithm: alg}}
	for k, v := range protected {
		if k == coseLabelAlg {
			return nil, fmt.Errorf("%w: alg label is derived from the key", ErrProtectedHeader)
		}
		hdrs.Protected[k] = v
	}
	csigner, err := cose.NewSigner(alg, signer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyTypeNotAllowed, err)
	}
	msg := cose.Sign1Message{Headers: hdrs, Payload: payload}
	if err := msg.Sign(rand.Reader, nil, csigner); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	out, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return out, nil
}
