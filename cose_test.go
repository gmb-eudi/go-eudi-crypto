package crypto_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/veraison/go-cose"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

func TestCOSESign1Roundtrip(t *testing.T) {
	ctx := context.Background()
	payload := []byte{0xa1, 0x01, 0x02} // arbitrary CBOR payload
	for _, tt := range []struct {
		name  string
		curve elliptic.Curve
	}{
		{"ES256_P256", elliptic.P256()},
		{"ES384_P384", elliptic.P384()},
		{"ES512_P521", elliptic.P521()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key := genKey(t, tt.curve)
			raw, err := crypto.SignCOSESign1(ctx, memProvider{"k": key}, "k", crypto.COSEHeader{4: []byte("kid-1")}, payload)
			if err != nil {
				t.Fatal(err)
			}
			got, protected, err := crypto.VerifyCOSESign1(raw, key.Public())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("payload = %x, want %x", got, payload)
			}
			if _, ok := protected[1]; !ok {
				t.Error("protected alg label (1) missing from returned header")
			}
			if kid, ok := protected[4].([]byte); !ok || !bytes.Equal(kid, []byte("kid-1")) {
				t.Errorf("protected kid label (4) = %v, want kid-1 preserved", protected[4])
			}
		})
	}
}

func TestCOSESign1TamperFails(t *testing.T) {
	key := genKey(t, elliptic.P256())
	raw, err := crypto.SignCOSESign1(context.Background(), memProvider{"k": key}, "k", nil, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xFF // flip a signature byte
	if _, _, err := crypto.VerifyCOSESign1(raw, key.Public()); !errors.Is(err, crypto.ErrVerificationFailed) {
		t.Fatalf("err = %v, want ErrVerificationFailed", err)
	}
}

// Alg in the protected header must match the algorithm implied by the key's
// curve: alg mismatch between header and key must be rejected.
func TestCOSESign1AlgKeyMismatch(t *testing.T) {
	p256 := genKey(t, elliptic.P256())
	p384 := genKey(t, elliptic.P384())
	raw, err := crypto.SignCOSESign1(context.Background(), memProvider{"k": p256}, "k", nil, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	// ES256-signed message verified against a P-384 key: expected alg ES384.
	if _, _, err := crypto.VerifyCOSESign1(raw, p384.Public()); !errors.Is(err, crypto.ErrAlgKeyMismatch) {
		t.Fatalf("err = %v, want ErrAlgKeyMismatch", err)
	}
}

func TestCOSESign1MalformedRejected(t *testing.T) {
	key := genKey(t, elliptic.P256())
	for _, raw := range [][]byte{nil, {0x00}, []byte("definitely not cbor"), bytes.Repeat([]byte{0x9f}, 64)} {
		if _, _, err := crypto.VerifyCOSESign1(raw, key.Public()); !errors.Is(err, crypto.ErrMalformed) {
			t.Errorf("raw %x: err = %v, want ErrMalformed", raw, err)
		}
	}
}

func TestCOSESign1RejectsCallerAlgHeader(t *testing.T) {
	key := genKey(t, elliptic.P256())
	_, err := crypto.SignCOSESign1(context.Background(), memProvider{"k": key}, "k", crypto.COSEHeader{1: int64(-7)}, []byte("x"))
	if !errors.Is(err, crypto.ErrProtectedHeader) {
		t.Fatalf("err = %v, want ErrProtectedHeader", err)
	}
}

// RFC 8152/9052 Appendix C.2.1 single-signer example, key "11" (P-256).
func TestCOSESign1RFCVector(t *testing.T) {
	msg, err := hex.DecodeString(
		"d28443a10126a10442313154546869732069732074686520636f6e74656e742e5840" +
			"8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e" +
			"2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36")
	if err != nil {
		t.Fatal(err)
	}
	// 0x04 || X || Y — parsed rather than assigned to the deprecated X/Y fields.
	pt, err := hex.DecodeString("04" +
		"bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff" +
		"20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e")
	if err != nil {
		t.Fatal(err)
	}

	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pt)
	if err != nil {
		t.Fatal(err)
	}
	payload, protected, err := crypto.VerifyCOSESign1(msg, pub)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "This is the content." {
		t.Errorf("payload = %q", payload)
	}
	if alg, ok := protected[1].(int64); !ok || alg != -7 {
		t.Errorf("protected alg = %v, want -7", protected[1])
	}
}

func TestCOSESign1KeyNotFoundRejected(t *testing.T) {
	_, err := crypto.SignCOSESign1(context.Background(), memProvider{}, "missing", nil, []byte("x"))
	if !errors.Is(err, crypto.ErrKeyNotFound) {
		t.Fatalf("err = %v, want ErrKeyNotFound", err)
	}
}

// Signer keys must be EC (algorithms are derived from keys, never chosen by
// callers or tokens); an Ed25519 signer is rejected before any algorithm
// negotiation.
func TestCOSESign1NonECSignerRejected(t *testing.T) {
	_, err := crypto.SignCOSESign1(context.Background(), newNonECKeyProvider(t), "k", nil, []byte("x"))
	if !errors.Is(err, crypto.ErrKeyTypeNotAllowed) {
		t.Fatalf("err = %v, want ErrKeyTypeNotAllowed", err)
	}
}

// P-224 is a valid EC curve but not ECCG-allowed; both signing and
// verification must reject it (fail closed: unknown/disallowed curve is
// never accepted).
func TestCOSESign1UnsupportedCurveRejected(t *testing.T) {
	key := genKey(t, elliptic.P224())
	if _, err := crypto.SignCOSESign1(context.Background(), memProvider{"k": key}, "k", nil, []byte("x")); !errors.Is(err, crypto.ErrCurveNotAllowed) {
		t.Fatalf("SignCOSESign1 err = %v, want ErrCurveNotAllowed", err)
	}
	if _, _, err := crypto.VerifyCOSESign1([]byte{0xd2, 0x84}, key.Public()); !errors.Is(err, crypto.ErrCurveNotAllowed) {
		t.Fatalf("VerifyCOSESign1 err = %v, want ErrCurveNotAllowed", err)
	}
}

func TestCOSESign1WrongKeyTypeRejected(t *testing.T) {
	if _, _, err := crypto.VerifyCOSESign1([]byte{0xd2, 0x84}, "not a key"); !errors.Is(err, crypto.ErrKeyTypeNotAllowed) {
		t.Fatalf("err = %v, want ErrKeyTypeNotAllowed", err)
	}
}

// A CBOR-well-formed Sign1Message with no alg in its protected header must
// be rejected as malformed, not treated as alg:none.
func TestCOSESign1MissingAlgHeaderRejected(t *testing.T) {
	key := genKey(t, elliptic.P256())
	msg := cose.Sign1Message{
		Headers:   cose.Headers{Protected: cose.ProtectedHeader{}},
		Payload:   []byte("x"),
		Signature: []byte("sig"),
	}
	raw, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := crypto.VerifyCOSESign1(raw, key.Public()); !errors.Is(err, crypto.ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

// A protected alg present in the message but outside the ECCG allow-list
// must be rejected by policy before any verifier is constructed.
func TestCOSESign1DisallowedAlgRejected(t *testing.T) {
	key := genKey(t, elliptic.P256())
	msg := cose.Sign1Message{
		Headers: cose.Headers{
			Protected: cose.ProtectedHeader{cose.HeaderLabelAlgorithm: cose.Algorithm(999)},
		},
		Payload:   []byte("x"),
		Signature: []byte("sig"),
	}
	raw, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := crypto.VerifyCOSESign1(raw, key.Public()); !errors.Is(err, crypto.ErrAlgorithmNotAllowed) {
		t.Fatalf("err = %v, want ErrAlgorithmNotAllowed", err)
	}
}

func TestSignCOSESign1NilPayloadRejected(t *testing.T) {
	key := genKey(t, elliptic.P256())
	_, err := crypto.SignCOSESign1(context.Background(), memProvider{"k": key}, "k", nil, nil)
	if !errors.Is(err, crypto.ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}
