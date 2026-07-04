package crypto_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

func encryptWith(t *testing.T, pub any, keyAlg jwa.KeyEncryptionAlgorithm, enc jwa.ContentEncryptionAlgorithm, payload []byte) []byte {
	t.Helper()
	out, err := jwe.Encrypt(payload, jwe.WithKey(keyAlg, pub), jwe.WithContentEncryption(enc))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestJWEDecryptRoundtrip(t *testing.T) {
	ctx := context.Background()
	payload := []byte(`{"vp_token":{}}`)
	for _, tt := range []struct {
		name   string
		keyAlg jwa.KeyEncryptionAlgorithm
		enc    jwa.ContentEncryptionAlgorithm
	}{
		{"ECDH_ES_A128GCM", jwa.ECDH_ES(), jwa.A128GCM()},
		{"ECDH_ES_A256GCM", jwa.ECDH_ES(), jwa.A256GCM()},
		{"ECDH_ES_A128KW_A128GCM", jwa.ECDH_ES_A128KW(), jwa.A128GCM()},
		{"ECDH_ES_A256KW_A256GCM", jwa.ECDH_ES_A256KW(), jwa.A256GCM()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key, err := crypto.GenerateEphemeralKey("P-256")
			if err != nil {
				t.Fatal(err)
			}
			kp := crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"resp": key})
			token := encryptWith(t, key.Public(), tt.keyAlg, tt.enc, payload)
			got, hdr, err := crypto.DecryptJWE(ctx, kp, "resp", token)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("payload = %q, want %q", got, payload)
			}
			if hdr["enc"] == nil || hdr["alg"] == nil {
				t.Errorf("header alg/enc missing: %v", hdr)
			}
		})
	}
}

func TestJWEWrongKeyFailsCleanly(t *testing.T) {
	right, _ := crypto.GenerateEphemeralKey("P-256")
	wrong, _ := crypto.GenerateEphemeralKey("P-256")
	token := encryptWith(t, right.Public(), jwa.ECDH_ES_A128KW(), jwa.A128GCM(), []byte("secret"))
	kp := crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"k": wrong})
	if _, _, err := crypto.DecryptJWE(context.Background(), kp, "k", token); !errors.Is(err, crypto.ErrDecryptionFailed) {
		t.Fatalf("err = %v, want ErrDecryptionFailed", err)
	}
}

// Disallowed enc must be rejected by the policy check on the protected
// header, before any decryption is attempted.
func TestJWEDisallowedEncRejected(t *testing.T) {
	key, _ := crypto.GenerateEphemeralKey("P-256")
	kp := crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"k": key})
	token := encryptWith(t, key.Public(), jwa.ECDH_ES(), jwa.A128CBC_HS256(), []byte("x"))
	if _, _, err := crypto.DecryptJWE(context.Background(), kp, "k", token); !errors.Is(err, crypto.ErrAlgorithmNotAllowed) {
		t.Fatalf("err = %v, want ErrAlgorithmNotAllowed", err)
	}
}

func TestJWEMalformedRejected(t *testing.T) {
	key, _ := crypto.GenerateEphemeralKey("P-256")
	kp := crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"k": key})
	for _, tok := range [][]byte{nil, []byte("a.b.c"), []byte("a.b.c.d.e.f"), []byte("!!!.a.a.a.a")} {
		if _, _, err := crypto.DecryptJWE(context.Background(), kp, "k", tok); !errors.Is(err, crypto.ErrMalformed) {
			t.Errorf("token %q: err = %v, want ErrMalformed", tok, err)
		}
	}
}

func TestGenerateEphemeralKey(t *testing.T) {
	for _, crv := range []string{"P-256", "P-384", "P-521"} {
		k, err := crypto.GenerateEphemeralKey(crv)
		if err != nil || k == nil {
			t.Errorf("GenerateEphemeralKey(%q): %v", crv, err)
		}
	}
	for _, crv := range []string{"P-192", "secp256k1", "X25519", ""} {
		if _, err := crypto.GenerateEphemeralKey(crv); !errors.Is(err, crypto.ErrCurveNotAllowed) {
			t.Errorf("GenerateEphemeralKey(%q): err = %v, want ErrCurveNotAllowed", crv, err)
		}
	}
}

func TestJWEKeyNotFoundRejected(t *testing.T) {
	key, err := crypto.GenerateEphemeralKey("P-256")
	if err != nil {
		t.Fatal(err)
	}
	token := encryptWith(t, key.Public(), jwa.ECDH_ES(), jwa.A128GCM(), []byte("x"))
	kp := crypto.NewStaticProvider(nil)
	if _, _, err := crypto.DecryptJWE(context.Background(), kp, "missing", token); !errors.Is(err, crypto.ErrKeyNotFound) {
		t.Fatalf("err = %v, want ErrKeyNotFound", err)
	}
}

// Decrypter keys must be EC (algorithms are derived from keys, never chosen
// by callers or tokens); an Ed25519-backed Decrypter is rejected before
// decryption is attempted.
func TestJWENonECDecrypterRejected(t *testing.T) {
	key, err := crypto.GenerateEphemeralKey("P-256")
	if err != nil {
		t.Fatal(err)
	}
	token := encryptWith(t, key.Public(), jwa.ECDH_ES(), jwa.A128GCM(), []byte("x"))
	if _, _, err := crypto.DecryptJWE(context.Background(), newNonECKeyProvider(t), "k", token); !errors.Is(err, crypto.ErrKeyTypeNotAllowed) {
		t.Fatalf("err = %v, want ErrKeyTypeNotAllowed", err)
	}
}

// craftJWE builds a 5-segment compact token with an arbitrary protected
// header; the remaining segments are empty since checkCrit/policy rejection
// happens before decryption is ever attempted.
func craftJWE(t *testing.T, header map[string]any) []byte {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	seg := base64.RawURLEncoding.EncodeToString(h)
	return []byte(seg + "....")
}

// RFC 7516 §4.1.13: we support no crit extensions, so any crit is rejected —
// before a decrypter is ever requested.
func TestJWECritRejected(t *testing.T) {
	key, err := crypto.GenerateEphemeralKey("P-256")
	if err != nil {
		t.Fatal(err)
	}
	kp := crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"k": key})
	tok := craftJWE(t, map[string]any{"alg": "ECDH-ES", "enc": "A128GCM", "crit": []string{"exp"}, "exp": 1})
	if _, _, err := crypto.DecryptJWE(context.Background(), kp, "k", tok); !errors.Is(err, crypto.ErrCritUnsupported) {
		t.Fatalf("err = %v, want ErrCritUnsupported", err)
	}
}

// jwx silently inflates a "zip":"DEF" payload before decryption ever sees
// the plaintext; DEFLATE is not an ECCG/HAIP mechanism, so a compressed JWE
// must be rejected outright.
func TestJWECompressionRejected(t *testing.T) {
	key, err := crypto.GenerateEphemeralKey("P-256")
	if err != nil {
		t.Fatal(err)
	}
	kp := crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"k": key})
	token, err := jwe.Encrypt([]byte("payload"), jwe.WithKey(jwa.ECDH_ES(), key.Public()),
		jwe.WithContentEncryption(jwa.A128GCM()), jwe.WithCompress(jwa.Deflate()))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := crypto.DecryptJWE(context.Background(), kp, "k", token); !errors.Is(err, crypto.ErrAlgorithmNotAllowed) {
		t.Fatalf("err = %v, want ErrAlgorithmNotAllowed", err)
	}
}

func TestJWEP521Roundtrip(t *testing.T) {
	// sanity-check a full non-P-256 roundtrip on an allowed curve
	key := genKey(t, elliptic.P521())
	kp := crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"k": key})
	token := encryptWith(t, key.Public(), jwa.ECDH_ES(), jwa.A256GCM(), []byte("y"))
	if _, _, err := crypto.DecryptJWE(context.Background(), kp, "k", token); err != nil {
		t.Fatal(err)
	}
}
