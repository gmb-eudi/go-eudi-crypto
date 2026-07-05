package crypto_test

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

func TestJWSSignVerifyRoundtrip(t *testing.T) {
	ctx := context.Background()
	payload := []byte(`{"hello":"world"}`)
	for _, tt := range []struct {
		name  string
		curve elliptic.Curve
		alg   string
	}{
		{"ES256_P256", elliptic.P256(), "ES256"},
		{"ES384_P384", elliptic.P384(), "ES384"},
		{"ES512_P521", elliptic.P521(), "ES512"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key := genKey(t, tt.curve)
			kp := memProvider{"sign": key}
			token, err := crypto.SignJWS(ctx, kp, "sign", map[string]any{"typ": "oauth-authz-req+jwt"}, payload)
			if err != nil {
				t.Fatal(err)
			}
			got, hdr, err := crypto.VerifyJWS(token, key.Public())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("payload = %q, want %q", got, payload)
			}
			if hdr["alg"] != tt.alg {
				t.Errorf("alg = %v, want %s", hdr["alg"], tt.alg)
			}
			if hdr["typ"] != "oauth-authz-req+jwt" {
				t.Errorf("typ = %v not preserved", hdr["typ"])
			}
		})
	}
}

func TestJWSTamperedPayloadFails(t *testing.T) {
	key := genKey(t, elliptic.P256())
	token, err := crypto.SignJWS(context.Background(), memProvider{"k": key}, "k", nil, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	parts := bytes.Split(token, []byte("."))
	parts[1] = []byte(base64.RawURLEncoding.EncodeToString([]byte("tampered")))
	if _, _, err := crypto.VerifyJWS(bytes.Join(parts, []byte(".")), key.Public()); !errors.Is(err, crypto.ErrVerificationFailed) {
		t.Fatalf("err = %v, want ErrVerificationFailed", err)
	}
}

// craft builds an unsigned compact token with an arbitrary protected header;
// the signature is garbage — header checks must reject before verification.
func craft(t *testing.T, header map[string]any, payload string) []byte {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	return []byte(enc.EncodeToString(h) + "." + enc.EncodeToString([]byte(payload)) + "." + enc.EncodeToString([]byte("sig")))
}

func TestJWSAlgNoneRejected(t *testing.T) {
	key := genKey(t, elliptic.P256())
	tok := craft(t, map[string]any{"alg": "none"}, "x")
	if _, _, err := crypto.VerifyJWS(tok, key.Public()); !errors.Is(err, crypto.ErrAlgorithmNotAllowed) {
		t.Fatalf("err = %v, want ErrAlgorithmNotAllowed", err)
	}
}

// Alg-confusion: RS256 token presented against an EC key (RFC 8725 §2.1).
func TestJWSAlgConfusionRejected(t *testing.T) {
	key := genKey(t, elliptic.P256())
	tok := craft(t, map[string]any{"alg": "RS256"}, "x")
	if _, _, err := crypto.VerifyJWS(tok, key.Public()); !errors.Is(err, crypto.ErrAlgorithmNotAllowed) {
		t.Fatalf("err = %v, want ErrAlgorithmNotAllowed", err)
	}
}

// Allowed-but-mismatched: ES384 is on the ECCG allow-list, but the key
// demands ES256 for its curve — this must still surface as a key mismatch,
// not an off-policy algorithm.
func TestJWSAllowedButMismatchedAlgRejected(t *testing.T) {
	key := genKey(t, elliptic.P256()) // key demands ES256
	tok := craft(t, map[string]any{"alg": "ES384"}, "x")
	if _, _, err := crypto.VerifyJWS(tok, key.Public()); !errors.Is(err, crypto.ErrAlgKeyMismatch) {
		t.Fatalf("err = %v, want ErrAlgKeyMismatch", err)
	}
}

// RFC 7515 §4.1.11: we support no crit extensions, so any crit is rejected —
// before signature verification.
func TestJWSCritRejected(t *testing.T) {
	key := genKey(t, elliptic.P256())
	tok := craft(t, map[string]any{"alg": "ES256", "crit": []string{"exp"}, "exp": 1}, "x")
	if _, _, err := crypto.VerifyJWS(tok, key.Public()); !errors.Is(err, crypto.ErrCritUnsupported) {
		t.Fatalf("err = %v, want ErrCritUnsupported", err)
	}
}

func TestJWSWrongKeyTypeRejected(t *testing.T) {
	if _, _, err := crypto.VerifyJWS([]byte("a.b.c"), "not a key"); !errors.Is(err, crypto.ErrKeyTypeNotAllowed) {
		t.Fatalf("err = %v, want ErrKeyTypeNotAllowed", err)
	}
}

func TestJWSMalformedTokenRejected(t *testing.T) {
	key := genKey(t, elliptic.P256())
	for _, tok := range [][]byte{nil, []byte(""), []byte("onlyonepart"), []byte("a.b"), []byte("a.b.c.d.e"), []byte("!!!.###.$$$")} {
		if _, _, err := crypto.VerifyJWS(tok, key.Public()); !errors.Is(err, crypto.ErrMalformed) {
			t.Errorf("token %q: err = %v, want ErrMalformed", tok, err)
		}
	}
}

// Callers must not smuggle an alg choice (algorithms are derived from keys,
// never chosen by callers or tokens).
func TestSignJWSRejectsCallerAlg(t *testing.T) {
	key := genKey(t, elliptic.P256())
	_, err := crypto.SignJWS(context.Background(), memProvider{"k": key}, "k", map[string]any{"alg": "ES384"}, []byte("x"))
	if !errors.Is(err, crypto.ErrProtectedHeader) {
		t.Fatalf("err = %v, want ErrProtectedHeader", err)
	}
}

// Callers must not smuggle crit extensions either — SignJWS must never mint
// a token that VerifyJWS would then reject as ErrCritUnsupported.
func TestSignJWSRejectsCallerCrit(t *testing.T) {
	key := genKey(t, elliptic.P256())
	_, err := crypto.SignJWS(context.Background(), memProvider{"k": key}, "k", map[string]any{"crit": []string{"x"}}, []byte("x"))
	if !errors.Is(err, crypto.ErrProtectedHeader) {
		t.Fatalf("err = %v, want ErrProtectedHeader", err)
	}
}

func TestSignJWSKeyNotFoundRejected(t *testing.T) {
	_, err := crypto.SignJWS(context.Background(), memProvider{}, "missing", nil, []byte("x"))
	if !errors.Is(err, crypto.ErrKeyNotFound) {
		t.Fatalf("err = %v, want ErrKeyNotFound", err)
	}
}

// Signer keys must be EC (algorithms are derived from keys, never chosen by
// callers or tokens); an Ed25519 signer is rejected before any algorithm
// negotiation.
func TestSignJWSNonECSignerRejected(t *testing.T) {
	_, err := crypto.SignJWS(context.Background(), newNonECKeyProvider(t), "k", nil, []byte("x"))
	if !errors.Is(err, crypto.ErrKeyTypeNotAllowed) {
		t.Fatalf("err = %v, want ErrKeyTypeNotAllowed", err)
	}
}

// P-224 is a valid EC curve but not ECCG-allowed; both signing and
// verification must reject it (fail closed: unknown/disallowed curve is
// never accepted).
func TestJWSUnsupportedCurveRejected(t *testing.T) {
	key := genKey(t, elliptic.P224())
	if _, err := crypto.SignJWS(context.Background(), memProvider{"k": key}, "k", nil, []byte("x")); !errors.Is(err, crypto.ErrCurveNotAllowed) {
		t.Fatalf("SignJWS err = %v, want ErrCurveNotAllowed", err)
	}
	if _, _, err := crypto.VerifyJWS([]byte("a.b.c"), key.Public()); !errors.Is(err, crypto.ErrCurveNotAllowed) {
		t.Fatalf("VerifyJWS err = %v, want ErrCurveNotAllowed", err)
	}
}

// A protected header value of the wrong type for its key (e.g. b64 must be
// bool per RFC 7797) must be rejected, not silently coerced.
func TestSignJWSInvalidHeaderValueRejected(t *testing.T) {
	key := genKey(t, elliptic.P256())
	_, err := crypto.SignJWS(context.Background(), memProvider{"k": key}, "k", map[string]any{"b64": "not-a-bool"}, []byte("x"))
	if !errors.Is(err, crypto.ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}
