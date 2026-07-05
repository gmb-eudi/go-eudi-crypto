package crypto_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

func TestECPublicKeyJWKRoundtrip(t *testing.T) {
	for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		k := genKey(t, c)
		jwk, err := crypto.ECPublicKeyToJWK(k.Public())
		if err != nil {
			t.Fatalf("ECPublicKeyToJWK(%s): %v", c.Params().Name, err)
		}
		raw, err := json.Marshal(jwk)
		if err != nil {
			t.Fatal(err)
		}
		got, err := crypto.ParseECPublicKeyJWK(raw)
		if err != nil {
			t.Fatalf("ParseECPublicKeyJWK(%s): %v", c.Params().Name, err)
		}
		ec, ok := got.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("%s: got %T, want *ecdsa.PublicKey", c.Params().Name, got)
		}
		if !ec.Equal(k.Public()) {
			t.Errorf("%s: roundtrip public key mismatch", c.Params().Name)
		}
	}
}

func TestECPublicKeyToJWKRejectsNonEC(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.ECPublicKeyToJWK(priv.Public()); !errors.Is(err, crypto.ErrKeyTypeNotAllowed) {
		t.Errorf("err = %v, want ErrKeyTypeNotAllowed", err)
	}
}

func TestParseECPublicKeyJWKRejectsNonECKty(t *testing.T) {
	if _, err := crypto.ParseECPublicKeyJWK([]byte(`{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`)); !errors.Is(err, crypto.ErrKeyTypeNotAllowed) {
		t.Errorf("err = %v, want ErrKeyTypeNotAllowed", err)
	}
}

func TestParseECPublicKeyJWKRejectsDisallowedCurve(t *testing.T) {
	if _, err := crypto.ParseECPublicKeyJWK([]byte(`{"kty":"EC","crv":"P-192","x":"AAAA","y":"AAAA"}`)); !errors.Is(err, crypto.ErrCurveNotAllowed) {
		t.Errorf("err = %v, want ErrCurveNotAllowed", err)
	}
}

func TestParseECPublicKeyJWKRejectsMalformed(t *testing.T) {
	// A valid P-256 JWK with one byte of x flipped — the point leaves the curve
	// and must be rejected (point validation, not just shape checks).
	k := genKey(t, elliptic.P256())
	m, err := crypto.ECPublicKeyToJWK(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	xb, _ := base64.RawURLEncoding.DecodeString(m["x"].(string))
	xb[0] ^= 0xff
	m["x"] = base64.RawURLEncoding.EncodeToString(xb)
	offCurve, _ := json.Marshal(m)

	cases := map[string][]byte{
		"empty":            []byte(``),
		"not_json":         []byte(`not json`),
		"missing_kty":      []byte(`{}`),
		"missing_xy":       []byte(`{"kty":"EC","crv":"P-256"}`),
		"bad_base64":       []byte(`{"kty":"EC","crv":"P-256","x":"!!!!","y":"AAAA"}`),
		"wrong_coord_size": []byte(`{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA"}`),
		"off_curve":        offCurve,
	}
	for name, in := range cases {
		if _, err := crypto.ParseECPublicKeyJWK(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
