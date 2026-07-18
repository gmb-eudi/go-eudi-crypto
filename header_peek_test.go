package crypto_test

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

// b64url helps build hand-crafted tokens for the malformed/structural cases
// (no signature is ever needed — ParseJWSHeader is structural only).
func b64url(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

// ParseJWSHeader must structurally read the protected header of a real
// SignJWS output WITHOUT verifying the signature ([RFC 7515 §4.1]). The alg is
// present because SignJWS derives it from the key.
func TestParseJWSHeaderRoundTripNoX5C(t *testing.T) {
	key := genKey(t, elliptic.P256())
	kp := memProvider{"sign": key}
	tok, err := crypto.SignJWS(context.Background(), kp, "sign", nil, []byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("SignJWS: %v", err)
	}
	h, err := crypto.ParseJWSHeader(tok)
	if err != nil {
		t.Fatalf("ParseJWSHeader: %v", err)
	}
	if h["alg"] != "ES256" {
		t.Errorf("alg = %v, want ES256", h["alg"])
	}
	certs, err := crypto.X5CFromHeader(h)
	if err != nil {
		t.Fatalf("X5CFromHeader: %v", err)
	}
	if certs != nil {
		t.Errorf("X5CFromHeader = %v, want nil (no x5c member)", certs)
	}
}

// The x5c round-trip must preserve leaf-first order and exact DER bytes: what
// X5CFromHeader decodes must equal what SignJWS embedded ([RFC 7515 §4.1.6]).
func TestParseJWSHeaderX5CRoundTrip(t *testing.T) {
	key := genKey(t, elliptic.P256())
	kp := memProvider{"sign": key}
	leaf := selfSignedCert(t, key, "leaf.example")
	ca := selfSignedCert(t, key, "ca.example")
	chain := []*x509.Certificate{leaf, ca}

	tok, err := crypto.SignJWS(context.Background(), kp, "sign", map[string]any{"x5c": chain}, []byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("SignJWS: %v", err)
	}
	h, err := crypto.ParseJWSHeader(tok)
	if err != nil {
		t.Fatalf("ParseJWSHeader: %v", err)
	}
	got, err := crypto.X5CFromHeader(h)
	if err != nil {
		t.Fatalf("X5CFromHeader: %v", err)
	}
	if len(got) != len(chain) {
		t.Fatalf("got %d certs, want %d", len(got), len(chain))
	}
	for i := range chain {
		if !bytes.Equal(got[i].Raw, chain[i].Raw) {
			t.Errorf("cert[%d] DER mismatch (order or bytes wrong)", i)
		}
	}
}

// {} is a valid (if empty) JSON-object header — return an empty Header, not an
// error. This proves ParseJWSHeader does not require any particular member.
func TestParseJWSHeaderEmptyObjectIsValid(t *testing.T) {
	tok := []byte(b64url("{}") + "." + b64url("payload") + "." + b64url("sig"))
	h, err := crypto.ParseJWSHeader(tok)
	if err != nil {
		t.Fatalf("ParseJWSHeader({}) = %v, want no error", err)
	}
	if h == nil || len(h) != 0 {
		t.Errorf("header = %v, want empty Header{}", h)
	}
}

func TestParseJWSHeaderMalformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":               []byte(""),
		"one segment":         []byte("abc"),
		"two segments":        []byte("a.b"),
		"four segments":       []byte("a.b.c.d"),
		"empty head segment":  []byte("." + b64url("payload") + "." + b64url("sig")),
		"empty middle":        []byte(b64url("{}") + ".." + b64url("sig")),
		"empty sig":           []byte(b64url("{}") + "." + b64url("payload") + "."),
		"garbage base64 head": []byte("!!!." + b64url("payload") + "." + b64url("sig")),
		"non-json header":     []byte(b64url("notjson") + "." + b64url("payload") + "." + b64url("sig")),
		"array header":        []byte(b64url("[1,2]") + "." + b64url("payload") + "." + b64url("sig")),
		"null header":         []byte(b64url("null") + "." + b64url("payload") + "." + b64url("sig")),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := crypto.ParseJWSHeader(tok); !errors.Is(err, crypto.ErrMalformed) {
				t.Errorf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestX5CFromHeaderAbsent(t *testing.T) {
	got, err := crypto.X5CFromHeader(crypto.Header{"alg": "ES256"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != nil {
		t.Errorf("got = %v, want nil for absent x5c", got)
	}
}

func TestX5CFromHeaderMalformed(t *testing.T) {
	key := genKey(t, elliptic.P256())
	goodCertDER := selfSignedCert(t, key, "x").Raw
	cases := map[string]crypto.Header{
		"not an array":     {"x5c": "not-an-array"},
		"non-string entry": {"x5c": []any{123}},
		"bad base64":       {"x5c": []any{"!!!not-base64!!!"}},
		"bad der":          {"x5c": []any{base64.StdEncoding.EncodeToString([]byte("not-a-cert"))}},
		"good then bad":    {"x5c": []any{base64.StdEncoding.EncodeToString(goodCertDER), "!!!"}},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := crypto.X5CFromHeader(h); !errors.Is(err, crypto.ErrMalformed) {
				t.Errorf("err = %v, want ErrMalformed", err)
			}
		})
	}
}
