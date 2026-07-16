package crypto_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

func selfSignedCert(t *testing.T, key *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func protectedHeader(t *testing.T, token []byte) map[string]any {
	t.Helper()
	head, _, _ := bytes.Cut(token, []byte("."))
	raw, err := base64.RawURLEncoding.DecodeString(string(head))
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

// SignJWS accepts an x5c chain as []*x509.Certificate and serializes it as the
// [RFC 7515 §4.1.6] array of base64 (standard, not URL) DER strings. Needed
// to sign the JAR with the WRPAC chain ([CIR 2024/2982 Art. 3]).
func TestSignJWSWithX5C(t *testing.T) {
	ctx := context.Background()
	key := genKey(t, elliptic.P256())
	leaf := selfSignedCert(t, key, "rp.example")
	kp := memProvider{"sign": key}

	token, err := crypto.SignJWS(ctx, kp, "sign", map[string]any{"x5c": []*x509.Certificate{leaf}}, []byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("SignJWS: %v", err)
	}

	hdr := protectedHeader(t, token)
	x5c, ok := hdr["x5c"].([]any)
	if !ok || len(x5c) != 1 {
		t.Fatalf("x5c header = %v (%T), want 1-element array", hdr["x5c"], hdr["x5c"])
	}
	if got, want := x5c[0].(string), base64.StdEncoding.EncodeToString(leaf.Raw); got != want {
		t.Errorf("x5c[0] = %q, want base64-std DER %q", got, want)
	}
	// Signature still verifies against the signing key (x5c is a header only;
	// key resolution/trust belongs to the caller, not this library).
	if _, _, err := crypto.VerifyJWS(token, key.Public()); err != nil {
		t.Errorf("VerifyJWS: %v", err)
	}
}

func TestSignJWSRejectsBadX5CType(t *testing.T) {
	key := genKey(t, elliptic.P256())
	kp := memProvider{"sign": key}
	if _, err := crypto.SignJWS(context.Background(), kp, "sign", map[string]any{"x5c": []string{"nope"}}, []byte("p")); !errors.Is(err, crypto.ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed", err)
	}
}
