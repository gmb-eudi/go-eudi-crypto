package crypto_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

// Parsers of untrusted input must not panic on malformed input — fuzzing
// verifies that. Each target seeds its corpus with one valid artifact and
// known edge cases.

func fuzzKey(f *testing.F) *ecdsa.PrivateKey {
	f.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	return k
}

func FuzzVerifyJWS(f *testing.F) {
	key := fuzzKey(f)
	token, err := crypto.SignJWS(context.Background(), crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"k": key}), "k", nil, []byte(`{"a":1}`))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(token)
	f.Add([]byte("eyJhbGciOiJub25lIn0..")) // alg:none skeleton
	f.Add([]byte("a.b.c"))
	f.Add([]byte(""))
	pub := key.Public()
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _, _ = crypto.VerifyJWS(data, pub) // must not panic
	})
}

func FuzzDecryptJWE(f *testing.F) {
	key := fuzzKey(f)
	kp := crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"k": key})
	token, err := jwe.Encrypt([]byte("seed"), jwe.WithKey(jwa.ECDH_ES(), key.Public()), jwe.WithContentEncryption(jwa.A128GCM()))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(token)
	f.Add([]byte("a.b.c.d.e"))
	f.Add([]byte(""))
	ctx := context.Background()
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _, _ = crypto.DecryptJWE(ctx, kp, "k", data) // must not panic
	})
}

func FuzzVerifyCOSESign1(f *testing.F) {
	key := fuzzKey(f)
	msg, err := crypto.SignCOSESign1(context.Background(), crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"k": key}), "k", nil, []byte("seed"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(msg)
	f.Add([]byte{0xd2, 0x84}) // truncated Sign1
	f.Add([]byte(""))
	pub := key.Public()
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _, _ = crypto.VerifyCOSESign1(data, pub) // must not panic
	})
}

func FuzzParseCertChain(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "seed"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(der)
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	f.Add([]byte(""))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = crypto.ParseCertChain(data) // must not panic
	})
}
