package filekeys_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
	"github.com/gmb-eudi/go-eudi-crypto/filekeys"
)

func writePKCS8(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "key.pem")
	buf := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(p, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeSEC1(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "key.pem")
	buf := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(p, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func genEC(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestLoadECKeys(t *testing.T) {
	p256 := genEC(t, elliptic.P256())
	p384 := genEC(t, elliptic.P384())
	prov, err := filekeys.New(map[string]string{
		"sign-p256": writePKCS8(t, p256),
		"sign-p384": writeSEC1(t, p384),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, id := range []string{"sign-p256", "sign-p384"} {
		s, err := prov.Signer(ctx, id)
		if err != nil {
			t.Fatalf("Signer(%q): %v", id, err)
		}
		if _, ok := s.Public().(*ecdsa.PublicKey); !ok {
			t.Fatalf("Signer(%q).Public() is %T, want *ecdsa.PublicKey", id, s.Public())
		}
		pub, err := prov.Public(ctx, id)
		if err != nil || pub == nil {
			t.Fatalf("Public(%q): %v", id, err)
		}
		d, err := prov.Decrypter(ctx, id)
		if err != nil || d.PrivateKey() == nil {
			t.Fatalf("Decrypter(%q): %v", id, err)
		}
	}
}

func TestRejectNonECKeys(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, err = filekeys.New(map[string]string{"k": writePKCS8(t, rsaKey)})
	if !errors.Is(err, crypto.ErrKeyTypeNotAllowed) {
		t.Fatalf("RSA key: err = %v, want ErrKeyTypeNotAllowed", err)
	}
}

func TestRejectUnknownKeyID(t *testing.T) {
	prov, err := filekeys.New(map[string]string{"a": writePKCS8(t, genEC(t, elliptic.P256()))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prov.Signer(context.Background(), "nope"); !errors.Is(err, crypto.ErrKeyNotFound) {
		t.Fatalf("err = %v, want ErrKeyNotFound", err)
	}
}

func TestRejectMalformedPEM(t *testing.T) {
	p := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(p, []byte("not pem at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := filekeys.New(map[string]string{"k": p}); !errors.Is(err, crypto.ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

// P-224 is a valid EC curve but not ECCG-allowed; New must reject the key
// file outright (fail closed: unknown/disallowed curve is never accepted).
func TestRejectDisallowedCurve(t *testing.T) {
	key := genEC(t, elliptic.P224())
	_, err := filekeys.New(map[string]string{"k": writePKCS8(t, key)})
	if !errors.Is(err, crypto.ErrCurveNotAllowed) {
		t.Fatalf("err = %v, want ErrCurveNotAllowed", err)
	}
}

func TestNewNonexistentPath(t *testing.T) {
	_, err := filekeys.New(map[string]string{"k": filepath.Join(t.TempDir(), "does-not-exist.pem")})
	if err == nil {
		t.Fatal("err = nil, want error for nonexistent key file")
	}
}

func TestDecrypterAndPublicUnknownKeyID(t *testing.T) {
	prov, err := filekeys.New(map[string]string{"a": writePKCS8(t, genEC(t, elliptic.P256()))})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := prov.Decrypter(ctx, "nope"); !errors.Is(err, crypto.ErrKeyNotFound) {
		t.Fatalf("Decrypter: err = %v, want ErrKeyNotFound", err)
	}
	if _, err := prov.Public(ctx, "nope"); !errors.Is(err, crypto.ErrKeyNotFound) {
		t.Fatalf("Public: err = %v, want ErrKeyNotFound", err)
	}
}

// Run with -race: provider must be safe for concurrent use.
func TestConcurrentAccess(t *testing.T) {
	prov, err := filekeys.New(map[string]string{"a": writePKCS8(t, genEC(t, elliptic.P256()))})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := prov.Signer(ctx, "a"); err != nil {
				t.Error(err)
			}
			if _, err := prov.Public(ctx, "a"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
