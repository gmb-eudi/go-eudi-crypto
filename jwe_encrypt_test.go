package crypto_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"testing"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

func TestEncryptJWERoundtrip(t *testing.T) {
	k := genKey(t, elliptic.P256())
	kp := crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"k": k})

	token, err := crypto.EncryptJWE(k.Public(), map[string]any{"apu": "bWRvY05vbmNl"}, []byte(`{"vp_token":{}}`))
	if err != nil {
		t.Fatalf("EncryptJWE: %v", err)
	}

	plain, hdr, err := crypto.DecryptJWE(context.Background(), kp, "k", token)
	if err != nil {
		t.Fatalf("DecryptJWE: %v", err)
	}
	if string(plain) != `{"vp_token":{}}` {
		t.Errorf("plaintext = %q, want %q", plain, `{"vp_token":{}}`)
	}
	if hdr["apu"] != "bWRvY05vbmNl" {
		t.Errorf("apu header = %v, want bWRvY05vbmNl", hdr["apu"])
	}
}

func TestEncryptJWERejectsNonECKey(t *testing.T) {
	if _, err := crypto.EncryptJWE("not a key", nil, []byte("x")); !errors.Is(err, crypto.ErrKeyTypeNotAllowed) {
		t.Errorf("err = %v, want ErrKeyTypeNotAllowed", err)
	}
}

// alg/enc/epk are set by the library from policy; callers must not supply them.
func TestEncryptJWERejectsLibraryOwnedHeaders(t *testing.T) {
	k := genKey(t, elliptic.P256())
	for _, h := range []string{"alg", "enc", "epk"} {
		if _, err := crypto.EncryptJWE(k.Public(), map[string]any{h: "x"}, []byte("p")); !errors.Is(err, crypto.ErrProtectedHeader) {
			t.Errorf("header %q: err = %v, want ErrProtectedHeader", h, err)
		}
	}
}
