package crypto_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"testing"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

func TestStaticProviderFound(t *testing.T) {
	key := genKey(t, elliptic.P256())
	kp := crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"k": key})
	ctx := context.Background()

	signer, err := kp.Signer(ctx, "k")
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	if _, ok := signer.Public().(*ecdsa.PublicKey); !ok {
		t.Errorf("Signer.Public() = %T, want *ecdsa.PublicKey", signer.Public())
	}

	dec, err := kp.Decrypter(ctx, "k")
	if err != nil {
		t.Fatalf("Decrypter: %v", err)
	}
	if _, ok := dec.PrivateKey().(*ecdsa.PrivateKey); !ok {
		t.Errorf("Decrypter.PrivateKey() = %T, want *ecdsa.PrivateKey", dec.PrivateKey())
	}

	pub, err := kp.Public(ctx, "k")
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Errorf("Public() = %T, want *ecdsa.PublicKey", pub)
	}
}

func TestStaticProviderNotFound(t *testing.T) {
	kp := crypto.NewStaticProvider(nil)
	ctx := context.Background()

	if _, err := kp.Signer(ctx, "missing"); !errors.Is(err, crypto.ErrKeyNotFound) {
		t.Errorf("Signer: err = %v, want ErrKeyNotFound", err)
	}
	if _, err := kp.Decrypter(ctx, "missing"); !errors.Is(err, crypto.ErrKeyNotFound) {
		t.Errorf("Decrypter: err = %v, want ErrKeyNotFound", err)
	}
	if _, err := kp.Public(ctx, "missing"); !errors.Is(err, crypto.ErrKeyNotFound) {
		t.Errorf("Public: err = %v, want ErrKeyNotFound", err)
	}
}
