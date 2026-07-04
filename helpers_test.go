package crypto_test

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

// memProvider is a minimal in-memory KeyProvider for tests.
type memProvider map[string]*ecdsa.PrivateKey

func (m memProvider) Signer(_ context.Context, id string) (stdcrypto.Signer, error) {
	k, ok := m[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", crypto.ErrKeyNotFound, id)
	}
	return k, nil
}

func (m memProvider) Decrypter(_ context.Context, id string) (crypto.Decrypter, error) {
	k, ok := m[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", crypto.ErrKeyNotFound, id)
	}
	return memDecrypter{k}, nil
}

func (m memProvider) Public(_ context.Context, id string) (stdcrypto.PublicKey, error) {
	k, ok := m[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", crypto.ErrKeyNotFound, id)
	}
	return k.Public(), nil
}

type memDecrypter struct{ k *ecdsa.PrivateKey }

func (d memDecrypter) PrivateKey() stdcrypto.PrivateKey { return d.k }

func genKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// nonECKeyProvider is a KeyProvider backed by an Ed25519 key. It exists to
// exercise the "signer/decrypter key is not EC" rejection paths (only EC keys
// are accepted; algorithms are derived from keys, never chosen by callers) in
// SignJWS, SignCOSESign1 and DecryptJWE.
type nonECKeyProvider struct{ key ed25519.PrivateKey }

func newNonECKeyProvider(t *testing.T) nonECKeyProvider {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return nonECKeyProvider{key: priv}
}

func (p nonECKeyProvider) Signer(_ context.Context, _ string) (stdcrypto.Signer, error) {
	return p.key, nil
}

func (p nonECKeyProvider) Decrypter(_ context.Context, _ string) (crypto.Decrypter, error) {
	return nonECDecrypter{p.key}, nil
}

func (p nonECKeyProvider) Public(_ context.Context, _ string) (stdcrypto.PublicKey, error) {
	return p.key.Public(), nil
}

type nonECDecrypter struct{ k ed25519.PrivateKey }

func (d nonECDecrypter) PrivateKey() stdcrypto.PrivateKey { return d.k }
