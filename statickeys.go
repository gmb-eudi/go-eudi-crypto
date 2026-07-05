package crypto

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"fmt"
)

// StaticProvider is an in-memory KeyProvider for per-session ephemeral keys
// (GenerateEphemeralKey) and tests. The map is copied at construction and
// immutable afterwards, so concurrent use needs no locking.
type StaticProvider struct {
	keys map[string]*ecdsa.PrivateKey
}

// NewStaticProvider returns a StaticProvider serving the given keys. The
// map is copied, so callers may safely mutate their own copy afterwards.
func NewStaticProvider(keys map[string]*ecdsa.PrivateKey) *StaticProvider {
	cp := make(map[string]*ecdsa.PrivateKey, len(keys))
	for id, k := range keys {
		cp[id] = k
	}
	return &StaticProvider{keys: cp}
}

func (p *StaticProvider) get(keyID string) (*ecdsa.PrivateKey, error) {
	k, ok := p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrKeyNotFound, keyID)
	}
	return k, nil
}

// Signer returns the EC private key matching keyID as a crypto.Signer.
func (p *StaticProvider) Signer(_ context.Context, keyID string) (stdcrypto.Signer, error) {
	return p.get(keyID)
}

// Decrypter returns a Decrypter wrapping the EC private key matching keyID.
func (p *StaticProvider) Decrypter(_ context.Context, keyID string) (Decrypter, error) {
	k, err := p.get(keyID)
	if err != nil {
		return nil, err
	}
	return staticDecrypter{k}, nil
}

// Public returns the EC public key matching keyID.
func (p *StaticProvider) Public(_ context.Context, keyID string) (stdcrypto.PublicKey, error) {
	k, err := p.get(keyID)
	if err != nil {
		return nil, err
	}
	return k.Public(), nil
}

type staticDecrypter struct{ k *ecdsa.PrivateKey }

func (d staticDecrypter) PrivateKey() stdcrypto.PrivateKey { return d.k }
