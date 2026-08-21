// Package filekeys is the file-based (PEM/PKCS#8) KeyProvider for
// development and tests. EC keys on ECCG-allowed curves only.
package filekeys

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

// Provider loads all keys eagerly at construction; the map is immutable
// afterwards, so concurrent use needs no locking.
type Provider struct {
	keys map[string]*ecdsa.PrivateKey
}

// New loads one PEM file per key ID. Fails closed on the first key that is
// not an EC key on an ECCG-allowed curve (algorithms are derived from keys,
// never chosen by callers or tokens).
func New(paths map[string]string) (*Provider, error) {
	keys := make(map[string]*ecdsa.PrivateKey, len(paths))
	for id, path := range paths {
		k, err := loadECKey(path)
		if err != nil {
			return nil, fmt.Errorf("filekeys: key %q: %w", id, err)
		}
		keys[id] = k
	}
	return &Provider{keys: keys}, nil
}

func loadECKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path comes from operator configuration, not untrusted input
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block", crypto.ErrMalformed)
	}
	switch block.Type {
	case "PRIVATE KEY": // PKCS#8
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", crypto.ErrMalformed, err)
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: PKCS#8 key is %T, EC required", crypto.ErrKeyTypeNotAllowed, k)
		}
		return checkCurve(ec)
	case "EC PRIVATE KEY": // SEC1
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", crypto.ErrMalformed, err)
		}
		return checkCurve(k)
	default:
		return nil, fmt.Errorf("%w: PEM type %q", crypto.ErrKeyTypeNotAllowed, block.Type)
	}
}

func checkCurve(k *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
	name := k.Curve.Params().Name
	if !crypto.ECCG().AllowedCurve(name) {
		return nil, fmt.Errorf("%w: %s", crypto.ErrCurveNotAllowed, name)
	}
	return k, nil
}

func (p *Provider) get(keyID string) (*ecdsa.PrivateKey, error) {
	k, ok := p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", crypto.ErrKeyNotFound, keyID)
	}
	return k, nil
}

// Signer returns the EC private key matching keyID as a crypto.Signer.
func (p *Provider) Signer(_ context.Context, keyID string) (stdcrypto.Signer, error) {
	return p.get(keyID)
}

// Decrypter returns a Decrypter wrapping the EC private key matching keyID.
func (p *Provider) Decrypter(_ context.Context, keyID string) (crypto.Decrypter, error) {
	k, err := p.get(keyID)
	if err != nil {
		return nil, err
	}
	return keyDecrypter{k}, nil
}

// Public returns the EC public key matching keyID.
func (p *Provider) Public(_ context.Context, keyID string) (stdcrypto.PublicKey, error) {
	k, err := p.get(keyID)
	if err != nil {
		return nil, err
	}
	return k.Public(), nil
}

type keyDecrypter struct{ k *ecdsa.PrivateKey }

func (d keyDecrypter) PrivateKey() stdcrypto.PrivateKey { return d.k }
