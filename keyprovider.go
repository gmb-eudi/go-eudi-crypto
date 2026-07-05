package crypto

import (
	"context"
	stdcrypto "crypto"
)

// KeyProvider abstracts access to the operator's private keys. Planned
// implementations: filekeys (PEM/PKCS#8, dev), k8ssecret, pkcs11 (build
// tag), kms — only filekeys and the in-memory StaticProvider ship today.
type KeyProvider interface {
	Signer(ctx context.Context, keyID string) (stdcrypto.Signer, error)
	Decrypter(ctx context.Context, keyID string) (Decrypter, error)
	Public(ctx context.Context, keyID string) (stdcrypto.PublicKey, error)
}

// Decrypter exposes the private key material needed for JWE ECDH-ES key
// agreement (RFC 7518 §4.6). In-memory implementations return the key
// directly; HSM-backed implementations require a native-decrypt extension of
// this interface — revisited when an HSM-backed provider lands.
type Decrypter interface {
	PrivateKey() stdcrypto.PrivateKey
}
