// Package crypto is the single cryptographic policy and primitives layer for
// the gmb-eudi EUDI modules. All JOSE/COSE/X.509 operations go through this
// package; no other module names an algorithm (ECCG Agreed Cryptographic
// Mechanisms v2.0, EW-PIO-01-003).
//
// Import with an alias to avoid clashing with the standard library:
//
//	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
package crypto
