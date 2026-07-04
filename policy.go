package crypto

import (
	stdcrypto "crypto"
	"fmt"
	"strings"
)

// ECCGVersion is the pinned version of the ECCG Agreed Cryptographic
// Mechanisms document this policy table implements (EW-PIO-01-003).
const ECCGVersion = "2.0"

// Policy is the ECCG-pinned algorithm allow-list. Immutable; no env/config
// overrides for algorithms — they are derived from keys, never chosen by
// callers or tokens. Unknown = reject.
type Policy interface {
	AllowedJWSAlg(alg string) bool
	AllowedJWEAlg(alg, enc string) bool
	AllowedCOSEAlg(alg int64) bool
	AllowedCurve(crv string) bool
	HashForAlg(alg string) (stdcrypto.Hash, error)
	AllowedHashName(name string) bool
	HashForName(name string) (stdcrypto.Hash, error)
	HashForMSODigestAlg(alg string) (stdcrypto.Hash, error)
}

// ECCG returns the immutable policy singleton pinned to ECCGVersion.
func ECCG() Policy { return eccg }

type policy struct {
	jwsAlgs  map[string]stdcrypto.Hash
	jweAlgs  map[string]bool
	jweEncs  map[string]bool
	coseAlgs  map[int64]bool
	curves    map[string]bool
	hashNames map[string]stdcrypto.Hash
}

// The versioned table. ECCG v2.0 (EW-PIO-01-003): ECDSA on NIST curves only;
// HAIP 1.0 baseline ES256/P-256; JWE per HAIP: ECDH-ES key agreement with
// AES-GCM content encryption. COSE labels per RFC 9053 §2.1.
var eccg = &policy{
	jwsAlgs: map[string]stdcrypto.Hash{
		"ES256": stdcrypto.SHA256,
		"ES384": stdcrypto.SHA384,
		"ES512": stdcrypto.SHA512,
	},
	jweAlgs: map[string]bool{
		"ECDH-ES":        true,
		"ECDH-ES+A128KW": true,
		"ECDH-ES+A256KW": true,
	},
	jweEncs: map[string]bool{
		"A128GCM": true,
		"A256GCM": true,
	},
	coseAlgs: map[int64]bool{
		-7:  true, // ES256
		-35: true, // ES384
		-36: true, // ES512
	},
	curves: map[string]bool{
		"P-256": true,
		"P-384": true,
		"P-521": true,
	},
	// IANA "Named Information Hash Algorithm" values used by SD-JWT `_sd_alg`
	// (draft-ietf-oauth-sd-jwt §4.1.1). The single hash allow-list; mdoc's
	// uppercase MSO digestAlgorithm names map onto this via HashForMSODigestAlg.
	hashNames: map[string]stdcrypto.Hash{
		"sha-256": stdcrypto.SHA256,
		"sha-384": stdcrypto.SHA384,
		"sha-512": stdcrypto.SHA512,
	},
}

func (p *policy) AllowedJWSAlg(alg string) bool { _, ok := p.jwsAlgs[alg]; return ok }

func (p *policy) AllowedJWEAlg(alg, enc string) bool {
	return p.jweAlgs[alg] && p.jweEncs[enc]
}

func (p *policy) AllowedCOSEAlg(alg int64) bool { return p.coseAlgs[alg] }

func (p *policy) AllowedCurve(crv string) bool { return p.curves[crv] }

func (p *policy) HashForAlg(alg string) (stdcrypto.Hash, error) {
	h, ok := p.jwsAlgs[alg]
	if !ok {
		return 0, fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, alg)
	}
	return h, nil
}

// AllowedHashName reports whether name is an ECCG-allowed hash identifier in
// the IANA "Named Information Hash Algorithm" form used by SD-JWT `_sd_alg`
// (draft-ietf-oauth-sd-jwt §4.1.1). Unknown = reject.
func (p *policy) AllowedHashName(name string) bool {
	if name == "" {
		return true // SD-JWT §4.1.1: absent _sd_alg = scheme default (baseline digest)
	}
	_, ok := p.hashNames[name]
	return ok
}

// HashForName maps an SD-JWT `_sd_alg` hash identifier (e.g. "sha-256") to its
// crypto.Hash. The empty string is the "scheme default" and resolves to the
// baseline digest sha-256 (SD-JWT §4.1.1: absent _sd_alg). Unknown = reject.
func (p *policy) HashForName(name string) (stdcrypto.Hash, error) {
	if name == "" {
		return p.hashNames["sha-256"], nil
	}
	h, ok := p.hashNames[name]
	if !ok {
		return 0, fmt.Errorf("%w: hash name %q", ErrAlgorithmNotAllowed, name)
	}
	return h, nil
}

// HashForMSODigestAlg maps an ISO/IEC 18013-5 MSO `digestAlgorithm` value
// (uppercase "SHA-256"/"SHA-384"/"SHA-512", ISO 18013-5 §9.1.2.5) to its
// crypto.Hash, reusing the single hash allow-list behind HashForName. Only the
// exact uppercase SHA-2 spellings are accepted; anything else = reject.
func (p *policy) HashForMSODigestAlg(alg string) (stdcrypto.Hash, error) {
	switch alg {
	case "SHA-256", "SHA-384", "SHA-512":
		return p.HashForName(strings.ToLower(alg))
	default:
		return 0, fmt.Errorf("%w: MSO digestAlgorithm %q", ErrAlgorithmNotAllowed, alg)
	}
}
