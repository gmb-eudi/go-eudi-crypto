package crypto

import (
	stdcrypto "crypto"
	"fmt"
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
}

// ECCG returns the immutable policy singleton pinned to ECCGVersion.
func ECCG() Policy { return eccg }

type policy struct {
	jwsAlgs  map[string]stdcrypto.Hash
	jweAlgs  map[string]bool
	jweEncs  map[string]bool
	coseAlgs map[int64]bool
	curves   map[string]bool
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
