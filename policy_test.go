package crypto_test

import (
	stdcrypto "crypto"
	"errors"
	"testing"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

// Table names cite the ECCG v2.0 mechanism (exact §s pinned once the ECCG
// PDF is in verifier references/).
func TestPolicyAllowedJWSAlg(t *testing.T) {
	p := crypto.ECCG()
	tests := []struct {
		name string
		alg  string
		want bool
	}{
		{"ECCG_v2_ECDSA_P256_baseline_ES256", "ES256", true},
		{"ECCG_v2_ECDSA_P384_ES384", "ES384", true},
		{"ECCG_v2_ECDSA_P521_ES512", "ES512", true},
		{"reject_RSA_PKCS1_RS256", "RS256", false},
		{"reject_RSA_PSS_PS256", "PS256", false},
		{"reject_HMAC_HS256", "HS256", false},
		{"reject_none_RFC7518", "none", false},
		{"reject_secp256k1_ES256K", "ES256K", false},
		{"reject_EdDSA_not_pinned", "EdDSA", false},
		{"reject_empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.AllowedJWSAlg(tt.alg); got != tt.want {
				t.Errorf("AllowedJWSAlg(%q) = %v, want %v", tt.alg, got, tt.want)
			}
		})
	}
}

func TestPolicyAllowedJWEAlg(t *testing.T) {
	p := crypto.ECCG()
	tests := []struct {
		name     string
		alg, enc string
		want     bool
	}{
		{"ECDH_ES_A128GCM_HAIP_baseline", "ECDH-ES", "A128GCM", true},
		{"ECDH_ES_A256GCM", "ECDH-ES", "A256GCM", true},
		{"ECDH_ES_A128KW_A128GCM", "ECDH-ES+A128KW", "A128GCM", true},
		{"ECDH_ES_A256KW_A256GCM", "ECDH-ES+A256KW", "A256GCM", true},
		{"reject_enc_A128CBC_HS256", "ECDH-ES", "A128CBC-HS256", false},
		{"reject_alg_RSA_OAEP", "RSA-OAEP", "A128GCM", false},
		{"reject_alg_dir", "dir", "A128GCM", false},
		{"reject_alg_A128KW_alone", "A128KW", "A128GCM", false},
		{"reject_both_empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.AllowedJWEAlg(tt.alg, tt.enc); got != tt.want {
				t.Errorf("AllowedJWEAlg(%q,%q) = %v, want %v", tt.alg, tt.enc, got, tt.want)
			}
		})
	}
}

func TestPolicyAllowedCOSEAlg(t *testing.T) {
	p := crypto.ECCG()
	tests := []struct {
		name string
		alg  int64
		want bool
	}{
		{"ES256_minus7_RFC9053", -7, true},
		{"ES384_minus35", -35, true},
		{"ES512_minus36", -36, true},
		{"reject_EdDSA_minus8", -8, false},
		{"reject_HMAC256_5", 5, false},
		{"reject_zero", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.AllowedCOSEAlg(tt.alg); got != tt.want {
				t.Errorf("AllowedCOSEAlg(%d) = %v, want %v", tt.alg, got, tt.want)
			}
		})
	}
}

func TestPolicyAllowedCurve(t *testing.T) {
	p := crypto.ECCG()
	for crv, want := range map[string]bool{
		"P-256": true, "P-384": true, "P-521": true,
		"secp256k1": false, "Ed25519": false, "X25519": false, "P-192": false, "": false,
	} {
		if got := p.AllowedCurve(crv); got != want {
			t.Errorf("AllowedCurve(%q) = %v, want %v", crv, got, want)
		}
	}
}

func TestPolicyHashForAlg(t *testing.T) {
	p := crypto.ECCG()
	tests := []struct {
		alg     string
		want    stdcrypto.Hash
		wantErr bool
	}{
		{"ES256", stdcrypto.SHA256, false},
		{"ES384", stdcrypto.SHA384, false},
		{"ES512", stdcrypto.SHA512, false},
		{"RS256", 0, true},
		{"none", 0, true},
	}
	for _, tt := range tests {
		got, err := p.HashForAlg(tt.alg)
		if tt.wantErr {
			if !errors.Is(err, crypto.ErrAlgorithmNotAllowed) {
				t.Errorf("HashForAlg(%q) err = %v, want ErrAlgorithmNotAllowed", tt.alg, err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("HashForAlg(%q) = %v, %v; want %v", tt.alg, got, err, tt.want)
		}
	}
}

func TestECCGVersionPinned(t *testing.T) {
	if crypto.ECCGVersion != "2.0" {
		t.Errorf("ECCGVersion = %q, want \"2.0\"", crypto.ECCGVersion)
	}
}

// AllowedHashName / HashForName cover the IANA "Named Information Hash
// Algorithm" registry values used by SD-JWT `_sd_alg` (draft-ietf-oauth-sd-jwt).
func TestPolicyAllowedHashName(t *testing.T) {
	p := crypto.ECCG()
	for name, want := range map[string]bool{
		"sha-256": true, "sha-384": true, "sha-512": true,
		"":        true,  // SD-JWT §4.1.1: absent _sd_alg = scheme default (sha-256)
		"SHA-256": false, // mdoc spelling — not an SD-JWT _sd_alg value
		"sha-1":   false, "md5": false, "sha256": false,
	} {
		if got := p.AllowedHashName(name); got != want {
			t.Errorf("AllowedHashName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestPolicyHashForName(t *testing.T) {
	p := crypto.ECCG()
	tests := []struct {
		name    string
		want    stdcrypto.Hash
		wantErr bool
	}{
		{"sha-256", stdcrypto.SHA256, false},
		{"sha-384", stdcrypto.SHA384, false},
		{"sha-512", stdcrypto.SHA512, false},
		{"", stdcrypto.SHA256, false}, // SD-JWT §4.1.1: absent _sd_alg defaults to sha-256
		{"SHA-256", 0, true},          // uppercase is the mdoc form, not _sd_alg
		{"sha-1", 0, true},
	}
	for _, tt := range tests {
		got, err := p.HashForName(tt.name)
		if tt.wantErr {
			if !errors.Is(err, crypto.ErrAlgorithmNotAllowed) {
				t.Errorf("HashForName(%q) err = %v, want ErrAlgorithmNotAllowed", tt.name, err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("HashForName(%q) = %v, %v; want %v", tt.name, got, err, tt.want)
		}
	}
}

// HashForMSODigestAlg covers ISO/IEC 18013-5 MSO `digestAlgorithm` (uppercase
// SHA-2 names); it reuses the single hash allow-list behind HashForName.
func TestPolicyHashForMSODigestAlg(t *testing.T) {
	p := crypto.ECCG()
	tests := []struct {
		alg     string
		want    stdcrypto.Hash
		wantErr bool
	}{
		{"SHA-256", stdcrypto.SHA256, false},
		{"SHA-384", stdcrypto.SHA384, false},
		{"SHA-512", stdcrypto.SHA512, false},
		{"sha-256", 0, true}, // lowercase is the SD-JWT form, not MSO
		{"SHA-1", 0, true},
		{"MD5", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		got, err := p.HashForMSODigestAlg(tt.alg)
		if tt.wantErr {
			if !errors.Is(err, crypto.ErrAlgorithmNotAllowed) {
				t.Errorf("HashForMSODigestAlg(%q) err = %v, want ErrAlgorithmNotAllowed", tt.alg, err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("HashForMSODigestAlg(%q) = %v, %v; want %v", tt.alg, got, err, tt.want)
		}
	}
}
