package crypto

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// ChainOptions configures VerifyChain. Anchors MUST come from go-eudi-trust —
// never the system pool, never inline PEM in services.
type ChainOptions struct {
	Anchors []*x509.Certificate
	EKUs    []x509.ExtKeyUsage // empty = any EKU accepted (callers pass profile EKUs)
	At      time.Time          // required; explicitly injected clock, no hidden time.Now
}

// VerifyChain performs [RFC 5280 §6.1] path validation of leaf against the
// explicit anchor set. Fail closed: empty anchors is an error, never a
// system-pool fallback.
func VerifyChain(leaf *x509.Certificate, intermediates []*x509.Certificate, opts ChainOptions) ([][]*x509.Certificate, error) {
	if leaf == nil {
		return nil, fmt.Errorf("%w: nil leaf", ErrMalformed)
	}
	if len(opts.Anchors) == 0 {
		// x509.VerifyOptions{Roots: nil} would consult the system pool —
		// exactly what this library must never do. Refuse before touching stdlib.
		return nil, ErrNoAnchors
	}
	if opts.At.IsZero() {
		return nil, fmt.Errorf("%w: ChainOptions.At is required", ErrMalformed)
	}
	roots := x509.NewCertPool()
	for _, a := range opts.Anchors {
		if a == nil {
			return nil, fmt.Errorf("%w: nil certificate in anchors/intermediates", ErrMalformed)
		}
		roots.AddCert(a)
	}
	var inters *x509.CertPool
	if len(intermediates) > 0 {
		inters = x509.NewCertPool()
		for _, c := range intermediates {
			if c == nil {
				return nil, fmt.Errorf("%w: nil certificate in anchors/intermediates", ErrMalformed)
			}
			inters.AddCert(c)
		}
	}
	ekus := opts.EKUs
	if len(ekus) == 0 {
		// stdlib defaults nil KeyUsages to ServerAuth; make "no EKU
		// constraint" explicit instead.
		ekus = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		CurrentTime:   opts.At,
		KeyUsages:     ekus,
	})
	if err != nil {
		// Wrap the standard library's error too, not just its text: an expired
		// certificate and a chain to an unknown anchor are different answers,
		// and a caller can only keep them apart if the typed cause survives
		// (x509.CertificateInvalidError vs x509.UnknownAuthorityError).
		return nil, fmt.Errorf("%w: %w", ErrVerificationFailed, err)
	}
	return chains, nil
}

// ParseCertChain parses one or more certificates from PEM (CERTIFICATE
// blocks) or raw DER. Untrusted input — fuzzed (FuzzParseCertChain).
func ParseCertChain(raw []byte) ([]*x509.Certificate, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty input", ErrMalformed)
	}
	if bytes.Contains(raw, []byte("-----BEGIN")) {
		var certs []*x509.Certificate
		rest := raw
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
			}
			certs = append(certs, c)
		}
		if len(certs) == 0 {
			return nil, fmt.Errorf("%w: no CERTIFICATE blocks", ErrMalformed)
		}
		return certs, nil
	}
	certs, err := x509.ParseCertificates(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: no certificates", ErrMalformed)
	}
	return certs, nil
}
