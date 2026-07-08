package crypto

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// ParseJWSHeader reads and JSON-decodes the protected header of a 3-segment
// compact JWS WITHOUT verifying the signature (RFC 7515 §4.1). Structural
// only — NEVER use its output to make a trust decision. It exists so a caller
// can inspect header members (e.g. an x5c chain, via X5CFromHeader) to resolve
// a candidate key BEFORE calling VerifyJWS; verify with VerifyJWS for anything
// security-relevant. Fail closed (ErrMalformed) on a wrong segment count, an
// empty segment, an undecodable base64url header, or a header that is not a
// JSON object. Must not panic on adversarial input (fuzzed:
// FuzzParseJWSHeader).
func ParseJWSHeader(token []byte) (Header, error) {
	if !isCompactJWS(token) {
		return nil, fmt.Errorf("%w: not a 3-segment compact JWS", ErrMalformed)
	}
	h, err := parseProtectedSegment(token, 3)
	if err != nil {
		return nil, err
	}
	if h == nil {
		// A JSON "null" header decodes into a nil map without error: it is not
		// a JSON object, so reject it (fail closed) — {} decodes to a non-nil
		// empty map and is accepted.
		return nil, fmt.Errorf("%w: protected header is not a JSON object", ErrMalformed)
	}
	return h, nil
}

// isCompactJWS reports whether token is a compact-serialized JWS shape: exactly
// three '.'-separated segments, all non-empty (RFC 7515 §7.1). It validates
// structure only — not the base64url charset of each segment nor the
// signature. Mirrors go-sdjwt's isCompactJWS.
func isCompactJWS(token []byte) bool {
	if len(token) == 0 {
		return false
	}
	segs := bytes.Split(token, []byte("."))
	if len(segs) != 3 {
		return false
	}
	for _, s := range segs {
		if len(s) == 0 {
			return false
		}
	}
	return true
}

// X5CFromHeader decodes the RFC 7515 §4.1.6 x5c header member (a JSON array of
// standard-base64-encoded DER certificates, leaf first) into parsed
// certificates. It is the symmetric decode counterpart of the certChain encode
// side and returns the certificates leaf-first, in header order. Returns
// (nil, nil) if the header carries no x5c member — absence is not an error; the
// caller decides whether a chain is required. The certificates are NOT
// validated against any trust anchor and their DER is NOT verified against any
// signature — this is a structural decode only; resolve/validate the chain
// through the trust layer before trusting it. Fail closed (ErrMalformed) if x5c
// is present but not an array, an entry is not a string, an entry is not valid
// standard base64, or a decoded entry is not a parseable certificate.
func X5CFromHeader(h Header) ([]*x509.Certificate, error) {
	raw, ok := h["x5c"]
	if !ok {
		return nil, nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: x5c must be a JSON array", ErrMalformed)
	}
	certs := make([]*x509.Certificate, 0, len(arr))
	for i, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("%w: x5c[%d] is not a string", ErrMalformed, i)
		}
		// Standard base64 (not URL-safe), matching the certChain encode side —
		// a wire-format constant from RFC 7515 §4.1.6, not an algorithm choice.
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("%w: x5c[%d]: %v", ErrMalformed, i, err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: x5c[%d]: %v", ErrMalformed, i, err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}
