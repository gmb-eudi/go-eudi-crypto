package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Header is a decoded JOSE protected header.
type Header map[string]any

// parseProtectedSegment decodes the protected header of a compact-serialized
// JOSE object with the given number of segments (JWS: 3 per [RFC 7515 §7.1],
// JWE: 5 per [RFC 7516 §7.1]). Non-compact serializations are rejected.
func parseProtectedSegment(token []byte, segments int) (Header, error) {
	if bytes.Count(token, []byte(".")) != segments-1 {
		return nil, fmt.Errorf("%w: expected compact serialization with %d segments", ErrMalformed, segments)
	}
	head, _, _ := bytes.Cut(token, []byte("."))
	raw, err := base64.RawURLEncoding.DecodeString(string(head))
	if err != nil {
		return nil, fmt.Errorf("%w: protected header: %v", ErrMalformed, err)
	}
	var h Header
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&h); err != nil {
		return nil, fmt.Errorf("%w: protected header: %v", ErrMalformed, err)
	}
	return h, nil
}

// checkCrit implements [RFC 7515 §4.1.11] / [RFC 7516 §4.1.13]: this library
// supports no critical extension parameters, so any crit member is rejected.
func checkCrit(h Header) error {
	v, ok := h["crit"]
	if !ok {
		return nil
	}
	arr, ok := v.([]any)
	if !ok || len(arr) == 0 {
		return fmt.Errorf("%w: crit must be a non-empty array", ErrMalformed)
	}
	return fmt.Errorf("%w: crit=%v", ErrCritUnsupported, arr)
}
