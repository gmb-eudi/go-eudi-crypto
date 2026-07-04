package crypto

import "errors"

// Sentinel errors. Callers map these to their own problem/reason codes; this
// library never carries HTTP semantics or framework dependencies.
var (
	ErrAlgorithmNotAllowed = errors.New("crypto: algorithm not allowed by ECCG policy")
	ErrCurveNotAllowed     = errors.New("crypto: curve not allowed by ECCG policy")
	ErrKeyTypeNotAllowed   = errors.New("crypto: key type not allowed by ECCG policy")
	ErrKeyNotFound         = errors.New("crypto: key not found")
	ErrNoAnchors           = errors.New("crypto: no trust anchors provided")
	ErrCritUnsupported     = errors.New("crypto: unsupported critical header parameter")
	ErrAlgKeyMismatch      = errors.New("crypto: token algorithm does not match key")
	ErrProtectedHeader     = errors.New("crypto: forbidden protected header parameter")
	ErrMalformed           = errors.New("crypto: malformed input")
	ErrVerificationFailed  = errors.New("crypto: verification failed")
	ErrDecryptionFailed    = errors.New("crypto: decryption failed")
)
