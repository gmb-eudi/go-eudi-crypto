package crypto_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

var testNow = time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newRootCA(t *testing.T, maxPathLen int) *testCA {
	t.Helper()
	key := genKey(t, elliptic.P256())
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test IACA Root"},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        maxPathLen == 0,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

func (ca *testCA) issueIntermediate(t *testing.T) *testCA {
	t.Helper()
	key := genKey(t, elliptic.P256())
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate"},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(12 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

func (ca *testCA) issueLeaf(t *testing.T, ekus []x509.ExtKeyUsage, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key := genKey(t, elliptic.P256())
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Test DS Leaf"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  ekus,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestVerifyChainHappyPath(t *testing.T) {
	root := newRootCA(t, 1)
	inter := root.issueIntermediate(t)
	leaf := inter.issueLeaf(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, testNow.Add(-time.Minute), testNow.Add(time.Hour))
	chains, err := crypto.VerifyChain(leaf, []*x509.Certificate{inter.cert}, crypto.ChainOptions{
		Anchors: []*x509.Certificate{root.cert},
		EKUs:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		At:      testNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) == 0 {
		t.Fatalf("chains = 0, want 1 chain of 3")
	}
	if len(chains[0]) != 3 {
		t.Fatalf("chains = %d×%d, want 1 chain of 3", len(chains), len(chains[0]))
	}
}

// GUARD TEST: empty Anchors must error out — never fall back to the system
// pool the way x509.VerifyOptions{Roots: nil} would.
func TestVerifyChainEmptyAnchorsFailsClosed(t *testing.T) {
	root := newRootCA(t, 0)
	leaf := root.issueLeaf(t, nil, testNow.Add(-time.Minute), testNow.Add(time.Hour))
	_, err := crypto.VerifyChain(leaf, nil, crypto.ChainOptions{At: testNow})
	if !errors.Is(err, crypto.ErrNoAnchors) {
		t.Fatalf("err = %v, want ErrNoAnchors", err)
	}
}

func TestVerifyChainZeroTimeRejected(t *testing.T) {
	root := newRootCA(t, 0)
	leaf := root.issueLeaf(t, nil, testNow.Add(-time.Minute), testNow.Add(time.Hour))
	_, err := crypto.VerifyChain(leaf, nil, crypto.ChainOptions{Anchors: []*x509.Certificate{root.cert}})
	if !errors.Is(err, crypto.ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed (At is a required, explicitly injected clock)", err)
	}
}

func TestVerifyChainFailures(t *testing.T) {
	root := newRootCA(t, 1)
	inter := root.issueIntermediate(t)
	otherRoot := newRootCA(t, 1)
	tests := []struct {
		name string
		leaf *x509.Certificate
		opts crypto.ChainOptions
	}{
		{
			"expired leaf",
			inter.issueLeaf(t, nil, testNow.Add(-2*time.Hour), testNow.Add(-time.Hour)),
			crypto.ChainOptions{Anchors: []*x509.Certificate{root.cert}, At: testNow},
		},
		{
			"not yet valid leaf",
			inter.issueLeaf(t, nil, testNow.Add(time.Hour), testNow.Add(2*time.Hour)),
			crypto.ChainOptions{Anchors: []*x509.Certificate{root.cert}, At: testNow},
		},
		{
			"wrong EKU",
			inter.issueLeaf(t, []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, testNow.Add(-time.Minute), testNow.Add(time.Hour)),
			crypto.ChainOptions{Anchors: []*x509.Certificate{root.cert}, EKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, At: testNow},
		},
		{
			"untrusted anchor",
			inter.issueLeaf(t, nil, testNow.Add(-time.Minute), testNow.Add(time.Hour)),
			crypto.ChainOptions{Anchors: []*x509.Certificate{otherRoot.cert}, At: testNow},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := crypto.VerifyChain(tt.leaf, []*x509.Certificate{inter.cert}, tt.opts); !errors.Is(err, crypto.ErrVerificationFailed) {
				t.Fatalf("err = %v, want ErrVerificationFailed", err)
			}
		})
	}
}

// path-len violation: root constrained to MaxPathLen 0 must not chain
// through an intermediate ([RFC 5280 §4.2.1.9]).
func TestVerifyChainPathLenViolation(t *testing.T) {
	root := newRootCA(t, 0)
	inter := root.issueIntermediate(t)
	leaf := inter.issueLeaf(t, nil, testNow.Add(-time.Minute), testNow.Add(time.Hour))
	_, err := crypto.VerifyChain(leaf, []*x509.Certificate{inter.cert}, crypto.ChainOptions{
		Anchors: []*x509.Certificate{root.cert},
		At:      testNow,
	})
	if !errors.Is(err, crypto.ErrVerificationFailed) {
		t.Fatalf("err = %v, want ErrVerificationFailed", err)
	}
}

// GUARD TEST (defensive nil check): a nil leaf must error, never panic.
func TestVerifyChainNilLeafRejected(t *testing.T) {
	root := newRootCA(t, 0)
	_, err := crypto.VerifyChain(nil, nil, crypto.ChainOptions{
		Anchors: []*x509.Certificate{root.cert},
		At:      testNow,
	})
	if !errors.Is(err, crypto.ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

// GUARD TEST (defensive nil check): a nil entry in Anchors must error, never
// panic in stdlib's CertPool.AddCert.
func TestVerifyChainNilAnchorEntryRejected(t *testing.T) {
	root := newRootCA(t, 0)
	leaf := root.issueLeaf(t, nil, testNow.Add(-time.Minute), testNow.Add(time.Hour))
	_, err := crypto.VerifyChain(leaf, nil, crypto.ChainOptions{
		Anchors: []*x509.Certificate{nil},
		At:      testNow,
	})
	if !errors.Is(err, crypto.ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestParseCertChain(t *testing.T) {
	root := newRootCA(t, 1)
	inter := root.issueIntermediate(t)
	pemBuf := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.cert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter.cert.Raw})...)
	certs, err := crypto.ParseCertChain(pemBuf)
	if err != nil || len(certs) != 2 {
		t.Fatalf("PEM: certs=%d err=%v, want 2, nil", len(certs), err)
	}
	certs, err = crypto.ParseCertChain(root.cert.Raw)
	if err != nil || len(certs) != 1 {
		t.Fatalf("DER: certs=%d err=%v, want 1, nil", len(certs), err)
	}
	for _, raw := range [][]byte{nil, []byte("garbage"), []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")} {
		if _, err := crypto.ParseCertChain(raw); !errors.Is(err, crypto.ErrMalformed) {
			t.Errorf("raw %q: err = %v, want ErrMalformed", raw, err)
		}
	}
}

// A PEM buffer containing only non-CERTIFICATE blocks must be rejected —
// the loop must skip them, then report "no CERTIFICATE blocks" rather than
// silently returning an empty chain.
func TestParseCertChainNoCertificateBlocks(t *testing.T) {
	pemBuf := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x00, 0x00, 0x00}})
	if _, err := crypto.ParseCertChain(pemBuf); !errors.Is(err, crypto.ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

// A caller must be able to tell an expired certificate from a chain to an
// anchor we do not hold: those are different answers for a relying party, and
// collapsing them sends people hunting for a trust problem that does not exist.
// The sentinel stays, so existing callers keep working; the typed cause is
// additionally reachable.
func TestVerifyChainPreservesTypedCause(t *testing.T) {
	root := newRootCA(t, 0)
	expired := root.issueLeaf(t, nil, testNow.Add(-48*time.Hour), testNow.Add(-24*time.Hour))

	_, err := crypto.VerifyChain(expired, nil, crypto.ChainOptions{
		Anchors: []*x509.Certificate{root.cert},
		At:      testNow,
	})
	if !errors.Is(err, crypto.ErrVerificationFailed) {
		t.Fatalf("expired leaf: want ErrVerificationFailed, got %v", err)
	}
	var invalid x509.CertificateInvalidError
	if !errors.As(err, &invalid) {
		t.Fatalf("expired leaf: typed cause lost, cannot be told from an unknown anchor: %v", err)
	}
	if invalid.Reason != x509.Expired {
		t.Fatalf("expired leaf: want Reason=Expired, got %v", invalid.Reason)
	}

	other := newRootCA(t, 0)
	foreign := other.issueLeaf(t, nil, testNow.Add(-time.Hour), testNow.Add(time.Hour))
	_, err = crypto.VerifyChain(foreign, nil, crypto.ChainOptions{
		Anchors: []*x509.Certificate{root.cert},
		At:      testNow,
	})
	if !errors.Is(err, crypto.ErrVerificationFailed) {
		t.Fatalf("unknown anchor: want ErrVerificationFailed, got %v", err)
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("unknown anchor: typed cause lost: %v", err)
	}
}
