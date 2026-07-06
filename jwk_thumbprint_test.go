package crypto_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

// Known-answer test vector.
//
// The EC P-256 key point below was generated with
// `openssl ecparam -name prime256v1 -genkey -noout`, and its raw uncompressed
// point (0x04 || X || Y) read back with `openssl ec -pubin -text -noout`.
//
// The expected thumbprint was derived independently of this package, in three
// separate tools that all agreed:
//
//	canonical JSON (RFC 7638 §3.1 member order kty<crv<x<y is ASCII-sorted to
//	crv,kty,x,y; no whitespace):
//	  {"crv":"P-256","kty":"EC","x":"LgH6aeDE1PAI11QOE9gG2rl9OyXiJAoU0vPlFdvgkss","y":"fSbLY-jqdziJAVHqAfKxR1VqS9HWEUXEaK_iHal0KxQ"}
//	sha256sum / openssl dgst -sha256 / node crypto.createHash("sha256") of the
//	126 ASCII bytes above (all three agree):
//	  2839d556ff4ae88336f0437b70965603bcc0acfd835dd61d6d9ccdcc56426519
//	base64url (RawURLEncoding, no padding) of that digest (openssl base64 +
//	tr, and node Buffer.toString("base64url"), and Python
//	base64.urlsafe_b64encode both agree):
//	  KDnVVv9K6IM28EN7cJZWA7zArP2DXdYdbZzNzFZCZRk
const (
	testP256XHex = "2e01fa69e0c4d4f008d7540e13d806dab97d3b25e2240a14d2f3e515dbe092cb"
	testP256YHex = "7d26cb63e8ea7738890151ea01f2b147556a4bd1d61145c468afe21da9742b14"

	wantThumbprint = "KDnVVv9K6IM28EN7cJZWA7zArP2DXdYdbZzNzFZCZRk"
)

func testP256PublicKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	xb, err := hex.DecodeString(testP256XHex)
	if err != nil {
		t.Fatal(err)
	}
	yb, err := hex.DecodeString(testP256YHex)
	if err != nil {
		t.Fatal(err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}
}

func TestJWKThumbprintKnownAnswer(t *testing.T) {
	got, err := crypto.JWKThumbprint(testP256PublicKey(t))
	if err != nil {
		t.Fatalf("JWKThumbprint: %v", err)
	}
	if got != wantThumbprint {
		t.Errorf("JWKThumbprint = %q, want %q", got, wantThumbprint)
	}
}

func TestJWKThumbprintDeterministic(t *testing.T) {
	pub := testP256PublicKey(t)
	first, err := crypto.JWKThumbprint(pub)
	if err != nil {
		t.Fatalf("JWKThumbprint (1st): %v", err)
	}
	second, err := crypto.JWKThumbprint(pub)
	if err != nil {
		t.Fatalf("JWKThumbprint (2nd): %v", err)
	}
	if first != second {
		t.Errorf("thumbprint not deterministic: %q != %q", first, second)
	}
}

func TestJWKThumbprintDistinctKeys(t *testing.T) {
	k1 := genKey(t, elliptic.P256())
	k2 := genKey(t, elliptic.P256())

	tp1, err := crypto.JWKThumbprint(k1.Public())
	if err != nil {
		t.Fatalf("JWKThumbprint(k1): %v", err)
	}
	tp2, err := crypto.JWKThumbprint(k2.Public())
	if err != nil {
		t.Fatalf("JWKThumbprint(k2): %v", err)
	}
	if tp1 == tp2 {
		t.Errorf("two different keys produced the same thumbprint: %q", tp1)
	}
}

func TestJWKThumbprintRejectsNonEC(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := crypto.JWKThumbprint(rsaKey.Public()); !errors.Is(err, crypto.ErrKeyTypeNotAllowed) {
		t.Errorf("RSA key: err = %v, want ErrKeyTypeNotAllowed", err)
	}

	// JWKThumbprint forwards ECPublicKeyToJWK's error unchanged (no rewrapping,
	// no new sentinel) — confirm the two error messages are identical, not just
	// that both happen to satisfy the same sentinel.
	_, wantErr := crypto.ECPublicKeyToJWK(rsaKey.Public())
	_, gotErr := crypto.JWKThumbprint(rsaKey.Public())
	if gotErr.Error() != wantErr.Error() {
		t.Errorf("JWKThumbprint error = %q, want ECPublicKeyToJWK error %q", gotErr, wantErr)
	}

	if _, err := crypto.JWKThumbprint(nil); !errors.Is(err, crypto.ErrKeyTypeNotAllowed) {
		t.Errorf("nil key: err = %v, want ErrKeyTypeNotAllowed", err)
	}
}

// TestECPublicKeyToJWKMarshalOrder is the canonicalization-correctness claim
// the whole thumbprint function depends on (RFC 7638 §3.1): json.Marshal on
// the map returned by ECPublicKeyToJWK must produce keys in ASCII-sorted
// order (crv, kty, x, y) with no extra whitespace. This is a byte-level
// assertion, not an assumption.
func TestECPublicKeyToJWKMarshalOrder(t *testing.T) {
	pub := testP256PublicKey(t)
	jwk, err := crypto.ECPublicKeyToJWK(pub)
	if err != nil {
		t.Fatalf("ECPublicKeyToJWK: %v", err)
	}
	raw, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	want := `{"crv":"P-256","kty":"EC","x":"LgH6aeDE1PAI11QOE9gG2rl9OyXiJAoU0vPlFdvgkss","y":"fSbLY-jqdziJAVHqAfKxR1VqS9HWEUXEaK_iHal0KxQ"}`
	if string(raw) != want {
		t.Errorf("json.Marshal(jwk) = %s, want %s", raw, want)
	}
}
