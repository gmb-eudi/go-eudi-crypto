package crypto_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
//	canonical JSON ([RFC 7638 §3.1] member order kty<crv<x<y is ASCII-sorted to
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

	wantThumbprint    = "KDnVVv9K6IM28EN7cJZWA7zArP2DXdYdbZzNzFZCZRk"
	wantThumbprintHex = "2839d556ff4ae88336f0437b70965603bcc0acfd835dd61d6d9ccdcc56426519"
)

func testP256PublicKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	// 0x04 || X || Y — parsed rather than assigned to the deprecated X/Y
	// fields, which also checks the point is on the curve.
	pt, err := hex.DecodeString("04" + testP256XHex + testP256YHex)
	if err != nil {
		t.Fatal(err)
	}

	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pt)
	if err != nil {
		t.Fatal(err)
	}

	return pub
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

// The raw-digest form is checked against the SAME independently-derived vector
// documented above — the 126-byte canonical JSON hashed by sha256sum, openssl
// and node — one step earlier in the pipeline than the base64url form.
func TestJWKThumbprintBytesKnownAnswer(t *testing.T) {
	got, err := crypto.JWKThumbprintBytes(testP256PublicKey(t))
	if err != nil {
		t.Fatalf("JWKThumbprintBytes: %v", err)
	}
	if len(got) != sha256.Size {
		t.Errorf("JWKThumbprintBytes returned %d bytes, want %d", len(got), sha256.Size)
	}
	if hex.EncodeToString(got) != wantThumbprintHex {
		t.Errorf("JWKThumbprintBytes = %s, want %s", hex.EncodeToString(got), wantThumbprintHex)
	}
}

// The two forms must stay exactly one base64url hop apart. Consumers pick the
// form their wire format needs (bytes for the mdoc SessionTranscript, text for
// identifiers) and must never disagree about the underlying value.
func TestJWKThumbprintFormsAgree(t *testing.T) {
	pub := testP256PublicKey(t)
	raw, err := crypto.JWKThumbprintBytes(pub)
	if err != nil {
		t.Fatalf("JWKThumbprintBytes: %v", err)
	}
	text, err := crypto.JWKThumbprint(pub)
	if err != nil {
		t.Fatalf("JWKThumbprint: %v", err)
	}
	if got := base64.RawURLEncoding.EncodeToString(raw); got != text {
		t.Errorf("base64url(JWKThumbprintBytes) = %q, JWKThumbprint = %q", got, text)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		t.Fatalf("JWKThumbprint is not unpadded base64url: %v", err)
	}
	if !bytes.Equal(decoded, raw) {
		t.Errorf("decode(JWKThumbprint) = %x, JWKThumbprintBytes = %x", decoded, raw)
	}
}

func TestJWKThumbprintBytesRejectsNonEC(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.JWKThumbprintBytes(rsaKey.Public()); !errors.Is(err, crypto.ErrKeyTypeNotAllowed) {
		t.Errorf("RSA key: err = %v, want ErrKeyTypeNotAllowed", err)
	}
	if _, err := crypto.JWKThumbprintBytes(nil); !errors.Is(err, crypto.ErrKeyTypeNotAllowed) {
		t.Errorf("nil key: err = %v, want ErrKeyTypeNotAllowed", err)
	}
	// Fail closed: no digest may be returned alongside the error.
	got, _ := crypto.JWKThumbprintBytes(nil)
	if got != nil {
		t.Errorf("JWKThumbprintBytes(nil) returned %x with an error, want nil", got)
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
// the whole thumbprint function depends on ([RFC 7638 §3.1]): json.Marshal on
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
