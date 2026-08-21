# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency.

## v0.0.7

Compatible: no signature changes, no message-text changes, nothing that passed before now
fails. This finishes the job v0.0.6 started on one function.

### Changed

- **Errors now wrap their cause as well as their sentinel — 29 sites** across `cose.go`,
  `filekeys/filekeys.go`, `header.go`, `header_peek.go`, `jwe.go`, `jwe_encrypt.go`, `jwk.go`,
  `jws.go`, `policy.go` and `x509.go`. v0.0.6 fixed `VerifyChain`; these are the rest of the
  library. Each was built as `fmt.Errorf("%w: …: %v", ErrSentinel, err)` — the sentinel
  wrapped, the cause printed into the string and then unreachable. Both are now `%w`.

  The practical gain is the same as v0.0.6's, now everywhere: a caller can tell a malformed
  encoding from a rejected key from an unsupported algorithm without matching on text.

  ```go
  var jwkErr *json.UnmarshalTypeError
  if errors.Is(err, ErrMalformed) && errors.As(err, &jwkErr) { /* the JWK shape is wrong */ }
  ```

  Every `errors.Is` check still holds and every rendered message is byte-identical (`%v` and
  `%w` print an error the same way), so no existing caller needs to change.

### Fixed

- Two P-256 test helpers built a public key by assigning the deprecated `X`/`Y` coordinate
  fields; they now parse the uncompressed point, which also checks the point is on the curve.
  Test-only — no shipped behaviour changed.

### Dependencies

- `github.com/lestrrat-go/dsig` v1.3.0 → v1.4.0 (indirect). Two test-only indirect entries
  (`go-spew`, `go-difflib`) dropped out of `go.mod` as no longer needed.

### Notes

- The `go` directive is now `1.26.6`, which is the minimum Go version a consumer needs. The
  previous `1.26` resolved to whatever patch the toolchain happened to have; the exact patch
  is pinned because earlier 1.26 releases carry standard-library security fixes this library's
  callers should not silently miss.

## v0.0.6

Compatible: no signature changes, no behavioural change to what passes or fails.

### Changed

- `VerifyChain` now wraps the standard library's error with `%w` in addition to its own
  sentinel, so a caller can tell **an expired certificate** (`x509.CertificateInvalidError`,
  reason `x509.Expired`) from **a chain that reaches no held anchor**
  (`x509.UnknownAuthorityError`). Those are different answers for a relying party — one is
  the issuer's certificate rotation, the other a trust problem — and collapsing them into
  one string is how a routine expiry gets diagnosed as a missing trust anchor.

  `errors.Is(err, ErrVerificationFailed)` still holds and the message text is byte-identical,
  so existing callers need no change; `errors.As` now reaches the cause.

### Notes

- Path validation is otherwise untouched: explicit anchors only, never the system pool, and
  `ChainOptions.At` remains required.
