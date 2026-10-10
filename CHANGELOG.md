# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency.

## v0.0.9

**Requires Go 1.27.2.** The `go` directive moves up from 1.26.6, so a consumer on an older
toolchain will not build this version. Go 1.27.2 is a security release, and this library's code
reaches four of the standard-library vulnerabilities it fixes. Nothing else changed here: no
source, no signature, no message text, and no direct dependency.

### Changed

- **`go` directive 1.26.6 → 1.27.2**, the minimum Go version a consumer needs. Under Go 1.27.0,
  `govulncheck` finds four vulnerabilities this library's code calls, all in `net/http`:
  GO-2026-6603, -6611, -6613 and -6617. Under 1.27.2 it finds none. Raise your own module's `go`
  directive to `1.27.2`; from there the go command downloads and uses that toolchain by itself.

### Notes

- **Indirect modules moved** through the existing dependencies: `fxamacker/cbor/v2` → v2.9.6,
  `goccy/go-json` → v0.11.2, `golang.org/x/crypto` → v0.58.0, `golang.org/x/sys` → v0.49.0.
  The direct dependencies (`lestrrat-go/jwx/v3` v3.3.0, `veraison/go-cose` v1.3.0) are already the
  latest.

- The gate is green on Go 1.27.2: `go mod verify`, `go mod tidy -diff`, build, vet, `gofmt`,
  golangci-lint v2.14.0, `go test -race` with **0 races**, and all six fuzz targets for 30 seconds
  each with no failing input. `govulncheck` now reports **no vulnerabilities found** at any level, the module-level `golang.org/x/crypto/openpgp` advisory
  (GO-2026-5932) included.

- Repository hygiene, with no effect on code that uses the library: CI's linter moved to
  golangci-lint v2.14.0 (the earlier release cannot read Go 1.27.2's compiled standard library),
  and the pinned GitHub Actions moved to their current commits.

## v0.0.8

Dependency maintenance. No source changed here, and nothing this library does behaves differently —
but the JOSE library it signs, verifies, encrypts and decrypts with moves a minor, so read the note
before you bump.

### Notes

- **`github.com/lestrrat-go/jwx/v3` → v3.3.0** (was v3.2.0). This library uses four of its packages:
  `jwa`, `jwe`, `jws` and `cert`. Measured against that release rather than assumed — `cert` is
  **byte-identical** between the two versions; `jwa` changes nothing but a build file; `jwe` has its
  generated headers regenerated; and `jws`, which this library calls for `Sign` and `Verify`, is the
  one that moved, gaining internal packages and regenerated headers.

  **No source change was needed here and the full gate is green on the new set** — build, vet,
  `gofmt`, `go mod verify`, `go mod tidy -diff`, and `go test -race` across both packages with **0
  races**, which includes the COSE_Sign1 round-trip, tamper, algorithm-mismatch and RFC-vector
  cases. What is written above is what was read and measured against *this* library; it is not a
  review of that jwx release.

- **`golang.org/x/crypto` → v0.57.0** (was v0.55.0, indirect). The move crosses v0.56.0, which fixed
  **GO-2026-6354** and **GO-2026-6355** upstream. `govulncheck` reports **0 vulnerabilities this
  library's code is affected by**, with one remaining in a required module whose vulnerable path is
  not called from here. `golang.org/x/sys` → v0.48.0 in the same pass.

- Repository hygiene, with no effect on code that uses the library: CI now also runs on pushes to
  `develop`, its `setup-go` pin rolled forward, and a stray comment was cleaned out of
  `.gitattributes`.

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
