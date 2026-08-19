# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency.

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
