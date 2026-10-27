# Changelog

All notable changes to keystore-tui are listed here. Versions follow
[Semantic Versioning](https://semver.org/).

## 1.0.0

First stable release, with prebuilt binaries for Linux, macOS, and Windows.

- Opens JKS, JCEKS, and PKCS12 keystores, detecting the format from the file
  content, and verifies their integrity with the store password.
- Opens standalone PEM, DER, and PKCS#7 certificate files and PKCS#10
  certificate signing requests.
- Lists entries with their type, public key algorithm, key size, and expiry,
  highlighting certificates that expire soon or have expired and flagging weak
  keys and signature hashes.
- Filters entries by alias or subject and sorts them by alias or expiry.
- Shows full certificate details, decoded extensions, fingerprints, and the
  certificate hierarchy, checking each signature against the issuer's key.
- Diagnoses stored certificate chains offline: validity, issuer names and key
  identifiers, CA status, signing key usage, and path-length constraints.
- Exports a certificate, a whole chain, or a request to a new PEM or DER file.
- Prints its version with `--version` (`-V`) and usage with `--help` (`-h`).
- Read-only: never modifies keystores and never decrypts private keys.
