# Changelog

All notable changes to keystore-tui are listed here. Versions follow
[Semantic Versioning](https://semver.org/).

## Unreleased

- Show the opened file's path in the detail view, including chain diagnostics,
  as well as in the entry list. The path itself is now shown in blue.
- The password prompt shows the path of the file being opened, instead of the
  file that was already open.
- Fix PKCS12 stores without an integrity MAC sometimes accepting a wrong or
  empty password and opening as an empty, incomplete store. This always
  happened with RC4 encryption and about 1 time in 256 otherwise. Any failure
  to decrypt the contents now asks for the password again.
- Fix a crash when a PKCS12 store's legacy 3DES or RC2 encrypted contents have
  an invalid length.
- Fix reading PKCS12 contents encrypted with legacy RC4, which were shown as an
  empty, incomplete store even with the right password.
- Open PKCS12 stores without an integrity MAC whose contents Java encrypted
  with an empty password using legacy encryption. These asked for a password
  that could not be typed.

## 1.0.1

- Adds `example.jks`, an empty-password test fixture with 20 certificate entries,
  including two expired certificates.
- Arrow keys and `j` / `k` cycle the entry-list selection, wrapping at either
  end, including arrow navigation while editing a filter.
- Show Java truststores named `cacerts` or `jssecacerts` in the file browser.
- Fix opening PKCS12 stores without an integrity MAC, including stores with
  password-encrypted certificates.

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
