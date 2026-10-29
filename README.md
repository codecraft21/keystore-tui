# keystore-tui

A terminal app for inspecting keystores, certificates, and certificate signing requests.

![Main screen showing five keystore entries, including one expired certificate](docs/main-screen.png)

![Details of the selected api-production entry, showing certificate fields and its verified signature](docs/entry-details.png)

![Offline chain diagnostics for the openssl-cert.p12 fixture, showing validity and signature checks with trust and revocation unchecked](docs/chain-diagnostics.png)

Open a JKS, JCEKS, or PKCS12
(`.jks`, `.jceks`, `.p12`, `.pfx`) file, enter its password, and browse its
entries and certificates. It also
opens standalone certificate files (`.pem`, `.crt`, `.cer`, `.der`, `.p7b`,
`.p7c`) and certificate signing requests (`.csr`, `.p10`).

- Lists every entry with its type (private key, trusted certificate, or secret
  key), public key algorithm, key size, and expiry date. Certificates expiring
  within 30 days are shown in yellow and expired ones in red.
- Flags weak cryptography: RSA and DSA keys under 2048 bits, EC keys under 256
  bits, and MD2, MD5, or SHA-1 signatures.
- Filters entries by alias or subject, and sorts them by alias or expiry date.
- Shows each certificate's full details, including decoded extensions, and its
  certificate hierarchy, with each signature checked against the issuer's key.
- Diagnoses stored certificate chains offline: validity, issuer names and key
  identifiers, CA status, signing key usage, and path-length constraints.
- Shows a certificate signing request's subject, public key, requested
  extensions, and attributes, and checks its signature with its own key.
- Exports a certificate, a whole chain, or a request to a new PEM or DER file.
- Detects the format from the file content, so a PKCS12 store renamed `.jks`
  still opens.
- Opens PKCS12 files made by Java, OpenSSL, and other tools. Keys without a
  name are listed under their certificate's common name, and certificates that
  belong to no key are listed as `Certificate` entries.
- Read-only and self-contained: it never modifies existing files, never
  decrypts or displays private keys, and does not need Java or `keytool`.

## Install

With Homebrew (macOS and Linux):

```sh
brew install codecraft21/tap/keystore-tui
```

See [other installation methods](docs/INSTALL.md) for scripts, manual downloads,
building from source, and download verification.

## Usage

Start with a keystore, certificate, or certificate request:

```sh
keystore-tui "path/to/store.jks"
keystore-tui "path/to/certificate.pem"
```

Enter the keystore password when prompted. You can also run `keystore-tui`
without a path and press `o` to browse for a file.

Use the arrow keys to select an entry and `Enter` to inspect it. Press `Esc`
to return to the list, or `q` to quit. `keystore-tui --help` shows command-line
usage.

See the [usage reference](docs/REFERENCE.md) for all key bindings, filtering,
certificate details, chain diagnostics, and exports.

## Limitations

- Keystores are read-only: there is no import or editing. Only certificates,
  certificate chains, and certificate signing requests can be exported.
- Private keys are never decrypted, shown, or exported.
- Raw ASN.1 views and clipboard actions are not available yet.
- PKCS12 integrity checks do not support PBMAC1 MACs.
- Files larger than 64 MiB are refused.

## More documentation

- [`docs/REFERENCE.md`](docs/REFERENCE.md): usage and key bindings.
- [`docs/SPEC.md`](docs/SPEC.md): the detailed behaviour specification.
- [`AGENTS.md`](AGENTS.md): architecture, development checks, and contribution
  guidelines.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
