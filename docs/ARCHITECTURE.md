# Architecture

Module responsibilities and dependencies for keystore-tui. See
[AGENTS.md](../AGENTS.md) for development checks and contribution instructions.

| Module | Responsibility |
| --- | --- |
| `src/startup.rs` | Command-line arguments (`--version`, `--help`), startup loading, and hidden terminal password input |
| `src/main.rs` | App state, event loop, main view rendering, password prompt, file loading (size limit, format detection), terminal setup and restoration |
| `src/certificate_file.rs` | PEM, DER, and PKCS#7 certificate files (including requests), and chain linking within a file |
| `src/certificate_request.rs` | PKCS#10 certificate requests: fields, requested extensions, and attributes |
| `src/file_picker.rs` | The keystore file browser |
| `src/path_bar.rs` | The opened file's path line and absolute directory, shared by the main view and the detail view |
| `src/keystore.rs` | JKS and JCEKS parsing and integrity check (SHA-1); the shared `KeystoreEntry` model, whose content is certificates (with their `Kind`) or a request |
| `src/java_serialization.rs` | Skipping a serialized Java object (a JCEKS secret key) without deserializing it |
| `src/pkcs12.rs` | PKCS12 parsing, MAC verification, and decryption of safe contents (AES and legacy PBE) |
| `src/entry_list.rs` | Entry-list filtering, sorting, and expiry classification |
| `src/certificate.rs` | X.509 summary (subject, algorithm, key size, expiry) for the entry table |
| `src/certificate/details.rs` | Full certificate fields for the detail view |
| `src/certificate/extensions.rs` | Decoding X.509 extensions into display lines |
| `src/certificate/security.rs` | Weak key-size and signature-hash checks |
| `src/certificate/diagnostics.rs` | Offline stored-chain validity, issuer and CA constraint diagnostics; no trust decisions |
| `src/certificate/signature.rs` | Checking a certificate's signature with its issuer's public key, and a request's with its own |
| `src/entry_details.rs` | The full-screen detail view: layout, keys, export, and shared detail formatting |
| `src/entry_details/chain.rs` | A stored chain's hierarchy and certificate details |
| `src/entry_details/request.rs` | A certificate request's details, shown in place of a hierarchy |
| `src/export.rs` | The export name prompt and writing PEM/DER certificate and request files |
| `src/test_support.rs`, `src/tests.rs` | Unit-test helpers, synthetic keystores, and tests |
| `tests/terminal_smoke.py` | PTY smoke tests against the built binary |
| `tests/fixtures/` | Generated keystore fixtures; see its `README.md` for how they were made |
| `dist-workspace.toml`, `.github/workflows/release.yml` | Release configuration for [`dist`](https://github.com/axodotdev/cargo-dist) and the workflow it generates |
| `.github/workflows/publish-crates.yml` | The crates.io publish job that `release.yml` calls |
| `.github/workflows/tag-release.yml` | Tags a new `Cargo.toml` version on `main`, which starts `release.yml` |

Dependencies are deliberately few:

- `ratatui`, with the `crossterm` backend, for the UI.
- `sha1` for the JKS and JCEKS integrity digest.
- `crown` for ASN.1, PEM, X.509, PKCS#7, PKCS12 (MAC and PBE), and signature
  verification (certificates and requests).
- `zeroize` for wiping passwords.

