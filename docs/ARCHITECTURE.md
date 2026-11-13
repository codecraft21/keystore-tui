# Architecture

Module responsibilities and dependencies for keystore-tui. See
[AGENTS.md](../AGENTS.md) for development checks and contribution instructions.

| Module | Responsibility |
| --- | --- |
| `src/startup.rs` | Command-line arguments (`--version`, `--help`), startup loading, and hidden terminal password input |
| `src/main.rs` | App state, event loop, main view rendering, password prompt, deleting entries and confirmation questions, file loading (size limit, format detection), terminal setup and restoration |
| `src/certificate_file.rs` | PEM, DER, and PKCS#7 certificate files (including requests), and chain linking within a file |
| `src/chain_edit.rs` | Editing a private key's chain: the append-or-remove question, checking that a certificate issued the chain's last one, and replacing the chain |
| `src/certificate_request.rs` | PKCS#10 certificate requests: fields, requested extensions, and attributes |
| `src/file_picker.rs` | The keystore file browser |
| `src/canonical_path.rs` | Canonical paths without the Windows verbatim `\\?\` prefix, as the file browser, path bar, and export prompt show them |
| `src/path_bar.rs` | The opened file's path line and absolute directory, shared by the main view and the detail view |
| `src/editing.rs` | The alias prompt, renaming an entry, and importing a trusted certificate or a key pair under the typed alias |
| `src/generate.rs` | Generating a key pair: the RSA, EC, and Ed25519 keys as PKCS #8, and adding the result with its certificate under the typed alias |
| `src/certificate_form.rs` | The form asking what a new key pair's certificate or a certificate request holds, and its checks |
| `src/ca_reply.rs` | Importing a CA reply: building the issued chain from the reply file and the keystore's certificates, and replacing a private key's chain with it |
| `src/new_request.rs` | Making a certificate request for a private key: starting the form from its certificate, the file name prompt, and writing the request |
| `src/signing.rs` | Certificates and requests signed with a PKCS #8 key: the subject name, the extensions of a purpose, alternative names, the signature algorithm of a key type, a self-signed certificate, and a PKCS #10 request |
| `src/key_export.rs` | Exporting a private key, alone or with its certificates, to a new PKCS12, PEM, or DER file, and its name prompt |
| `src/key_import.rs` | Importing a key pair: finding the private key in a PEM or PKCS #8 file, or a keystore to copy from, the file's password prompt, and matching a key to its certificate chain |
| `src/copy_entries.rs` | Copying entries from another keystore: the list in which they are chosen, and adding them to the open keystore |
| `src/new_password.rs` | Typing a new password twice, changing the open keystore's password or a key's password, and creating a new keystore file |
| `src/save.rs` | The open keystore's writable form and password, converting it to another format, the "save as" and new-keystore name prompt, and replacing a file atomically |
| `src/keystore.rs` | JKS and JCEKS parsing, integrity check (SHA-1), and writing entries back as stored, renamed, added, or with another certificate chain; the shared `KeystoreEntry` model, whose content is certificates (with their `Kind`) or a request |
| `src/key_protection.rs` | Java's password protection of private keys in JKS (SHA-1 keystream) and JCEKS (`PBEWithMD5AndTripleDES`): recovering a key and protecting it again |
| `src/java_serialization.rs` | Skipping a serialized Java object (a JCEKS secret key) without deserializing it |
| `src/pkcs12.rs` | PKCS12 parsing, MAC verification, and decryption of safe contents (AES and legacy PBE); listing entries from bags; editing bags, re-encrypting keys for a new password, and writing bags back with PBES2 and a new MAC |
| `src/entry_list.rs` | Entry-list filtering, sorting, and expiry classification |
| `src/certificate.rs` | X.509 summary (subject, algorithm, key size, expiry) for the entry table |
| `src/certificate/details.rs` | Full certificate fields for the detail view |
| `src/certificate/extensions.rs` | Decoding X.509 extensions into display lines |
| `src/certificate/security.rs` | Weak key-size and signature-hash checks |
| `src/certificate/diagnostics.rs` | Offline stored-chain validity, issuer and CA constraint diagnostics; no trust decisions |
| `src/certificate/signature.rs` | Checking a certificate's signature with its issuer's public key, and a request's with its own; finding a certificate's SubjectPublicKeyInfo |
| `src/entry_details.rs` | The full-screen detail view: layout, keys, the bottom pane (details, diagnostics, ASN.1, PEM), export, and shared detail formatting |
| `src/entry_details/chain.rs` | A stored chain's hierarchy and certificate details |
| `src/entry_details/request.rs` | A certificate request's details, shown in place of a hierarchy |
| `src/asn1_dump.rs` | The ASN.1 structure dump of a certificate or request, hiding challenge passwords |
| `src/export.rs` | The export name prompt and writing PEM/DER certificate, public key, and request files |
| `src/test_support.rs`, `src/tests.rs` | Unit-test helpers, synthetic keystores, and tests |
| `tests/terminal_smoke/` | Unix PTY smoke tests against the built binary: the harness (`pty.rs`, `screen.rs`, `fixtures.rs`), tests grouped by SPEC section, each linking the sections it checks, and the link check (`spec.rs`) |
| `tests/fixtures/` | Generated keystore fixtures; see its `README.md` for how they were made |
| `dist-workspace.toml`, `.github/workflows/release.yml` | Release configuration for [`dist`](https://github.com/axodotdev/cargo-dist) and the workflow it generates |
| `.github/workflows/publish-crates.yml` | The crates.io publish job that `release.yml` calls |
| `.github/workflows/tag-release.yml` | Tags a new `Cargo.toml` version on `main`, which starts `release.yml` |
| `.github/workflows/rust.yml` | CI checks (format, lint, build, tests), a minimum-supported-Rust build, macOS tests, including the PTY smoke tests, Windows unit tests, and test coverage, uploaded to Codecov, for pushes to `main` and PRs |
| `.github/dependabot.yml` | Monthly grouped Cargo and GitHub Actions updates, leaving out the generated `release.yml` |
| `.github/workflows/dependabot-auto-merge.yml` | Turns on auto-merge for Dependabot PRs, which merge once the required checks pass |

Dependencies are deliberately few:

- `ratatui`, with the `crossterm` backend, for the UI.
- `sha1` for the JKS and JCEKS integrity digest and the JKS key protector.
- `crown` for ASN.1, PEM, X.509, PKCS#7, PKCS12 (MAC and PBE), signature
  verification (certificates and requests), key generation, and signing
  certificates and requests. It generates RSA keys without giving out their private parts,
  so `generate.rs` works them out again from the modulus and the random
  candidates the generator drew.
- `zeroize` for wiping passwords, including the one kept for saving.
- `getrandom` for the random salts and IVs of saved PKCS12 keystores, and for
  generated keys and serial numbers.

The PTY smoke tests also use `rustix` (Unix only, a dev-dependency) for
pseudo-terminals; crossterm already depends on it.

