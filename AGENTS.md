# Agent and contributor guide

keystore-tui is a small, read-only Rust and Ratatui TUI for inspecting JKS,
JCEKS, and PKCS12 keystores, standalone certificate files, and certificate
signing requests. [`README.md`](README.md) describes the app from the user's
point of view. [`docs/SPEC.md`](docs/SPEC.md) specifies its detailed behaviour.
This file covers how the code is organised and how to work on it.

## Contents

- [Architecture](#architecture)
- [Development](#development)
  - [Fixtures](#fixtures)
- [Conventions and constraints](#conventions-and-constraints)
- [Documentation](#documentation)
- [Workflow](#workflow)
  - [Releasing](#releasing)

## Architecture

| Module | Responsibility |
| --- | --- |
| `src/startup.rs` | Command-line arguments (`--version`, `--help`), startup loading, and hidden terminal password input |
| `src/main.rs` | App state, event loop, main view rendering, password prompt, file loading (size limit, format detection), terminal setup and restoration |
| `src/certificate_file.rs` | PEM, DER, and PKCS#7 certificate files (including requests), and chain linking within a file |
| `src/certificate_request.rs` | PKCS#10 certificate requests: fields, requested extensions, and attributes |
| `src/file_picker.rs` | The keystore file browser |
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

## Development

Cargo sets `TMPDIR` to the repository root for builds and tests (see
`.cargo/config.toml`). Temporary files therefore stay inside the workspace even
when the system temporary directory is unavailable.

Run these after any code or dependency change:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

On Linux, macOS, or WSL, also run the PTY smoke tests after building. They need
Python 3 and use only its standard library:

```sh
cargo build --locked
python3 tests/terminal_smoke.py
```

To test a build in another location, pass
`--binary /absolute/path/to/keystore-tui`.

The smoke tests use a generated public-certificate fixture with an empty
password. They exercise opening a keystore, detail navigation, scrolling,
signature checks, fingerprints, extensions, the file path, resizing, and
returning to the list. At startup, they check the hidden password prompt for
JKS, JCEKS, and PKCS12 fixtures, including the no-MAC `encrypted-no-mac.p12`,
and that a wrong password, `Ctrl+C`, or `Esc` there exits without starting the
app. They check that `empty-password.p12` and the no-MAC `passwordless.p12`
open without a prompt, and that a missing, invalid, or malformed path shows a
warning, a path with spaces opens, and extra arguments print usage. They open
PEM, DER, and request files given at startup straight into their details, and
open and leave the chain diagnostics view. They also build a three-entry store
at runtime from copies of that certificate to exercise entry selection
wrapping with the arrow keys, filtering (including `q` typed into the filter
and `Esc` cancelling it), and sorting. They also open a PEM certificate file
and export it, checking that `q` is typed into the export name and `Esc`
cancels the prompt. They open the `keytool` certificate request fixture, check
its signature is verified, and export it as PEM. They check that `--version`
and `--help` print and exit without starting the app. They check that `q`,
`Esc`, and `Ctrl+C` (including while typing a filter) restore terminal modes,
leave the alternate screen, and show the cursor again.

CI (`.github/workflows/rust.yml`) runs all of the above on Linux for every push
to `main` and every pull request. The release workflow also runs `dist plan` on
pull requests to check the release configuration.

For TUI changes, also check rendering, input, and terminal restoration by hand
in an interactive terminal.

### Fixtures

Fixtures are generated with Java `keytool`, OpenSSL, or, for `example.jks`,
Python's `cryptography` package. `invalid-ciphertext-no-mac.p12` is derived
from an OpenSSL fixture by a script that uses only the Python standard library. The commands are recorded in
`tests/fixtures/README.md`. These tools are needed only to regenerate fixtures,
never to build, test, or run the app. Tests that need private-key entries build them at
runtime from synthetic bytes, so no private key is ever committed.

## Conventions and constraints

- **Scope:** keep changes focused on the small TUI. Add modules as
  responsibilities grow rather than enlarging existing ones.
- **Self-contained:** opening keystores must work without Java or `keytool`.
- **Dependencies:** keep dependencies and their enabled features to a minimum.
  Check that a new dependency is really needed before adding it.
- **Terminal safety:** keep terminal restoration working on initialization
  failure, on errors, and on normal exit. Keep every documented quit shortcut.
- **Secrets:** use generated fixtures only. Keep passwords, private keys, and
  real keystores out of logs, test output, and commits. Wipe password buffers
  after use.
- **Read-only:** the app never writes keystores and never decrypts private keys.
  Certificate exports only ever create new files.

## Documentation

- `README.md` is the user's overview: what the app does, installation, quick
  start, and limitations. Update it when these change.
- `docs/REFERENCE.md` covers detailed usage and key bindings. Update it when
  user-visible behaviour changes.
- `docs/SPEC.md` holds the detailed behaviour contracts, such as validation
  rules, compatibility details, colours, and edge cases. Update it with every
  behaviour change.
- `CHANGELOG.md` lists user-visible changes per version. Add them under the
  next version's heading; its section becomes the GitHub release notes.
- This file covers architecture, development, and conventions. Update it when
  modules, checks, or workflows change.

## Workflow

When the user says "publish", do the following without asking for confirmation.
Use the configured GitHub plugin for every GitHub step, so that no Git
credentials are needed in the workspace. Use local Git only for inspection and
checkouts.

1. Run the [Development](#development) checks and fix any failures.
2. Commit to a feature branch, never `main`, and push it.
3. Open a pull request against `main`.
4. When CI finishes, merge if every check passed. If a check failed, fix it and
   push again, or report what is failing.
5. After merging, switch to `main`, pull, and delete the local feature branch.

When reporting back, give the pull request link, what changed, which checks ran
and their results, and any unresolved failures.

### Releasing

Releases are built by `.github/workflows/release.yml`, which
[`dist`](https://github.com/axodotdev/cargo-dist) generates from
`dist-workspace.toml`. Pushing a version tag such as `v1.2.0` builds static
Linux (x86_64 and ARM64, musl), macOS (x86_64 and ARM64), and Windows (x86_64)
binaries. It then pushes the Homebrew formula to `codecraft21/homebrew-tap`,
publishes the crate to crates.io, and creates a GitHub release with the
archives, SHA-256 checksums, build provenance attestations, and shell and
PowerShell installers.

1. In a pull request, bump `version` in `Cargo.toml` (run `cargo build`, not
   `--locked`, to update `Cargo.lock`), and move the changes into a
   `## <version>` section of `CHANGELOG.md`.
2. When it merges, `tag-release.yml` tags the merge commit with
   `v<version>`, which starts the release. It does nothing when that tag
   already exists. To tag by hand instead, push `v<version>`; the tag must
   match the `Cargo.toml` version, or `dist` finds nothing to release.
3. Check that the release workflow passed and that the release lists every
   archive.

To rehearse, release a pre-release version such as `1.2.0-rc.1` the same way:
bump `Cargo.toml` to it, and `v1.2.0-rc.1` is tagged on merge. Pre-releases
skip the Homebrew and crates.io jobs.

`publish-crates.yml` publishes with crates.io
[Trusted Publishing](https://crates.io/docs/trusted-publishing), so no
crates.io token is stored. crates.io trusts `release.yml` in this repository
(the calling workflow, not `publish-crates.yml`). The job skips a version that
is already on crates.io. The first version, 1.0.0, is published by hand,
because crates.io requires a crate's first version to be published with an API
token.

Don't edit `release.yml` by hand. Change `dist-workspace.toml` and run
`dist generate`, using the `cargo-dist-version` it pins. `dist` is only needed
for this; it is not a build or test dependency.

The workflows need two repository secrets:

- `HOMEBREW_TAP_TOKEN`: a token that can push to `codecraft21/homebrew-tap`.
- `RELEASE_TAG_TOKEN`: a fine-grained token for this repository with Contents
  read and write access, used by `tag-release.yml`. Tags created with the
  built-in `GITHUB_TOKEN` don't start other workflows, so `release.yml` would
  not run.
