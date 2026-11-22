# Architecture

How keystore-tui is organised, to help locate responsibilities. Behaviour is
specified in [SPEC](SPEC.md); development checks and conventions are in
[AGENTS.md](../AGENTS.md). Each module's own doc comment has the details.

## Overview

keystore-tui is a single binary crate with no Java dependency. It is built in
three layers:

1. **Application shell** (`main.rs`, `startup.rs`): command-line handling,
   terminal setup and restoration, the event loop, and the `App` state.
2. **Workflows and views**: the screens, prompts, and forms that turn key
   presses into actions on the open keystore.
3. **Formats and cryptography**: parsing, verifying, editing, and writing
   keystores, certificates, requests, and revocation lists. These modules
   know nothing about the UI.

## Application shell

`main.rs` holds the `App` struct, which owns the loaded entries and the state
of whichever prompt, form, or view is active (each an `Option` field). Its
event loop draws, then routes each key press to the active component; global
keys such as `Ctrl+C` are handled first. Workflow modules add their own
`impl App` blocks rather than growing `main.rs`.

Long-running work (key pair generation) runs on a worker thread; the loop
polls it and shows a cancellable modal meanwhile.

## Workflows and views

| Area | Modules |
| --- | --- |
| Browsing and viewing | `file_picker`, `entry_list`, `entry_details/`, `asn1_dump`, `path_bar`, `canonical_path` |
| Shared input | `path_input` (file name prompts), `new_password` |
| Editing entries | `editing` (alias prompt, rename, import certificate), `copy_entries`, `chain_edit`, `ca_reply` |
| Keys | `generate`, `key_import`, `key_export`, `secret_entry` |
| Signing and requests | `certificate_form`, `new_request`, `sign`, `sign_form`, `crl_form` |
| Saving and exporting | `save` (save, save as, new keystore, atomic replace), `export` (certificates, public keys, requests, CRLs) |

## Formats and cryptography

| Area | Modules |
| --- | --- |
| JKS and JCEKS | `keystore` (parsing, integrity check, writing, and the shared `KeystoreEntry` model), `key_protection`, `java_serialization`, `secret_key` |
| PKCS12 | `pkcs12/` (`read`, `crypto`, `bags`, `write`) |
| Certificate files | `certificate_file` (PEM, DER, PKCS#7), `certificate_request`, `revocation_list` |
| X.509 | `certificate` (summary) and `certificate/` (details, extensions, security warnings, offline diagnostics, signature checks) |
| Creating objects | `signing` (certificates, requests, and CRLs signed with a PKCS #8 key) |

## Data flow

- **Opening:** a file is read with a size limit and its format detected. A
  keystore is verified with its password, giving the entry list and, when it
  can be edited, a writable `save::Document`. Certificate files are read-only.
- **Editing:** workflows change the entries and the document in memory and
  mark the keystore modified; nothing touches the file until an explicit save.
- **Saving:** the document is serialised and written to a temporary file in
  the target directory, then renamed over the original. Exports and "save as"
  only create new files.

## Handling secrets

Passwords live in zeroizing buffers; the open keystore's password is kept only
for saving. Private and secret keys are decrypted or generated in memory only
where a workflow needs them and are wiped afterwards. See the write and secret
rules in [AGENTS.md](../AGENTS.md) and [ROADMAP](ROADMAP.md).

## Dependencies

Dependencies are deliberately few:

- `ratatui` (crossterm backend) for the UI.
- `crown` for ASN.1, PEM, X.509, PKCS#7, PKCS12, signature verification, key
  generation, and signing.
- `sha1` for the JKS and JCEKS integrity digest and JKS key protection.
- `zeroize` for wiping passwords and keys.
- `getrandom` for salts, IVs, keys, and serial numbers.
- `rustix` (Unix dev-dependency, already used by crossterm) for the PTY smoke
  tests.

## Tests

- Unit tests sit next to their modules; `App` workflow tests are in
  `src/tests/`, with helpers and synthetic keystores in `src/test_support.rs`.
- `tests/terminal_smoke/` drives the built binary in a pseudo-terminal, with
  tests grouped by SPEC section and linked to it (checked by `spec.rs`).
- `tests/fixtures/` holds generated fixtures; see its `README.md`.

## CI and release

- `.github/workflows/rust.yml`: format, lint, tests, MSRV, macOS and Windows,
  and coverage; `ci-ok` is the single required check.
- `tag-release.yml` tags a new `Cargo.toml` version on `main`, which starts the
  [`dist`](https://github.com/axodotdev/cargo-dist)-generated `release.yml`
  (configured in `dist-workspace.toml`); it calls `publish-crates.yml`.
- `.github/dependabot.yml` and `dependabot-auto-merge.yml` handle dependency
  updates. See [RELEASING](RELEASING.md).
