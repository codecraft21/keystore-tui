# Architecture

The components of keystore-tui, what each one owns, and the rules for how they
depend on each other. Behaviour is specified in [SPEC](SPEC.md); development
workflow is in [AGENTS.md](../AGENTS.md).

## Components

```text
┌──────────────────────────────────────────────┐
│ Shell: startup, terminal, event loop, App    │
├──────────────────────────────────────────────┤
│ Workflows: prompts, forms, views, actions    │
├──────────────────────────────────────────────┤
│ Document: the open keystore, saving          │
├──────────────────────────────────────────────┤
│ Formats: keystores, X.509 objects, signing   │
└──────────────────────────────────────────────┘
         each layer uses only those below it
```

### Shell

Starts the program, owns the terminal, and runs the event loop. It holds the
application state: what is loaded and which workflow currently has focus. It
gives each key press to the focused workflow, except for global keys such as
quitting. It guarantees the terminal is restored however the program ends.

### Workflows

One component per user task: browsing files, viewing an entry, editing
entries, importing and exporting, generating keys, making and signing
requests, and so on. A workflow owns its own state while it is active, draws
itself, and turns input into requests to the document or the format layer.
Workflows build on shared UI pieces such as the file browser, text and
password inputs, the alias prompt, and the certificate form.

Work that can take long, such as key generation, runs off the event loop so
the UI stays responsive and the work can be cancelled.

### Document

The open keystore as an editable, saveable object: its entries, its password,
and whether it has unsaved changes. It is the only path by which a keystore
file is changed, and it changes one only on an explicit save, by replacing it
atomically. Read-only inputs (certificate files, incompletely read PKCS12
files) have no document.

### Formats

Pure data handling with no UI or terminal knowledge: reading, verifying, and
writing JKS, JCEKS, and PKCS12 keystores; reading certificates, requests, and
revocation lists from PEM, DER, and PKCS#7, and encoding PKCS#7 certificate
bundles; describing and checking X.509
objects; and creating keys, certificates, requests, and revocation lists.
It presents everything through one entry model shared by every keystore
format, so the layers above do not depend on the file format.

## Boundaries

- **Dependencies point down.** The format layer never refers to the document,
  workflows, or shell, and can be tested without a terminal.
- **One way to write a keystore.** Workflows change entries through the
  document; only the document writes the keystore file. Exports and "save as"
  create new files and never overwrite.
- **Secrets stay in memory, briefly.** Passwords and decrypted or generated
  keys live in wiping buffers, only for the operation that needs them. The
  document keeps the keystore password until the keystore is closed. Keys are
  never displayed or logged, and are written unencrypted only by an export the
  user confirms.
- **Untrusted input is bounded.** Files are size-limited before parsing, and
  malformed data is reported as an error.
- **No trust decisions.** Chain diagnostics are offline and informational;
  the app never decides whether a certificate is trusted.

## External dependencies

Kept deliberately few, each confined to the component that needs it:

| Dependency | Used by | For |
| --- | --- | --- |
| `ratatui` (crossterm) | Shell, workflows | Terminal and rendering |
| `crown` | Formats | ASN.1, PEM, X.509, PKCS#7, PKCS12, keys, signatures |
| `sha1` | Formats | JKS and JCEKS integrity and key protection |
| `getrandom` | Document, passed down to formats | Keys, serial numbers, salts, IVs |
| `zeroize` | Wherever secrets are held | Wiping passwords and keys |

## Known deviations

- `save.rs` contains both the document and the "save as" and new-keystore
  prompts, so it also depends on UI code.
- Workflows extend the shell's `App` state directly rather than through a
  narrower interface, so the shell's state lists every workflow's state.
