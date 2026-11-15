<img src="docs/logo.svg" alt="keystore-tui logo: a terminal prompt with a key as the cursor" width="96">

# keystore-tui

[![CI](https://github.com/codecraft21/keystore-tui/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/codecraft21/keystore-tui/actions/workflows/rust.yml?query=branch%3Amain)
[![Coverage](https://codecov.io/gh/codecraft21/keystore-tui/graph/badge.svg?branch=main)](https://codecov.io/gh/codecraft21/keystore-tui)
[![Release](https://img.shields.io/github/v/release/codecraft21/keystore-tui)](https://github.com/codecraft21/keystore-tui/releases/latest)
[![crates.io](https://img.shields.io/crates/v/keystore-tui.svg)](https://crates.io/crates/keystore-tui)
[![License](https://img.shields.io/crates/l/keystore-tui.svg)](LICENSE)

A terminal app for managing keystores, keys, and certificates.

<p align="center">
  <a href="docs/main-screen.png"><img src="docs/main-screen.png" alt="Entry list with expiry highlighting and keystore and key management shortcuts" width="32%"></a>
  <a href="docs/entry-details.png"><img src="docs/entry-details.png" alt="Certificate details with verified signature, fingerprint, and export shortcuts" width="32%"></a>
  <a href="docs/chain-diagnostics.png"><img src="docs/chain-diagnostics.png" alt="Offline chain diagnostics with validity and signature checks, and explicit trust and revocation limitations" width="32%"></a>
</p>

<p align="center"><sub>Entry list · Certificate details · Chain diagnostics — click an image for full size.</sub></p>

Open your keystore and see what’s inside. Inspect certificates, manage keys,
and make changes from your terminal—without Java or `keytool`.

- **Find what needs attention.** Browse and filter entries, spot expired
  certificates, and flag weak cryptography.
- **Understand your certificates.** Explore certificate details and chains,
  check signatures, and inspect certificate requests and revocation lists.
- **Manage keys and certificates.** Create keys, request and sign certificates,
  import and export entries, and update passwords.
- **Save with confidence.** Changes stay in memory until you save. Convert
  between keystore formats while keeping your keys and certificates together.

Supports JKS, JCEKS, and PKCS12 keystores, plus standalone certificates,
certificate requests, and revocation lists. See the
[usage reference](docs/REFERENCE.md) for supported formats and all available
actions.

## Install

With Homebrew (macOS and Linux):

```sh
brew install codecraft21/tap/keystore-tui
```

See [other installation methods](docs/INSTALL.md) for scripts, manual downloads,
building from source, and download verification.

## Usage

Apart from starting the app without parameters, you can open a keystore,
certificate, or certificate request directly:

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
certificate details, chain diagnostics, ASN.1 and PEM views, and exports.

## Limitations

- Certificate checks run offline. They don’t establish whether a certificate
  is trusted or has been revoked.
- Saved PKCS12 files may not work with older Java versions.
- Some PKCS12 protection formats, including PBMAC1, aren’t supported.
- Built-in clipboard actions aren’t available.
- Files larger than 64 MiB can’t be opened.

See the [roadmap](docs/ROADMAP.md) for planned features.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
