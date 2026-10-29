# Installation

[Back to the README](../README.md) for an overview and Homebrew installation.

Prebuilt binaries are published on the
[releases page](https://github.com/codecraft21/keystore-tui/releases) for
Linux (x86_64 and ARM64, statically linked), macOS (Intel and Apple Silicon),
and Windows (x86_64). Alternative installation methods:

- **Install script** (macOS and Linux), which downloads the binary for your
  platform into `~/.cargo/bin`:

  ```sh
  curl --proto '=https' --tlsv1.2 -LsSf https://github.com/codecraft21/keystore-tui/releases/latest/download/keystore-tui-installer.sh | sh
  ```

  On Windows, in PowerShell:

  ```powershell
  powershell -ExecutionPolicy Bypass -c "irm https://github.com/codecraft21/keystore-tui/releases/latest/download/keystore-tui-installer.ps1 | iex"
  ```

- **Manual download:** download the archive for your platform from the
  releases page, extract it, and put `keystore-tui` (or `keystore-tui.exe`) on
  your `PATH`. On macOS, a binary downloaded in a browser is quarantined
  because it is not notarized; run `xattr -d com.apple.quarantine keystore-tui`
  once to allow it.

- **From crates.io** with Rust 1.88 or later, which builds from source:

  ```sh
  cargo install --locked keystore-tui
  ```

- **From a clone** of the repository: `cargo run --locked`.

Check the installed version with `keystore-tui --version`.

## Verifying a download

Each archive has a `.sha256` checksum file next to it on the releases page.
Release artifacts also carry GitHub build provenance attestations, which the
[GitHub CLI](https://cli.github.com/) can check:

```sh
gh attestation verify keystore-tui-x86_64-unknown-linux-musl.tar.xz --repo codecraft21/keystore-tui
```
