//! Exercise the built TUI in a real Unix PTY using generated public test data.
//!
//! `cargo test` builds the binary and runs these tests on Unix (including
//! Linux/WSL and macOS). Set `KEYSTORE_TUI_BINARY=/absolute/path/to/keystore-tui`
//! to test another build: `cargo test --locked --test terminal_smoke`.
//!
//! [`pty`], [`screen`], and [`fixtures`] are the harness. Each test module's
//! documentation lists what it covers (keep it in step with the tests). Across
//! them, `q`, `Esc`, and `Ctrl+C` (including while typing a filter) restore
//! terminal modes, leave the alternate screen, and show the cursor again.

#![cfg(unix)]

mod fixtures;
mod pty;
mod screen;

mod details;
mod export;
mod lists;
mod startup;
