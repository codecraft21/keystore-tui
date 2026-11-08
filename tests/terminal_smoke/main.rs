//! Exercise the built TUI in a real Unix PTY using generated public test data.
//!
//! `cargo test` builds the binary and runs these tests on Unix (including
//! Linux/WSL and macOS). Set `KEYSTORE_TUI_BINARY=/absolute/path/to/keystore-tui`
//! to test another build: `cargo test --locked --test terminal_smoke`.
//!
//! [`pty`], [`screen`], and [`fixtures`] are the harness. Every test in the
//! other modules has a `SPEC:` doc line linking the [SPEC](../../docs/SPEC.md)
//! sections it checks; [`spec`] fails when one is missing or names no heading.

#![cfg(unix)]

mod fixtures;
mod pty;
mod screen;
mod spec;

mod browser;
mod details;
mod entry_list;
mod export;
mod startup;
