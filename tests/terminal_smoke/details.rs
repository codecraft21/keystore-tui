//! The entry detail view and its panes.

use std::ffi::OsStr;
use std::fs;

use crate::fixtures::{TempDir, empty_password_fixture, fixture_certificate};
use crate::pty::PtyApp;

/// SPEC: [Offline chain diagnostics](../../docs/SPEC.md#offline-chain-diagnostics).
#[test]
fn chain_diagnostics_navigation() {
    let directory = TempDir::new();
    fs::write(directory.join("certificate.der"), fixture_certificate()).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("certificate.der")]);
    app.expect(&["Certificate details", "[verified]"]);
    app.send(b"d");
    app.expect(&[
        "Chain diagnostics",
        "Trust: not checked",
        "Revocation: not checked",
        "certificate.der'",
    ]);
    app.resize(60, 24);
    app.send(b"\x1b[F");
    app.expect(&["self-issued; trust not checked"]);
    app.send(b"d");
    app.expect(&["Certificate details", "Subject:"]);
    app.send(b"\x1b");
    app.expect(&["1 entries | Sort: alias"]);
    app.send(b"q");
    app.assert_restored();
}

/// SPEC: [ASN.1 and PEM views](../../docs/SPEC.md#asn1-and-pem-views).
#[test]
fn asn1_and_pem_panes() {
    let directory = TempDir::new();
    fs::write(directory.join("certificate.der"), fixture_certificate()).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("certificate.der")]);
    app.expect(&["Certificate details", "a ASN.1 | p PEM"]);
    app.send(b"a");
    app.expect(&[
        "Certificate ASN.1 [focused]",
        "SEQUENCE (3 elements)",
        "(commonName)",
    ]);
    app.send(b"p");
    app.expect(&["Certificate PEM [focused]", "-----BEGIN CERTIFICATE-----"]);
    app.send(b"p");
    app.expect(&["Certificate details [focused]", "Subject:"]);
    app.send(b"q");
    app.assert_restored();
}

fn exercise(exit_key: &[u8]) {
    // This fixture contains only a generated public certificate. Its integrity
    // digest is recomputed for an empty password, avoiding password input.
    let directory = TempDir::new();
    fs::write(directory.join("entry.jks"), empty_password_fixture()).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[]);
    app.open_from_picker("entry.jks");
    app.expect(&["root-cert", "Expires"]);
    app.send(b"\r");
    app.expect(&["Certificate hierarchy", "Version: 3", "[verified]"]);
    app.send(b"\t");
    app.expect(&["Certificate details [focused]"]);
    app.send(b"\x1b[F"); // End scrolls to the fingerprint and extensions.
    app.expect(&[
        "Signature: verified with its own public key (self-signed).",
        "Fingerprint (SHA-256)",
        "Extensions:",
        "Subject Key Identifier (2.5.29.14)",
    ]);
    app.send(b"f");
    app.expect(&["Fingerprint (SHA-1)"]);
    app.send(b"\x1b[H"); // Home restores the top fields.
    app.expect(&["Version: 3"]);
    app.resize(40, 8);
    app.expect(&["Resize terminal"]);
    app.resize(100, 30);
    app.expect(&["Certificate hierarchy", "Version: 3"]);
    app.send(b"\x1b");
    app.expect(&["root-cert", "Expires"]);
    app.send(b"\r");
    app.expect(&["Certificate hierarchy"]);
    app.send(exit_key);
    app.assert_restored();
}

/// SPEC: [Entry details](../../docs/SPEC.md#entry-details),
/// [Extensions](../../docs/SPEC.md#extensions),
/// [Signature checks](../../docs/SPEC.md#signature-checks),
/// [Small terminals](../../docs/SPEC.md#small-terminals),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn quit_restores_terminal() {
    exercise(b"q");
}

/// SPEC: [Entry details](../../docs/SPEC.md#entry-details),
/// [Extensions](../../docs/SPEC.md#extensions),
/// [Signature checks](../../docs/SPEC.md#signature-checks),
/// [Small terminals](../../docs/SPEC.md#small-terminals),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn ctrl_c_restores_terminal() {
    exercise(b"\x03");
}
