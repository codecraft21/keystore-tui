//! Exporting certificates, public keys, and certificate requests.

use std::ffi::OsStr;
use std::fs;

use crate::fixtures::{TempDir, certificate_pem, fixture, fixture_certificate, pem_der};
use crate::pty::PtyApp;

fn certificate_file(exit_key: &[u8]) {
    let pem = certificate_pem(&fixture_certificate());
    let directory = TempDir::new();
    fs::write(directory.join("certificate.pem"), &pem).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[]);
    // A single certificate opens from the browser straight into its details.
    app.open_from_picker("certificate.pem");
    app.expect(&["Certificate hierarchy", "x Export certificate"]);
    app.send(b"x");
    app.expect(&["Save certificate to:"]);
    app.send(b"\x15"); // Ctrl+U clears the suggested absolute path.
    app.expect(&["Save certificate to:"]);
    app.send(b"q"); // Typed into the name, not a quit.
    app.expect(&["Save certificate to: q"]);
    assert_eq!(app.exited(), None);
    app.send(b"x\x1b[D\x1b[Dp"); // Left twice, then insert at the start.
    app.expect(&["Save certificate to: pqx"]);
    app.send(b"\x1b[3~\x1b[F\x7f"); // Delete, End, Backspace.
    app.expect(&["Save certificate to: p "]);
    app.send(b".pem\r"); // Saved next to the file.
    app.expect(&["Saved certificate to"]);
    assert_eq!(fs::read_to_string(directory.join("p.pem")).unwrap(), pem);
    app.send(b"X");
    app.expect(&["Save chain to:"]);
    app.send(b"\x1b"); // Cancels the export, staying in the details.
    app.expect(&["x Export certificate", "Certificate hierarchy"]);
    app.send(exit_key);
    app.assert_restored();
}

/// SPEC: [Exporting](../../docs/SPEC.md#exporting),
/// [Certificate files](../../docs/SPEC.md#certificate-files),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn certificate_file_export_then_quit_restores_terminal() {
    certificate_file(b"q");
}

/// SPEC: [Exporting](../../docs/SPEC.md#exporting),
/// [Certificate files](../../docs/SPEC.md#certificate-files),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn certificate_file_export_then_ctrl_c_restores_terminal() {
    certificate_file(b"\x03");
}

/// SPEC: [Exporting](../../docs/SPEC.md#exporting),
/// [Certificate requests](../../docs/SPEC.md#certificate-requests),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn certificate_request_export_then_quit_restores_terminal() {
    let request = fs::read_to_string(fixture("keytool-request.csr")).unwrap();
    let directory = TempDir::new();
    fs::write(directory.join("server.csr"), &request).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[]);
    app.open_from_picker("server.csr");
    app.expect(&["Request details", "[verified]", "x Export request"]);
    app.send(b"x");
    app.expect(&["Save certificate request to:"]);
    app.send(b"\x15"); // Ctrl+U clears the suggested absolute path.
    app.send(b"q.csr\r");
    app.expect(&["Saved certificate request to"]);
    let saved = fs::read_to_string(directory.join("q.csr")).unwrap();
    assert!(saved.starts_with("-----BEGIN CERTIFICATE REQUEST-----\n"));
    assert_eq!(pem_der(&saved), pem_der(&request));
    app.send(b"q");
    app.assert_restored();
}

/// SPEC: [Exporting](../../docs/SPEC.md#exporting),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn public_key_export_then_quit_restores_terminal() {
    let directory = TempDir::new();
    fs::write(directory.join("certificate.der"), fixture_certificate()).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("certificate.der")]);
    app.expect(&["Certificate details", "X Chain | K Public key"]);
    app.send(b"K");
    app.expect(&["Save public key to:"]);
    app.send(b"\x15"); // Ctrl+U clears the suggested absolute path.
    app.send(b"K.pem\r"); // Typed into the name.
    app.expect(&["Saved public key to"]);
    let saved = fs::read_to_string(directory.join("K.pem")).unwrap();
    assert!(saved.starts_with("-----BEGIN PUBLIC KEY-----\n"));
    let key = pem_der(&saved);
    // The key is the certificate's own SubjectPublicKeyInfo.
    assert!(
        fixture_certificate()
            .windows(key.len())
            .any(|window| window == key)
    );
    app.send(b"q");
    app.assert_restored();
}

/// SPEC: [Exporting](../../docs/SPEC.md#exporting),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn ctrl_c_in_export_prompt_restores_terminal() {
    let directory = TempDir::new();
    fs::write(directory.join("certificate.der"), fixture_certificate()).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("certificate.der")]);
    app.expect(&["Certificate details", "x Export certificate"]);
    app.send(b"x");
    app.expect(&["Save certificate to:"]);
    app.send(b"\x03"); // Quits instead of being typed into the name.
    app.assert_restored();
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}
