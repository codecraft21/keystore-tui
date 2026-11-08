//! Starting the app with and without a path.
//!
//! - The hidden startup password prompt for JKS, JCEKS, and PKCS12 fixtures,
//!   including the no-MAC `encrypted-no-mac.p12`; a wrong password, `Ctrl+C`, or
//!   `Esc` there exits without starting the app.
//! - `empty-password.p12` and the no-MAC `passwordless.p12` open without a prompt.
//! - A missing, invalid, or malformed path shows a warning, a path with spaces
//!   opens, and extra arguments print usage.
//! - The committed single-certificate PEM and DER (`.crt`) fixtures and the
//!   request fixture given at startup open straight into their details, and
//!   `Esc` returns to the list; the two-certificate `bundle.pem` opens on the
//!   list.
//! - `--version` and `--help` print and exit without starting the app.

use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::fixtures::{ROOT, TempDir, empty_password_fixture, fixture};
use crate::pty::{PtyApp, binary};
use crate::screen::contains;

#[test]
fn startup_password() {
    for name in [
        "trusted-cert.jks",
        "trusted-cert.jceks",
        "trusted-cert.p12",
        "encrypted-no-mac.p12",
    ] {
        let path = fixture(name);
        let mut app = PtyApp::spawn(Path::new(ROOT), &[path.as_os_str()]);
        app.expect(&["Keystore password:"]);
        assert!(!contains(app.output(), b"\x1b[?1049h"), "{name}");
        app.send(b"changeit\r");
        app.expect(&["root-cert"]);
        assert!(!contains(app.output(), b"changeit"), "{name}");
        app.send(b"q");
        assert_eq!(app.wait(), 0, "{name}");
        app.assert_modes_restored();
    }
}

#[test]
fn startup_password_failure() {
    let path = fixture("trusted-cert.jks");
    for keys in [&b"wrong-secret\r"[..], b"\x03", b"\x1b"] {
        let mut app = PtyApp::spawn(Path::new(ROOT), &[path.as_os_str()]);
        app.expect(&["Keystore password:"]);
        app.send(keys);
        assert_eq!(app.wait(), 1, "{keys:?}");
        app.read(Duration::from_millis(100));
        assert!(!contains(app.output(), b"wrong-secret"), "{keys:?}");
        assert!(!contains(app.output(), b"\x1b[?1049h"), "{keys:?}");
        app.assert_modes_restored();
    }
}

#[test]
fn startup_invalid_path() {
    for path in ["missing.jks", "README.md", "tests"] {
        let mut app = PtyApp::spawn(Path::new(ROOT), &[OsStr::new(path)]);
        app.expect(&["No keystore selected", path, "Quit"]);
        assert!(!contains(app.output(), b"Keystore password:"), "{path}");
        assert!(contains(app.output(), b"38;5;3;"), "{path}");
        app.send(b"q");
        assert_eq!(app.wait(), 0, "{path}");
    }
}

#[test]
fn startup_spaces_and_malformed() {
    let directory = TempDir::new();
    let name = OsStr::new("store with spaces.jks");
    let path = directory.join("store with spaces.jks");
    let fixture = empty_password_fixture();
    fs::write(&path, &fixture).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[name]);
    app.expect(&["root-cert", "Quit"]);
    app.send(b"q");
    app.assert_restored();

    fs::write(&path, &fixture[..12]).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[name]);
    app.expect(&["No keystore selected", "not a valid", "Quit"]);
    assert!(contains(app.output(), b"38;5;3;"));
    app.send(b"q");
    app.assert_restored();
}

#[test]
fn startup_certificate_details() {
    let directory = TempDir::new();
    for (name, source, heading) in [
        (
            "certificate with spaces.pem",
            "trusted-cert.pem",
            "Certificate hierarchy",
        ),
        (
            "trusted-cert.crt",
            "trusted-cert.crt",
            "Certificate hierarchy",
        ),
        ("request.csr", "keytool-request.csr", "Request details"),
    ] {
        fs::copy(fixture(source), directory.join(name)).unwrap();
        let mut app = PtyApp::spawn(directory.path(), &[OsStr::new(name)]);
        app.expect(&[heading, "[verified]", &format!("{name}'")]);
        assert!(!contains(app.output(), b"Keystore password:"), "{name}");
        app.send(b"\x1b");
        app.expect(&["1 entries | Sort: alias"]);
        app.send(b"q");
        app.assert_restored();
    }
}

#[test]
fn startup_certificate_bundle_opens_on_the_list() {
    let directory = TempDir::new();
    let mut app = PtyApp::spawn(directory.path(), &[fixture("bundle.pem").as_os_str()]);
    app.expect(&[
        "JKS TUI test fixture",
        "example-03",
        "2 entries | Sort: alias",
    ]);
    assert!(!contains(app.output(), b"Certificate hierarchy"));
    app.send(b"q");
    app.assert_restored();
}

#[test]
fn startup_extra_arguments() {
    let result = Command::new(binary()).args(["a", "b"]).output().unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(contains(&result.stderr, b"Usage:"));
}

#[test]
fn version_and_help() {
    for (flag, expected) in [
        ("--version", &b"keystore-tui "[..]),
        ("-V", b"keystore-tui "),
        ("--help", b"Usage: keystore-tui [path]"),
        ("-h", b"Usage: keystore-tui [path]"),
    ] {
        let result = Command::new(binary()).arg(flag).output().unwrap();
        assert_eq!(result.status.code(), Some(0), "{flag}");
        assert!(contains(&result.stdout, expected), "{flag}");
        assert!(!contains(&result.stdout, b"\x1b[?1049h"), "{flag}");
    }
}

#[test]
fn startup_empty_password() {
    for name in ["empty-password.p12", "passwordless.p12"] {
        let path = fixture(name);
        let mut app = PtyApp::spawn(Path::new(ROOT), &[path.as_os_str()]);
        app.expect(&["root-cert"]);
        assert!(!contains(app.output(), b"Keystore password:"), "{name}");
        app.send(b"q");
        assert_eq!(app.wait(), 0, "{name}");
    }
}
