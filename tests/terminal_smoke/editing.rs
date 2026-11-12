//! Deleting entries and saving the keystore.

use std::ffi::OsStr;
use std::fs;

use crate::fixtures::{
    TempDir, certificate_pem, empty_password_fixture, fixture_certificate, key_keystore,
    with_empty_password_digest,
};
use crate::pty::PtyApp;

/// SPEC: [Deleting entries](../../docs/SPEC.md#deleting-entries),
/// [Saving](../../docs/SPEC.md#saving),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn delete_save_and_quit_restores_terminal() {
    let directory = TempDir::new();
    let path = directory.join("store.jks");
    let original = empty_password_fixture();
    fs::write(&path, &original).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("store.jks")]);
    app.expect(&["root-cert", "d Delete | w Save | W Save as"]);
    app.send(b"d");
    app.expect(&["Delete entry 'root-cert'? Press y"]);
    app.send(b"y");
    app.expect(&["Deleted entry 'root-cert'.", "[modified]", "no entries"]);
    // Nothing is written before saving, and quitting asks first.
    assert_eq!(fs::read(&path).unwrap(), original);
    app.send(b"q");
    app.expect(&["Quit without saving the changes?"]);
    app.send(b"n");
    assert_eq!(app.exited(), None);
    app.send(b"W");
    app.expect(&["Save keystore as:"]);
    app.send(b"\x15"); // Ctrl+U clears the suggested absolute path.
    app.expect(&["Save keystore as: _"]);
    app.send(b"copy.jks\r"); // Saved next to the opened file.
    app.expect(&["Saved"]);
    assert_eq!(fs::read(&path).unwrap(), original);
    // An empty JKS keystore: header, no entries, digest.
    assert_eq!(fs::read(directory.join("copy.jks")).unwrap().len(), 32);
    app.send(b"q");
    app.assert_restored();
}

/// SPEC: [Saving](../../docs/SPEC.md#saving),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn save_in_place_then_ctrl_c_restores_terminal() {
    let directory = TempDir::new();
    let path = directory.join("store.jks");
    fs::write(&path, empty_password_fixture()).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("store.jks")]);
    app.expect(&["root-cert"]);
    app.send(b"w");
    app.expect(&["No changes to save."]);
    app.send(b"dy");
    app.expect(&["[modified]"]);
    app.send(b"w");
    app.expect(&["Saved"]);
    assert_eq!(fs::read(&path).unwrap().len(), 32);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    app.send(b"\x03");
    app.assert_restored();
}

/// SPEC: [Renaming entries](../../docs/SPEC.md#renaming-entries),
/// [Importing certificates](../../docs/SPEC.md#importing-certificates),
/// [Saving](../../docs/SPEC.md#saving),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn rename_import_save_and_quit_restores_terminal() {
    let directory = TempDir::new();
    let path = directory.join("store.jks");
    let original = empty_password_fixture();
    fs::write(&path, &original).unwrap();
    fs::write(
        directory.join("ca.pem"),
        certificate_pem(&fixture_certificate()),
    )
    .unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("store.jks")]);
    app.expect(&["root-cert", "i Import | r Rename"]);
    app.send(b"r");
    app.expect(&["New alias for 'root-cert': root-cert_"]);
    app.send(b"\x15q"); // Ctrl+U clears; `q` is typed, not a quit.
    app.expect(&["New alias for 'root-cert': q_"]);
    app.send(b"\x7fOld-Root\r");
    app.expect(&["Renamed entry 'root-cert' to 'old-root'.", "[modified]"]);
    app.send(b"i");
    app.expect(&["Import certificate from file", "ca.pem"]);
    app.send(b"ca\r");
    app.expect(&["Alias for the imported certificate: jks tui test fixture_"]);
    app.send(b"\x15new-root\r");
    app.expect(&[
        "Imported certificate as 'new-root'.",
        "old-root",
        "2 entries",
    ]);
    assert_eq!(fs::read(&path).unwrap(), original);
    app.send(b"w");
    app.expect(&["Saved"]);
    let saved = fs::read(&path).unwrap();
    assert_eq!(&saved[8..12], &2_u32.to_be_bytes());
    for alias in [&b"old-root"[..], b"new-root"] {
        assert!(saved.windows(alias.len()).any(|window| window == alias));
    }
    app.send(b"q");
    app.assert_restored();
}

/// SPEC: [Creating a keystore](../../docs/SPEC.md#creating-a-keystore),
/// [Changing the password](../../docs/SPEC.md#changing-the-password),
/// [Saving](../../docs/SPEC.md#saving),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn create_keystore_change_password_and_quit_restores_terminal() {
    let directory = TempDir::new();
    let mut app = PtyApp::spawn(directory.path(), &[]);
    app.expect(&["Press n to create a JKS, JCEKS, or PKCS12 keystore."]);
    app.send(b"n");
    app.expect(&["New keystore file (.jks, .jceks, or .p12):"]);
    app.send(b"\x15new.jks\r");
    app.expect(&["Password for the new keystore: _"]);
    app.send(b"qwerty"); // Typed, masked, into the password.
    app.expect(&["Password for the new keystore: ******_"]);
    assert!(!directory.join("new.jks").exists());
    app.send(b"\r");
    app.expect(&["Type the password again: _"]);
    app.send(b"qwerty\r");
    app.expect(&["Created the JKS keystore", "no entries", "p Password"]);
    let created = fs::read(directory.join("new.jks")).unwrap();
    assert_eq!(created.len(), 32);

    app.send(b"p");
    app.expect(&["New keystore password: _"]);
    app.send(b"\r");
    app.expect(&["Type the password again: _"]);
    app.send(b"\r");
    app.expect(&["Password changed", "[modified]"]);
    assert_eq!(fs::read(directory.join("new.jks")).unwrap(), created);
    app.send(b"w");
    app.expect(&["Saved"]);
    // The empty password's digest replaces the old one.
    assert_eq!(
        fs::read(directory.join("new.jks")).unwrap(),
        with_empty_password_digest(created[..12].to_vec())
    );
    app.send(b"q");
    app.assert_restored();
}

/// SPEC: [Creating a keystore](../../docs/SPEC.md#creating-a-keystore),
/// [Importing certificates](../../docs/SPEC.md#importing-certificates),
/// [Writing PKCS12 keystores](../../docs/SPEC.md#writing-pkcs12-keystores),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn create_pkcs12_import_save_and_quit_restores_terminal() {
    let directory = TempDir::new();
    let certificate = fixture_certificate();
    fs::write(directory.join("ca.pem"), certificate_pem(&certificate)).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[]);
    app.expect(&["No keystore selected"]);
    app.send(b"n");
    app.expect(&["New keystore file (.jks, .jceks, or .p12):"]);
    app.send(b"\x15new.p12\r");
    app.expect(&["Password for the new keystore: _"]);
    app.send(b"secret\r");
    app.expect(&["Type the password again: _"]);
    app.send(b"secret\r");
    app.expect(&["Created the PKCS12 keystore", "no entries"]);
    let empty = fs::read(directory.join("new.p12")).unwrap();
    app.send(b"i");
    app.expect(&["Import certificate from file", "ca.pem"]);
    app.send(b"ca\r");
    app.expect(&["Alias for the imported certificate:"]);
    app.send(b"\x15root\r");
    app.expect(&["Imported certificate as 'root'.", "Trusted certificate"]);
    assert_eq!(fs::read(directory.join("new.p12")).unwrap(), empty);
    app.send(b"w");
    app.expect(&["Saved"]);
    // The certificate is stored encrypted.
    let saved = fs::read(directory.join("new.p12")).unwrap();
    assert!(saved.len() > empty.len() + certificate.len());
    assert!(
        !saved
            .windows(certificate.len())
            .any(|window| window == certificate)
    );
    app.send(b"q");
    app.assert_restored();

    // The saved keystore opens again with its password.
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("new.p12")]);
    app.expect(&["Keystore password:"]);
    app.send(b"secret\r");
    app.expect(&["root", "Trusted certificate", "1 entries"]);
    app.send(b"q");
    app.assert_restored();
}

/// SPEC: [Changing a key password](../../docs/SPEC.md#changing-a-key-password),
/// [Saving](../../docs/SPEC.md#saving),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn change_key_password_save_and_quit_restores_terminal() {
    let directory = TempDir::new();
    let path = directory.join("keys.jks");
    let original = key_keystore("keypass");
    fs::write(&path, &original).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("keys.jks")]);
    app.expect(&["server", "Private key", "P Key password"]);
    app.send(b"P");
    app.expect(&["Current password of key 'server': _"]);
    app.send(b"wrong\r");
    app.expect(&["Incorrect key password."]);
    app.send(b"keypass\r");
    app.expect(&["New password for key 'server': _"]);
    app.send(b"q1\r"); // `q` is typed, masked, into the password.
    app.expect(&["Type the password again: _"]);
    app.send(b"q1\r");
    app.expect(&["Password of key 'server' changed", "[modified]"]);
    assert_eq!(fs::read(&path).unwrap(), original);
    app.send(b"w");
    app.expect(&["Saved"]);
    // Everything before the key's new random salt is as it was, and the
    // protected key has the same size.
    let saved = fs::read(&path).unwrap();
    assert_eq!(saved[..56], original[..56]);
    assert_ne!(saved, original);
    assert_eq!(saved.len(), original.len());
    app.send(b"q");
    app.assert_restored();

    // The key now opens with the new password and not the old one.
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("keys.jks")]);
    app.expect(&["server", "Private key"]);
    app.send(b"P");
    app.expect(&["Current password of key 'server': _"]);
    app.send(b"keypass\r");
    app.expect(&["Incorrect key password."]);
    app.send(b"q1\r");
    app.expect(&["New password for key 'server': _"]);
    app.send(b"\x03");
    app.assert_restored();
}
