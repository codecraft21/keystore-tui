//! Deleting entries and saving the keystore.

use std::ffi::OsStr;
use std::fs;

use crate::fixtures::{
    TempDir, certificate_pem, ed25519_certificate, empty_password_fixture, fixture_certificate,
    key_keystore, key_pair_pem, triage_keystore, with_empty_password_digest,
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
    app.expect(&["root-cert", "w Save | W Save as | p Password"]);
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
    app.expect(&["root-cert", "Entry: e Export | c Request | R CA reply"]);
    app.send(b"r");
    app.expect(&["New alias for 'root-cert': root-cert_"]);
    app.send(b"\x15q"); // Ctrl+U clears; `q` is typed, not a quit.
    app.expect(&["New alias for 'root-cert': q_"]);
    app.send(b"\x7fOld-Root\r");
    app.expect(&["Renamed entry 'root-cert' to 'old-root'.", "[modified]"]);
    app.send(b"i");
    app.expect(&["Import certificate or key pair from file", "ca.pem"]);
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
    app.expect(&["Import certificate or key pair from file", "ca.pem"]);
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

/// SPEC: [Converting a keystore](../../docs/SPEC.md#converting-a-keystore),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn convert_keystore_and_quit_restores_terminal() {
    let directory = TempDir::new();
    let path = directory.join("keys.jks");
    // The key shares the keystore's empty password.
    let original = key_keystore("");
    fs::write(&path, &original).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("keys.jks")]);
    app.expect(&["server", "Private key"]);
    app.send(b"W");
    app.expect(&["Save keystore as:", "name converts"]);
    // PKCS12 needs a password, so nothing is written.
    app.send(b"\x15keys.p12\r");
    app.expect(&["needs a password that is not empty"]);
    assert!(!directory.join("keys.p12").exists());
    app.send(b"\x15keys.jceks\r");
    // A long temporary path wraps the message, so only its start is expected.
    app.expect(&["Saved", "server", "Private key"]);
    assert_eq!(fs::read(&path).unwrap(), original);
    let converted = fs::read(directory.join("keys.jceks")).unwrap();
    assert_eq!(converted[..4], [0xce; 4]);
    // The converted keystore is the open one, and its key still unlocks
    // with the keystore's password.
    app.send(b"P");
    app.expect(&["New password for key 'server': _"]);
    app.send(b"\x1b");
    // Sent on its own: Esc followed at once by `q` would read as Alt+q.
    app.expect(&["P Key password"]);
    app.send(b"q");
    app.assert_restored();
}

/// SPEC: [Importing key pairs](../../docs/SPEC.md#importing-key-pairs),
/// [Saving](../../docs/SPEC.md#saving),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn import_key_pair_save_and_quit_restores_terminal() {
    let directory = TempDir::new();
    let path = directory.join("store.jks");
    let original = empty_password_fixture();
    fs::write(&path, &original).unwrap();
    fs::write(directory.join("pair.pem"), key_pair_pem()).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("store.jks")]);
    app.expect(&["root-cert", "Entry: e Export | c Request | R CA reply"]);
    app.send(b"i");
    app.expect(&["Import certificate or key pair from file", "pair.pem"]);
    app.send(b"pair\r");
    app.expect(&["Alias for the imported key pair: imported_"]);
    app.send(b"\r");
    app.expect(&[
        "Imported key pair as 'imported'.",
        "Private key",
        "Ed25519",
        "[modified]",
    ]);
    assert_eq!(fs::read(&path).unwrap(), original);
    app.send(b"w");
    app.expect(&["Saved"]);
    let saved = fs::read(&path).unwrap();
    assert_eq!(&saved[8..12], &2_u32.to_be_bytes());
    // The key is written protected, never as it was read.
    let secret = [7_u8; 32];
    assert!(!saved.windows(32).any(|window| window == secret));
    app.send(b"q");
    app.assert_restored();
}

/// SPEC: [Generating key pairs](../../docs/SPEC.md#generating-key-pairs),
/// [Saving](../../docs/SPEC.md#saving),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn generate_key_pair_save_and_quit_restores_terminal() {
    let directory = TempDir::new();
    let path = directory.join("store.jks");
    let original = empty_password_fixture();
    fs::write(&path, &original).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("store.jks")]);
    app.expect(&["root-cert", "Keystore: n New | g Generate | i Import"]);
    app.send(b"g");
    app.expect(&["Generate key pair", "< EC P-256 >", "Left/Right Change"]);
    // Three steps right of EC P-256 is Ed25519.
    app.send(b"\x1b[C\x1b[C\x1b[C");
    app.expect(&["< Ed25519 >"]);
    // Enter without a common name points at that field.
    app.send(b"\r");
    app.expect(&["A common name is required."]);
    // `q` is typed into the name, not a quit.
    app.send(b"q.smoke\r");
    app.expect(&["Alias for the generated key pair: q.smoke_"]);
    app.send(b"\r");
    app.expect(&[
        "Generated Ed25519 key pair 'q.smoke'.",
        "Private key",
        "Ed25519",
        "[modified]",
    ]);
    assert_eq!(fs::read(&path).unwrap(), original);
    app.send(b"w");
    app.expect(&["Saved"]);
    let saved = fs::read(&path).unwrap();
    assert_eq!(&saved[8..12], &2_u32.to_be_bytes());
    app.send(b"q");
    app.assert_restored();
}

/// SPEC: [Making certificate requests](../../docs/SPEC.md#making-certificate-requests),
/// [Generating key pairs](../../docs/SPEC.md#generating-key-pairs),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn make_certificate_request_and_quit_restores_terminal() {
    let directory = TempDir::new();
    let path = directory.join("store.jks");
    fs::write(&path, empty_password_fixture()).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("store.jks")]);
    app.expect(&["root-cert", "c Request"]);
    // A trusted certificate has no key to sign with.
    app.send(b"c");
    app.expect(&["Only a private key can sign a certificate request."]);
    // Three steps right of EC P-256 is Ed25519.
    app.send(b"g\x1b[C\x1b[C\x1b[C\x1b[Bq.smoke\r");
    app.expect(&["Alias for the generated key pair: q.smoke_"]);
    app.send(b"\r");
    app.expect(&["Generated Ed25519 key pair 'q.smoke'."]);
    app.send(b"c");
    app.expect(&["Certificate request for 'q.smoke'", "q.smoke_"]);
    app.send(b"\r");
    app.expect(&["Save certificate request as:", "A .der name saves DER"]);
    // `q` is typed into the name, not a quit.
    app.send(b"\x15q.csr\r");
    app.expect(&["Saved a certificate request for 'q.smoke' to"]);
    let request = fs::read_to_string(directory.join("q.csr")).unwrap();
    assert!(request.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
    // The request changed nothing; the generated key is still unsaved.
    app.send(b"q");
    app.expect(&["Quit without saving the changes?"]);
    app.send(b"y");
    app.assert_restored();
}

/// SPEC: [Importing a CA reply](../../docs/SPEC.md#importing-a-ca-reply),
/// [Saving](../../docs/SPEC.md#saving),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn import_ca_reply_save_and_quit_restores_terminal() {
    let directory = TempDir::new();
    let path = directory.join("store.jks");
    fs::write(&path, empty_password_fixture()).unwrap();
    fs::write(directory.join("pair.pem"), key_pair_pem()).unwrap();
    // The reply: the key's certificate issued by a CA, then the CA's own.
    let reply = certificate_pem(&ed25519_certificate("imported", "smoke ca", 7, 9))
        + &certificate_pem(&ed25519_certificate("smoke ca", "smoke ca", 9, 9));
    fs::write(directory.join("reply.pem"), reply).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("store.jks")]);
    app.expect(&["root-cert", "R CA reply"]);
    app.send(b"R");
    app.expect(&["Only a private key takes a CA reply"]);
    app.send(b"i");
    app.expect(&["Import certificate or key pair from file", "pair.pem"]);
    app.send(b"pair\r");
    app.expect(&["Alias for the imported key pair: imported_"]);
    app.send(b"\r");
    app.expect(&["Imported key pair as 'imported'."]);
    app.send(b"R");
    app.expect(&["CA reply for 'imported'", "reply.pem"]);
    app.send(b"reply\r");
    app.expect(&["Replaced the certificate chain of 'imported' with the 2 certificates"]);
    app.send(b"w");
    app.expect(&["Saved"]);
    let saved = fs::read(&path).unwrap();
    assert!(saved.windows(8).any(|window| window == b"smoke ca"));
    app.send(b"q");
    app.assert_restored();
}

/// SPEC: [Editing a certificate chain](../../docs/SPEC.md#editing-a-certificate-chain),
/// [Importing a CA reply](../../docs/SPEC.md#importing-a-ca-reply),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn edit_chain_save_and_ctrl_c_restores_terminal() {
    let directory = TempDir::new();
    let path = directory.join("store.jks");
    fs::write(&path, empty_password_fixture()).unwrap();
    fs::write(directory.join("pair.pem"), key_pair_pem()).unwrap();
    let ca = certificate_pem(&ed25519_certificate("smoke ca", "smoke ca", 9, 9));
    let reply = certificate_pem(&ed25519_certificate("imported", "smoke ca", 7, 9));
    fs::write(directory.join("ca.pem"), &ca).unwrap();
    fs::write(directory.join("reply.pem"), reply + &ca).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("store.jks")]);
    app.expect(&["root-cert", "C Chain"]);
    app.send(b"C");
    app.expect(&["Only a private key has a certificate chain to edit."]);
    app.send(b"ipair\r");
    app.expect(&["Alias for the imported key pair: imported_"]);
    app.send(b"\r");
    app.expect(&["Imported key pair as 'imported'."]);
    app.send(b"Rreply\r");
    app.expect(&["Replaced the certificate chain of 'imported' with the 2 certificates"]);
    app.send(b"C");
    app.expect(&["Chain of 'imported': 2 certificates", "x Remove last"]);
    // `q` does nothing here.
    app.send(b"q");
    assert_eq!(app.exited(), None);
    app.send(b"x");
    app.expect(&["Removed 'smoke ca' from the chain of 'imported'."]);
    app.send(b"C");
    app.expect(&["Chain of 'imported': 1 certificate"]);
    app.send(b"a");
    app.expect(&["Certificate to append to the chain of 'imported'", "ca.pem"]);
    app.send(b"ca\r");
    app.expect(&["Appended 'smoke ca' to the chain of 'imported'."]);
    app.send(b"w");
    app.expect(&["Saved"]);
    assert!(
        fs::read(&path)
            .unwrap()
            .windows(8)
            .any(|window| window == b"smoke ca")
    );
    app.send(b"\x03");
    app.assert_restored();
}

/// SPEC: [Exporting private keys](../../docs/SPEC.md#exporting-private-keys),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn export_private_key_and_quit_restores_terminal() {
    let directory = TempDir::new();
    let path = directory.join("keys.jks");
    let original = key_keystore("");
    fs::write(&path, &original).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("keys.jks")]);
    app.expect(&["server", "e Export"]);
    app.send(b"e");
    app.expect(&["Export key to:", ".key .p8 Key only"]);
    // `q` is typed into the name, not a quit.
    app.send(b"\x15q.key\r");
    app.expect(&["Password for the exported key: _", "Empty: unencrypted"]);
    app.send(b"secret\r");
    app.expect(&["Type the password again: _"]);
    app.send(b"secret\r");
    app.expect(&["Exported key 'server' to"]);
    let exported = fs::read_to_string(directory.join("q.key")).unwrap();
    assert!(exported.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
    assert_eq!(fs::read(&path).unwrap(), original);
    app.send(b"q");
    app.assert_restored();
}

/// SPEC: [Copying entries from another keystore](../../docs/SPEC.md#copying-entries-from-another-keystore),
/// [Saving](../../docs/SPEC.md#saving),
/// [Quitting and terminal restoration](../../docs/SPEC.md#quitting-and-terminal-restoration).
#[test]
fn copy_entries_save_and_quit_restores_terminal() {
    let directory = TempDir::new();
    let path = directory.join("store.jks");
    let original = empty_password_fixture();
    fs::write(&path, &original).unwrap();
    fs::write(directory.join("triage.jks"), triage_keystore()).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("store.jks")]);
    app.expect(&["root-cert", "i Import"]);
    app.send(b"i");
    app.expect(&["Import certificate or key pair from file", "triage.jks"]);
    app.send(b"triage\r");
    app.expect(&["Password of 'triage.jks': _"]);
    app.send(b"\r");
    app.expect(&[
        "Import entries from 'triage.jks'",
        "> [ ] alpha | Trusted certificate",
        "[ ] zeta-soon",
    ]);
    // `q` does not quit while the list is open.
    app.send(b"qj ");
    app.expect(&["> [x] beta-quit"]);
    app.send(b"a");
    app.expect(&["[x] alpha", "[x] zeta-soon"]);
    app.send(b"\r");
    app.expect(&["Imported 3 entries from 'triage.jks'.", "[modified]"]);
    assert_eq!(fs::read(&path).unwrap(), original);
    app.send(b"w");
    app.expect(&["Saved"]);
    assert_eq!(&fs::read(&path).unwrap()[8..12], &4_u32.to_be_bytes());
    app.send(b"q");
    app.assert_restored();
}
