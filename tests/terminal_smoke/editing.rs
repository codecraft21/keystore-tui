//! Deleting entries and saving the keystore.

use std::ffi::OsStr;
use std::fs;

use crate::fixtures::{TempDir, empty_password_fixture};
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
    app.expect(&["root-cert", "d Delete entry | w Save | W Save as"]);
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
    app.expect(&["Saved '"]);
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
    app.expect(&["Saved '"]);
    assert_eq!(fs::read(&path).unwrap().len(), 32);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    app.send(b"\x03");
    app.assert_restored();
}
