//! Opening files from the file browser.

use std::fs;

use crate::fixtures::{TempDir, empty_password_fixture};
use crate::pty::PtyApp;

/// SPEC: [File selection](../../docs/SPEC.md#file-selection).
#[test]
fn picker_filters_by_typed_prefix() {
    let directory = TempDir::new();
    fs::write(directory.join("alpha.jks"), empty_password_fixture()).unwrap();
    fs::write(directory.join("quux.jks"), empty_password_fixture()).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[]);
    app.expect(&["No keystore selected"]);
    app.send(b"o");
    app.expect(&["> alpha.jks", "quux.jks"]);
    app.send(b"qu"); // `q` is typed into the filter, not a quit.
    app.expect(&["Filter: qu", "> quux.jks"]);
    assert_eq!(app.exited(), None);
    assert!(!app.screen().contains("alpha.jks"));
    app.send(b"\x1b"); // Clears the filter, keeping the selection.
    app.expect(&["alpha.jks", "> quux.jks", "../"]);
    assert!(!app.screen().contains("Filter:"));
    app.send(b"\x1b"); // Closes the browser.
    app.expect(&["No keystore selected"]);
    app.send(b"o");
    app.expect(&["> alpha.jks"]);
    // Only the path bar tells the two files apart. Widen the terminal so the
    // file name isn't clipped from a long temporary directory path, such as
    // under `cargo llvm-cov`'s target directory in CI.
    app.resize(250, 30);
    app.send(b"QU\r");
    app.expect(&["root-cert", "Path:", "quux.jks"]);
    app.send(b"\x03");
    app.assert_restored();
}
