//! Opening files from the file browser.

use std::ffi::OsStr;
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

/// SPEC: [File selection](../../docs/SPEC.md#file-selection).
#[test]
fn browser_navigation_and_cancelling_keep_the_open_store() {
    let directory = TempDir::new();
    fs::write(directory.join("entry.jks"), empty_password_fixture()).unwrap();
    fs::create_dir(directory.join("sub")).unwrap();
    fs::write(directory.join("sub/inner.jks"), empty_password_fixture()).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("entry.jks")]);
    app.expect(&["root-cert", "1 entries | Sort: alias"]);
    app.send(b"o"); // Starts in the open keystore's directory, folders first.
    app.expect(&["> sub/", "entry.jks"]);
    app.send(b"\r");
    app.expect(&["> inner.jks", "../"]);
    // The second Backspace has no filter to delete and stays in `sub`, so the
    // new filter still matches `inner.jks`.
    app.send(b"x\x7f\x7fin");
    app.expect(&["Filter: in", "> inner.jks"]);
    app.send(b"\x1b[D"); // Left opens the parent, which starts with no filter.
    app.expect(&["> sub/", "entry.jks", "../"]);
    app.send(b"\x1b"); // Closes the browser, keeping the open store.
    app.expect(&["root-cert", "1 entries | Sort: alias"]);
    // Widen the terminal so a long temporary directory doesn't clip the name.
    app.resize(250, 30);
    app.expect(&["Path:", "entry.jks'"]);
    app.send(b"q");
    app.assert_restored();
}
