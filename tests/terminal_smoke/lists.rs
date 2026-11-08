//! Selecting, filtering, and sorting in the entry list and the file browser.
//!
//! - A three-entry store, built at runtime from copies of the certificate:
//!   entry selection wrapping with the arrow keys, filtering (including `q` typed
//!   into the filter and `Esc` cancelling it), and sorting.
//! - The file browser's prefix filter: `q` is typed into it, matching ignores
//!   case, `Esc` clears it and then closes the browser, and `Enter` opens the
//!   only match.

use std::fs;

use crate::fixtures::{TempDir, empty_password_fixture, triage_keystore};
use crate::pty::PtyApp;

#[test]
fn entry_selection_wraps_with_arrow_keys() {
    let directory = TempDir::new();
    let path = directory.join("triage.jks");
    fs::write(&path, triage_keystore()).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[path.as_os_str()]);
    app.expect(&["3 entries | Sort: alias"]);
    app.send(b"\x1b[A\r"); // Up from alpha wraps to zeta-soon.
    app.expect(&["Certificate hierarchy", "zeta-soon"]);
    app.send(b"\x1b");
    app.expect(&["3 entries | Sort: alias"]);
    app.send(b"\x1b[B\r"); // Down wraps back to alpha.
    app.expect(&["Certificate hierarchy", "alpha"]);
    app.send(b"\x1b");
    app.expect(&["3 entries | Sort: alias"]);
    app.send(b"q");
    app.assert_restored();
}

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

fn assert_before(screen: &str, first: &str, second: &str) {
    let position = |text| {
        screen
            .find(text)
            .unwrap_or_else(|| panic!("{text} missing"))
    };
    assert!(
        position(first) < position(second),
        "{first} before {second}\n{screen}"
    );
}

fn triage(quit_while_typing: bool, exit_key: &[u8]) {
    let directory = TempDir::new();
    fs::write(directory.join("triage.jks"), triage_keystore()).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[]);
    app.open_from_picker("triage.jks");
    app.expect(&["alpha", "beta-quit", "zeta-soon", "3 entries | Sort: alias"]);
    app.send(b"/");
    app.expect(&["Type to filter", "Filter: _ | 3 of 3 entries"]);
    app.send(b"q"); // Typed into the filter, not a quit.
    app.expect(&["Filter: q_ | 1 of 3 entries", "beta-quit"]);
    assert_eq!(app.exited(), None);
    assert!(!app.screen().contains("alpha"));
    app.send(b"x");
    app.expect(&["Filter: qx_ | 0 of 3 entries", "No matching entries"]);
    app.send(b"\x1b"); // Cancels and clears the filter.
    app.expect(&["3 entries | Sort: alias", "alpha", "Up/Down j/k Scroll"]);
    assert!(!app.screen().contains("Filter:"));
    app.send(b"/zeta\r");
    app.expect(&["Filter: 'zeta' | 1 of 3 entries"]);
    assert!(!app.screen().contains("alpha"));
    app.send(b"\r"); // Details open for the filtered selection.
    app.expect(&["Certificate hierarchy", "zeta-soon"]);
    app.send(b"\x1b");
    app.expect(&["Filter: 'zeta' | 1 of 3 entries"]);
    app.send(b"/");
    app.expect(&["Filter: zeta_"]);
    app.send(b"\x1b");
    app.expect(&["3 entries | Sort: alias", "alpha"]);
    assert_before(&app.screen(), "alpha", "zeta-soon");
    app.send(b"s");
    app.expect(&["3 entries | Sort: expiry"]);
    assert_before(&app.screen(), "zeta-soon", "alpha");
    app.send(b"s");
    app.expect(&["3 entries | Sort: alias"]);
    app.send(b"/a\r");
    app.expect(&["Filter: 'a' | 3 of 3 entries"]);
    if quit_while_typing {
        app.send(b"/");
        app.expect(&["Filter: a_"]);
    }
    app.send(exit_key);
    app.assert_restored();
}

#[test]
fn filter_and_sort_then_quit_restores_terminal() {
    triage(false, b"q");
}

#[test]
fn filter_and_sort_then_escape_restores_terminal() {
    triage(false, b"\x1b");
}

#[test]
fn ctrl_c_while_filtering_restores_terminal() {
    triage(true, b"\x03");
}
