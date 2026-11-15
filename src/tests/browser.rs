use super::*;

#[test]
fn browser_shows_directories_then_supported_keystore_files() {
    let directory = TestDirectory::new();
    fs::create_dir(directory.path().join("z-directory")).unwrap();
    fs::write(directory.path().join("a-keystore.jks"), "").unwrap();
    fs::write(directory.path().join("b-keystore.JKS"), "").unwrap();
    fs::write(directory.path().join("c-keystore.p12"), "").unwrap();
    fs::write(directory.path().join("d-keystore.PFX"), "").unwrap();
    fs::write(directory.path().join("e-keystore.jceks"), "").unwrap();
    fs::write(directory.path().join("cacerts"), "").unwrap();
    fs::write(directory.path().join("jssecacerts"), "").unwrap();
    // On a case-insensitive file system, such as macOS by default, `CACERTS`
    // is the same file as `cacerts`.
    let case_sensitive = !directory.path().join("CACERTS").exists();
    if case_sensitive {
        fs::write(directory.path().join("CACERTS"), "").unwrap();
    }
    fs::write(directory.path().join("ignored.txt"), "").unwrap();
    fs::write(directory.path().join("ignored.jks.bak"), "").unwrap();
    fs::write(directory.path().join("cacerts.bak"), "").unwrap();

    let mut app = browsing(directory.path());
    let rendered = screen(&mut app, 100, 24);
    assert!(rendered.find("../").unwrap() < rendered.find("z-directory/").unwrap());
    assert!(rendered.find("z-directory/").unwrap() < rendered.find("a-keystore.jks").unwrap());
    assert!(rendered.find("a-keystore.jks").unwrap() < rendered.find("b-keystore.JKS").unwrap());
    assert!(rendered.find("b-keystore.JKS").unwrap() < rendered.find("c-keystore.p12").unwrap());
    assert!(rendered.find("c-keystore.p12").unwrap() < rendered.find("d-keystore.PFX").unwrap());
    assert!(rendered.find("d-keystore.PFX").unwrap() < rendered.find("e-keystore.jceks").unwrap());
    assert!(!rendered.contains("ignored"));
    for name in ["cacerts", "jssecacerts"] {
        assert!(rendered.contains(name));
    }
    assert_eq!(rendered.contains("CACERTS"), case_sensitive);
    assert!(!rendered.contains("cacerts.bak"));
}

#[test]
fn browser_opens_cacerts_and_prompts_for_its_encrypted_contents() {
    let directory = TestDirectory::new();
    let path = directory.path().join("cacerts");
    fs::write(
        &path,
        include_bytes!("../../tests/fixtures/encrypted-no-mac.p12"),
    )
    .unwrap();
    let mut app = browsing(directory.path());
    assert!(screen(&mut app, 100, 24).contains("cacerts"));
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    assert!(app.file_picker.is_none());
    assert!(app.password_prompt.is_some());
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    assert!(app.password_prompt.is_none());
    assert!(app.error.is_none());
    assert_eq!(app.keystore_path, Some(path));
    assert_eq!(app.entries.len(), 1);
    assert_eq!(app.entries[0].certificate, Some(fixture_summary()));
}

#[test]
fn browser_cycles_through_parent_directories_and_files_in_both_directions() {
    let directory = TestDirectory::new();
    fs::create_dir(directory.path().join("nested")).unwrap();
    fs::write(directory.path().join("store.jks"), empty_keystore()).unwrap();

    let mut app = browsing(directory.path());
    assert!(screen(&mut app, 100, 24).contains("> nested/"));
    for expected in ["../", "store.jks", "nested/"] {
        assert!(!press(&mut app, KeyCode::Up));
        assert!(screen(&mut app, 100, 24).contains(&format!("> {expected}")));
    }
    for expected in ["store.jks", "../", "nested/"] {
        assert!(!press(&mut app, KeyCode::Down));
        assert!(screen(&mut app, 100, 24).contains(&format!("> {expected}")));
    }
    assert!(app.keystore_path.is_none());
    assert!(app.file_picker.is_some());
}

#[test]
fn browser_filters_by_typed_prefix() {
    let directory = TestDirectory::new();
    let nested = directory.path().join("query");
    fs::create_dir(&nested).unwrap();
    fs::write(nested.join("inner.jks"), "").unwrap();
    fs::write(directory.path().join("alpha.jks"), "").unwrap();
    fs::write(directory.path().join("Quux.p12"), "").unwrap();
    let mut app = browsing(directory.path());

    // `q` is typed rather than quitting, and matching ignores case.
    assert!(!press(&mut app, KeyCode::Char('q')));
    let rendered = screen(&mut app, 100, 24);
    assert!(rendered.contains("Filter: q"), "{rendered}");
    assert!(rendered.contains("> query/"));
    assert!(rendered.contains("Quux.p12"));
    assert!(!rendered.contains("alpha.jks"));
    assert!(!rendered.contains("../"));

    press(&mut app, KeyCode::Char('z'));
    assert!(screen(&mut app, 100, 24).contains("No entries start with \"qz\"."));
    press(&mut app, KeyCode::Backspace);

    // Entering a directory starts it unfiltered.
    press(&mut app, KeyCode::Enter);
    let rendered = screen(&mut app, 100, 24);
    assert!(!rendered.contains("Filter:"), "{rendered}");
    assert!(rendered.contains("> inner.jks"));
    press(&mut app, KeyCode::Left);

    // Esc first clears the filter, then closes the browser.
    press(&mut app, KeyCode::Char('A'));
    assert!(screen(&mut app, 100, 24).contains("> alpha.jks"));
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.file_picker.is_some());
    assert!(screen(&mut app, 100, 24).contains("../"));
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.file_picker.is_none());
}

#[test]
fn browser_wrapping_scrolls_between_ends_of_a_long_list() {
    let directory = TestDirectory::new();
    for index in 0..40 {
        fs::write(directory.path().join(format!("store-{index:02}.jks")), "").unwrap();
    }
    let mut app = browsing(directory.path());
    assert!(screen(&mut app, 100, 20).contains("> store-00.jks"));
    press(&mut app, KeyCode::Home);
    assert!(screen(&mut app, 100, 20).contains("> ../"));
    press(&mut app, KeyCode::Up);
    assert!(screen(&mut app, 100, 20).contains("> store-39.jks"));
    press(&mut app, KeyCode::Down);
    assert!(screen(&mut app, 100, 20).contains("> ../"));
}

#[test]
fn browser_cycles_safely_with_only_the_parent_entry() {
    let directory = TestDirectory::new();
    let mut app = browsing(directory.path());
    for key in [KeyCode::Up, KeyCode::Down, KeyCode::Home, KeyCode::End] {
        assert!(!press(&mut app, key));
        assert!(screen(&mut app, 100, 24).contains("> ../"));
    }
}

#[test]
fn single_certificate_files_from_the_browser_open_in_details() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for (name, heading) in [
        ("trusted-cert.pem", "Certificate hierarchy"),
        ("trusted-cert.crt", "Certificate hierarchy"),
        ("keytool-request.csr", "Request details"),
    ] {
        let mut app = App::default();
        app.open_file(fixtures.join(name));
        assert!(app.error.is_none(), "{name}");
        assert_eq!(app.entries.len(), 1, "{name}");
        assert!(app.entry_details.is_some(), "{name}");
        assert!(screen(&mut app, 100, 30).contains(heading), "{name}");
        assert!(!press(&mut app, KeyCode::Esc));
        assert!(app.entry_details.is_none(), "{name}");
        assert!(screen(&mut app, 100, 30).contains("1 entries | Sort: alias"));
    }

    // Several certificates, or a single-entry keystore, open on the list.
    for (name, count) in [("bundle.pem", 2), ("passwordless.p12", 1)] {
        let mut app = App::default();
        app.open_file(fixtures.join(name));
        assert!(app.error.is_none(), "{name}");
        assert_eq!(app.entries.len(), count, "{name}");
        assert!(app.entry_details.is_none(), "{name}");
    }
}

#[test]
fn selecting_a_valid_empty_keystore_displays_its_absolute_path() {
    let directory = TestDirectory::new();
    let path = directory.path().join("my keystore-ü.JKS");
    let data = empty_keystore();
    fs::write(&path, &data).unwrap();
    let mut app = browsing(directory.path());

    press(&mut app, KeyCode::End);
    assert!(!press(&mut app, KeyCode::Enter));

    let expected = canonical_path::canonicalize(&path).unwrap();
    assert_eq!(app.keystore_path.as_deref(), Some(expected.as_path()));
    assert!(app.file_picker.is_none());
    let rendered = screen(&mut app, 200, 24);
    assert_eq!(
        rendered.lines().nth(20).unwrap().trim_end(),
        format!("Path: '{}'", expected.display())
    );
    // Only the path itself is blue, not the label or the quotes.
    let path_bar = buffer(&mut app, 200, 24);
    let path_end = 7 + expected.display().to_string().chars().count() as u16;
    for x in 0..=path_end {
        let color = if (7..path_end).contains(&x) {
            Color::Blue
        } else {
            Color::Reset
        };
        assert_eq!(path_bar[(x, 20)].fg, color, "column {x}");
    }
    let title = rendered.lines().next().unwrap();
    assert!(title.contains(" keystore-tui "));
    assert!(!title.contains(expected.to_str().unwrap()));
    assert!(!title.contains("entries"));
    assert!(screen(&mut app, 200, 24).contains("This keystore contains no entries."));
    assert!(app.password_prompt.is_none());
    assert_eq!(fs::read(&path).unwrap(), data);
}

#[test]
fn directories_can_be_entered_and_left_before_selecting() {
    let directory = TestDirectory::new();
    let nested = directory.path().join("nested");
    fs::create_dir(&nested).unwrap();
    let path = nested.join("nested-keystore.jks");
    fs::write(&path, empty_keystore()).unwrap();
    let mut app = browsing(directory.path());

    press(&mut app, KeyCode::Right);
    assert!(app.keystore_path.is_none());
    assert!(screen(&mut app, 200, 24).contains("nested-keystore.jks"));

    press(&mut app, KeyCode::Left);
    let parent = screen(&mut app, 200, 24);
    assert!(parent.contains("nested/"));
    assert!(!parent.contains("nested-keystore.jks"));

    press(&mut app, KeyCode::Enter);
    // Home selects ../, so Enter also navigates to the parent.
    press(&mut app, KeyCode::Home);
    press(&mut app, KeyCode::Enter);
    assert!(!screen(&mut app, 200, 24).contains("nested-keystore.jks"));

    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.keystore_path,
        Some(canonical_path::canonicalize(&path).unwrap())
    );
}

#[test]
fn a_missing_directory_does_not_close_the_browser() {
    let directory = TestDirectory::new();
    let nested = directory.path().join("removed-directory");
    fs::create_dir(&nested).unwrap();
    let mut app = browsing(directory.path());
    press(&mut app, KeyCode::End);
    fs::remove_dir(&nested).unwrap();

    press(&mut app, KeyCode::Enter);
    let rendered = screen(&mut app, 200, 24);
    assert!(rendered.contains("Could not open selection"));
    assert!(rendered.contains("removed-directory/"));
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.file_picker.is_none());
}

#[test]
fn empty_directories_and_small_terminals_are_handled() {
    let directory = TestDirectory::new();
    let mut app = browsing(directory.path());
    assert!(
        screen(&mut app, 100, 24)
            .contains("No keystore (.jks, .jceks, .p12, .pfx, cacerts, jssecacerts)")
    );
    press(&mut app, KeyCode::Up);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Home);
    press(&mut app, KeyCode::End);
    screen(&mut app, 12, 5);
    screen(&mut app, 1, 1);
    assert!(app.keystore_path.is_none());
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.file_picker.is_none());
    assert!(press(&mut app, KeyCode::Esc));
}
