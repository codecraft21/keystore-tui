use super::*;

#[test]
fn deleting_an_entry_asks_first_and_changes_the_file_only_on_save() {
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    assert!(screen(&mut app, 120, 24).contains("w Save | W Save as | p Password"));

    press(&mut app, KeyCode::Char('d'));
    assert!(screen(&mut app, 120, 24).contains("Delete entry 'root-cert'? Press y"));
    // Any key other than `y` cancels, without acting as a shortcut.
    assert!(!press(&mut app, KeyCode::Char('q')));
    assert_eq!(app.entries.len(), 2);
    assert!(!app.modified);

    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Delete);
    press(&mut app, KeyCode::Char('y'));
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("Deleted entry 'server-key'."));
    assert!(rendered.contains(" keystore-tui [modified] "));
    assert!(!rendered.contains("Private key"));
    // The selection stays on a row that still exists.
    assert_eq!(app.selected_entry(), Some(0));
    assert_eq!(aliases(&path), ["root-cert", "server-key"]);

    press(&mut app, KeyCode::Char('w'));
    let rendered = screen(&mut app, 200, 24);
    assert!(rendered.contains("Saved '"));
    assert!(!rendered.contains("[modified]"));
    assert_eq!(aliases(&path), ["root-cert"]);
    press(&mut app, KeyCode::Char('w'));
    assert!(screen(&mut app, 120, 24).contains("No changes to save."));
    // The last entry can be deleted too, leaving an empty keystore.
    press(&mut app, KeyCode::Char('d'));
    press(&mut app, KeyCode::Char('y'));
    assert_eq!(app.selected_entry(), None);
    press(&mut app, KeyCode::Char('w'));
    assert!(aliases(&path).is_empty());
    assert!(press(&mut app, KeyCode::Char('q')));
}

#[test]
fn deleting_a_filtered_entry_removes_that_entry() {
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    press(&mut app, KeyCode::Char('/'));
    type_password(&mut app, "server");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('d'));
    assert!(screen(&mut app, 120, 24).contains("Delete entry 'server-key'?"));
    press(&mut app, KeyCode::Char('y'));
    press(&mut app, KeyCode::Char('w'));
    assert_eq!(aliases(&path), ["root-cert"]);
}

#[test]
fn unsaved_changes_are_confirmed_before_quitting_or_opening_a_file() {
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    press(&mut app, KeyCode::Char('d'));
    press(&mut app, KeyCode::Char('y'));

    for key in [KeyCode::Char('q'), KeyCode::Esc] {
        assert!(!press(&mut app, key));
        assert!(screen(&mut app, 120, 24).contains("Quit without saving the changes?"));
        assert!(!press(&mut app, KeyCode::Char('n')));
        assert!(app.confirm.is_none());
    }
    // From the details, the question replaces the view until it is answered.
    press(&mut app, KeyCode::Enter);
    assert!(!press(&mut app, KeyCode::Char('q')));
    assert!(screen(&mut app, 120, 24).contains("Quit without saving the changes?"));
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.entry_details.is_some());
    press(&mut app, KeyCode::Esc);

    press(&mut app, KeyCode::Char('o'));
    assert!(screen(&mut app, 120, 24).contains("discards the unsaved changes"));
    assert!(app.file_picker.is_none());
    press(&mut app, KeyCode::Char('y'));
    assert!(app.file_picker.is_some());
    // Cancelling the browser keeps the changes.
    press(&mut app, KeyCode::Esc);
    assert!(app.modified);

    assert!(!press(&mut app, KeyCode::Char('q')));
    assert!(press(&mut app, KeyCode::Char('y')));
    assert_eq!(aliases(&path), ["root-cert", "server-key"]);

    // Ctrl+C quits at once.
    let (mut app, _) = editing(&directory);
    press(&mut app, KeyCode::Char('d'));
    press(&mut app, KeyCode::Char('y'));
    assert!(app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
}

#[test]
fn save_as_writes_a_new_file_and_switches_to_it() {
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    press(&mut app, KeyCode::Char('d'));
    press(&mut app, KeyCode::Char('y'));
    press(&mut app, KeyCode::Char('W'));
    let copy = directory.path().join("store-copy.jks");
    assert!(screen(&mut app, 200, 24).contains(&format!("Save keystore as: {} ", copy.display())));
    // Letters are typed into the name instead of quitting.
    assert!(!press(&mut app, KeyCode::Char('q')));
    press(&mut app, KeyCode::Backspace);
    // An existing file is never replaced.
    app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    type_password(&mut app, "store.jks");
    press(&mut app, KeyCode::Enter);
    assert!(red_text(&mut app).contains("already exists"));
    assert!(app.save_as.is_some());
    app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    type_password(&mut app, "store-copy.jks");
    press(&mut app, KeyCode::Enter);

    let copy = canonical_path::canonicalize(&copy).unwrap();
    assert!(app.save_as.is_none());
    assert!(!app.modified);
    assert_eq!(app.keystore_path.as_deref(), Some(copy.as_path()));
    assert_eq!(aliases(&copy), ["server-key"]);
    assert_eq!(aliases(&path), ["root-cert", "server-key"]);
    // Later saves go to the new file.
    press(&mut app, KeyCode::Char('d'));
    press(&mut app, KeyCode::Char('y'));
    press(&mut app, KeyCode::Char('w'));
    assert!(aliases(&copy).is_empty());
    assert_eq!(aliases(&path), ["root-cert", "server-key"]);
}

#[test]
fn certificate_files_cannot_be_changed() {
    let directory = TestDirectory::new();
    for (name, data) in [("bundle.pem", test_support::BUNDLE_PEM)] {
        let path = directory.path().join(name);
        fs::write(&path, data).unwrap();
        let mut app = App::default();
        app.open_file(path.clone());
        assert!(!app.entries.is_empty(), "{name}");
        assert!(!screen(&mut app, 120, 24).contains("d Delete |"), "{name}");
        for key in ['d', 'w', 'W'] {
            press(&mut app, KeyCode::Char(key));
            assert!(app.confirm.is_none() && app.save_as.is_none(), "{name}");
            assert!(red_text(&mut app).contains(NOT_EDITABLE), "{name} {key}");
        }
        assert_eq!(fs::read(&path).unwrap(), data, "{name}");
    }
    // Without a loaded file the keys do nothing.
    let mut app = App::default();
    for key in ['d', 'w', 'W'] {
        press(&mut app, KeyCode::Char(key));
        assert!(app.message.is_none());
    }
}

#[test]
fn renaming_an_entry_keeps_alias_order_and_is_written_on_save() {
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains(
        "Keystore: n New | g Generate | G Secret key | i Import | w Save | W Save as | p Password"
    ));
    assert!(rendered.contains(
        "Entry: e Export | c Request | R CA reply | C Chain | S Sign | r Rename | d Delete | P Key password"
    ));
    press(&mut app, KeyCode::Char('r'));
    assert!(screen(&mut app, 120, 24).contains("New alias for 'root-cert': root-cert_"));
    // Letters are typed into the alias instead of quitting.
    assert!(!press(&mut app, KeyCode::Char('q')));
    assert!(screen(&mut app, 120, 24).contains("root-certq_"));
    press(&mut app, KeyCode::Backspace);
    // Confirming the unchanged alias changes nothing.
    press(&mut app, KeyCode::Enter);
    assert!(app.alias_prompt.is_none() && !app.modified);

    press(&mut app, KeyCode::Char('r'));
    for (alias, error) in [
        ("", "Type an alias"),
        ("SERVER-key", "An entry named 'server-key' already exists."),
    ] {
        type_alias(&mut app, alias);
        assert!(red_text(&mut app).contains(error), "{alias}");
        assert!(app.alias_prompt.is_some() && !app.modified);
    }
    // Aliases are stored in lower case, as Java does.
    type_alias(&mut app, "Zulu-Ü");
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("Renamed entry 'root-cert' to 'zulu-ü'."));
    assert!(rendered.contains("[modified]"));
    assert_eq!(app.entries[1].alias, "zulu-ü");
    // The renamed entry stays selected in its new row.
    assert_eq!(app.selected_entry(), Some(1));
    assert_eq!(aliases(&path), ["root-cert", "server-key"]);
    press(&mut app, KeyCode::Char('w'));
    assert!(screen(&mut app, 200, 24).contains("Saved '"));
    assert_eq!(aliases(&path), ["server-key", "zulu-ü"]);

    // Esc cancels.
    press(&mut app, KeyCode::Char('r'));
    press(&mut app, KeyCode::Esc);
    assert!(app.alias_prompt.is_none() && !app.modified);
}

#[test]
fn importing_a_certificate_adds_a_trusted_entry() {
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    fs::write(
        directory.path().join("ca.pem"),
        test_support::TRUSTED_CERT_PEM,
    )
    .unwrap();
    fs::write(
        directory.path().join("bundle.pem"),
        test_support::BUNDLE_PEM,
    )
    .unwrap();
    fs::write(
        directory.path().join("request.csr"),
        test_support::KEYTOOL_REQUEST,
    )
    .unwrap();

    fs::write(directory.path().join("junk.der"), b"\x30\x03\x02\x01\x00").unwrap();
    // Files without exactly one certificate are refused.
    for (name, error) in [
        ("bundle", "holds 2 certificates"),
        ("request", "holds no certificate"),
        ("junk", "is not a certificate file"),
    ] {
        press(&mut app, KeyCode::Char('i'));
        assert!(screen(&mut app, 120, 24).contains(" Import certificate or key pair from file "));
        type_password(&mut app, name);
        press(&mut app, KeyCode::Enter);
        assert!(red_text(&mut app).contains(error), "{name}");
        assert!(
            app.file_picker.is_none() && app.alias_prompt.is_none(),
            "{name}"
        );
        assert!(!app.modified && !app.importing, "{name}");
    }
    // Cancelling the browser leaves the import.
    press(&mut app, KeyCode::Char('i'));
    press(&mut app, KeyCode::Esc);
    assert!(!app.importing);
    assert_eq!(app.keystore_path.as_deref(), Some(path.as_path()));

    press(&mut app, KeyCode::Char('i'));
    type_password(&mut app, "ca");
    press(&mut app, KeyCode::Enter);
    // The subject's common name, in lower case, is suggested.
    assert!(
        screen(&mut app, 120, 24)
            .contains("Alias for the imported certificate: jks tui test fixture_")
    );
    type_alias(&mut app, "root-cert");
    assert!(red_text(&mut app).contains("already exists"));
    type_alias(&mut app, "New-CA");
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("Imported certificate as 'new-ca'."));
    assert!(rendered.contains("[modified]"));
    assert_eq!(app.selected_entry(), Some(0));
    assert_eq!(
        app.entries[0],
        KeystoreEntry {
            alias: "new-ca".into(),
            certificate: Some(fixture_summary()),
            content: Content::Certificates {
                kind: Kind::TrustedCertificate,
                certificates: vec![test_support::fixture_certificate_der().to_vec()],
            },
            chain_warning: None,
        }
    );
    // The imported entry opens in the details like any other.
    press(&mut app, KeyCode::Enter);
    assert!(app.entry_details.is_some());
    press(&mut app, KeyCode::Esc);

    press(&mut app, KeyCode::Char('w'));
    assert_eq!(aliases(&path), ["new-ca", "root-cert", "server-key"]);
    let saved = keystore::load_entries(&fs::read(&path).unwrap(), "changeit").unwrap();
    assert_eq!(saved, app.entries);
}

#[test]
fn rename_and_import_need_an_editable_keystore() {
    let directory = TestDirectory::new();
    let path = directory.path().join("bundle.pem");
    fs::write(&path, test_support::BUNDLE_PEM).unwrap();
    let mut app = App::default();
    app.open_file(path);
    for key in ['r', 'i', 'g', 'c', 'R', 'C', 'S', 'G'] {
        press(&mut app, KeyCode::Char(key));
        assert!(app.alias_prompt.is_none() && app.file_picker.is_none());
        assert!(app.secret_choice.is_none());
        assert!(app.generating.is_none() && app.requesting.is_none());
        assert!(app.reply.is_none() && app.chain_menu.is_none());
        assert!(app.sign_menu.is_none());
        assert!(red_text(&mut app).contains(NOT_EDITABLE), "{key}");
    }
    let mut app = App::default();
    for key in ['r', 'i', 'g', 'c', 'R', 'C', 'S', 'G'] {
        press(&mut app, KeyCode::Char(key));
        assert!(app.message.is_none() && app.file_picker.is_none());
        assert!(app.secret_choice.is_none());
        assert!(app.generating.is_none() && app.requesting.is_none());
        assert!(app.sign_menu.is_none());
    }
}

#[test]
fn alias_prompt_scrolls_long_and_wide_unicode_aliases() {
    let directory = TestDirectory::new();
    let (mut app, _) = editing(&directory);
    press(&mut app, KeyCode::Char('r'));
    app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    type_password(&mut app, &format!("{}tail", "a".repeat(80)));
    let rendered = screen(&mut app, 80, 24);
    assert!(rendered.contains("aaatail_"), "{rendered}");

    app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    type_password(&mut app, &format!("{}end", "日".repeat(40)));
    let rendered = screen(&mut app, 80, 24);
    // Each 2-column glyph occupies two buffer cells ("日" + " ").
    assert!(rendered.contains("日 end_"), "{rendered}");
}
