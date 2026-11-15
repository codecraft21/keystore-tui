use super::*;

#[test]
fn creating_a_keystore_writes_an_empty_file_and_opens_it() {
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    fs::write(directory.path().join("keystore.jks"), b"existing").unwrap();
    press(&mut app, KeyCode::Char('n'));
    let suggested = directory.path().join("keystore-2.jks");
    assert!(screen(&mut app, 200, 24).contains(&format!(
        "New keystore file (.jks, .jceks, or .p12): {} ",
        suggested.display()
    )));
    type_alias(&mut app, "store.jks");
    assert!(red_text(&mut app).contains("already exists"));
    assert!(app.save_as.is_some() && app.new_password.is_none());
    type_alias(&mut app, "new.JCEKS");
    assert!(screen(&mut app, 120, 24).contains("Password for the new keystore: _"));
    let created = directory.path().join("new.JCEKS");
    // Nothing is created before the password is confirmed.
    assert!(!created.exists());
    type_new_password(&mut app, "secret", "secret");

    let created = canonical_path::canonicalize(&created).unwrap();
    let rendered = screen(&mut app, 200, 24);
    assert!(rendered.contains("Created the JCEKS keystore"));
    assert!(rendered.contains("This keystore contains no entries."));
    assert_eq!(app.keystore_path.as_deref(), Some(created.as_path()));
    assert!(!app.modified && app.document.is_some());
    let data = fs::read(&created).unwrap();
    assert!(keystore::is_jceks(&data));
    assert!(keystore::load_entries(&data, "secret").unwrap().is_empty());
    assert_eq!(aliases(&path), ["root-cert", "server-key"]);

    // The new keystore can be filled and saved with its password.
    fs::write(
        directory.path().join("ca.pem"),
        test_support::TRUSTED_CERT_PEM,
    )
    .unwrap();
    press(&mut app, KeyCode::Char('i'));
    type_password(&mut app, "ca");
    press(&mut app, KeyCode::Enter);
    type_alias(&mut app, "ca");
    press(&mut app, KeyCode::Char('w'));
    let data = fs::read(&created).unwrap();
    assert_eq!(
        keystore::load_entries(&data, "secret").unwrap(),
        app.entries
    );
    assert_eq!(app.entries.len(), 1);
}

#[test]
fn a_keystore_can_be_created_before_any_file_is_open() {
    let directory = TestDirectory::in_working_directory();
    let mut app = App::default();
    assert!(
        screen(&mut app, 120, 24).contains("Press n to create a JKS, JCEKS, or PKCS12 keystore.")
    );
    press(&mut app, KeyCode::Char('n'));
    assert!(app.save_as.as_ref().is_some_and(|prompt| prompt.creating));
    press(&mut app, KeyCode::Esc);
    assert!(app.save_as.is_none() && app.keystore_path.is_none());

    press(&mut app, KeyCode::Char('n'));
    let path = directory.path().join("first.jks");
    type_alias(&mut app, &path.to_string_lossy());
    // Keys that are not text are ignored.
    press(&mut app, KeyCode::Tab);
    // An empty password is allowed, as for the stores the app opens.
    type_new_password(&mut app, "", "");
    let data = fs::read(&path).unwrap();
    assert!(!keystore::is_jceks(&data));
    assert_eq!(data, empty_keystore());
    assert!(app.document.is_some());

    // A file that cannot be created is reported, and the loaded file stays.
    press(&mut app, KeyCode::Char('n'));
    let missing = directory.path().join("missing").join("new.jks");
    type_alias(&mut app, &missing.to_string_lossy());
    type_new_password(&mut app, "secret", "secret");
    assert!(red_text(&mut app).contains("Cannot create"));
    assert!(app.new_password.is_none());
    assert_eq!(
        app.keystore_path.as_deref().map(fs::read).unwrap().unwrap(),
        data
    );
}

#[test]
fn creating_a_keystore_asks_before_discarding_changes() {
    let directory = TestDirectory::new();
    let (mut app, _) = editing(&directory);
    press(&mut app, KeyCode::Char('d'));
    press(&mut app, KeyCode::Char('y'));
    press(&mut app, KeyCode::Char('n'));
    assert!(
        screen(&mut app, 120, 24).contains("Creating a keystore discards the unsaved changes.")
    );
    press(&mut app, KeyCode::Char('x'));
    assert!(app.save_as.is_none());
    press(&mut app, KeyCode::Char('n'));
    press(&mut app, KeyCode::Char('y'));
    assert!(app.save_as.is_some());
    // The changes are kept until the keystore is created.
    press(&mut app, KeyCode::Esc);
    assert!(app.modified);

    // A passwordless PKCS12 truststore has no password to change.
    let path = directory.path().join("store.p12");
    let data = include_bytes!("../../tests/fixtures/passwordless.p12");
    fs::write(&path, data).unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    press(&mut app, KeyCode::Char('p'));
    type_new_password(&mut app, "secret", "secret");
    assert!(red_text(&mut app).contains("not protected by a password"));
    assert!(!app.modified);
    assert_eq!(fs::read(&path).unwrap(), data);
}

#[test]
fn pkcs12_keystores_are_edited_and_saved_like_the_others() {
    let directory = TestDirectory::new();
    let path = directory.path().join("store.p12");
    let original = include_bytes!("../../tests/fixtures/trusted-cert.p12");
    fs::write(&path, original).unwrap();
    let ca = test_support::metadata_certificate("New CA", "New CA", &[1], &[]);
    fs::write(directory.path().join("ca.der"), &ca).unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    assert!(
        screen(&mut app, 120, 24)
            .contains("Entry: e Export | c Request | R CA reply | C Chain | S Sign | r Rename")
    );

    press(&mut app, KeyCode::Char('r'));
    type_alias(&mut app, "Renamed");
    assert!(screen(&mut app, 120, 24).contains("Renamed entry 'root-cert' to 'renamed'."));
    press(&mut app, KeyCode::Char('i'));
    type_password(&mut app, "ca");
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 24).contains("Alias for the imported certificate: new ca_"));
    type_alias(&mut app, "renamed");
    assert!(red_text(&mut app).contains("already exists"));
    type_alias(&mut app, "added");
    assert_eq!(app.selected_entry(), Some(0));
    assert_eq!(app.entries[0].kind(), "Trusted certificate");
    press(&mut app, KeyCode::Char('p'));
    type_new_password(&mut app, "new-secret", "new-secret");
    assert!(screen(&mut app, 120, 24).contains("Password changed"));
    // Nothing reached the file yet.
    assert_eq!(fs::read(&path).unwrap(), original);

    press(&mut app, KeyCode::Char('w'));
    assert!(screen(&mut app, 200, 24).contains("Saved '"));
    assert!(!app.modified);
    let saved = pkcs12_entries(&path, "new-secret");
    assert_eq!(saved, app.entries);
    assert_eq!(saved.len(), 2);
    assert!(matches!(
        pkcs12::parse(&fs::read(&path).unwrap())
            .unwrap()
            .verify("changeit"),
        Err(pkcs12::VerifyError::Password)
    ));

    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Char('d'));
    assert!(screen(&mut app, 120, 24).contains("Delete entry 'renamed'?"));
    press(&mut app, KeyCode::Char('y'));
    press(&mut app, KeyCode::Char('W'));
    type_alias(&mut app, "copy.p12");
    let copy = directory.path().join("copy.p12");
    assert_eq!(pkcs12_entries(&copy, "new-secret"), app.entries);
    assert_eq!(app.entries.len(), 1);
    assert_eq!(pkcs12_entries(&path, "new-secret").len(), 2);

    // The saved store opens again in the app with the new password.
    let mut reopened = App::default();
    reopened.open_file(copy);
    type_password(&mut reopened, "new-secret");
    press(&mut reopened, KeyCode::Enter);
    assert_eq!(reopened.entries, app.entries);
}

#[test]
fn a_pkcs12_keystore_is_created_from_a_p12_or_pfx_name() {
    let directory = TestDirectory::in_working_directory();
    let mut app = App::default();
    press(&mut app, KeyCode::Char('n'));
    let path = directory.path().join("new.PFX");
    type_alias(&mut app, &path.to_string_lossy());
    // PKCS12 needs a password; nothing is created without one.
    type_new_password(&mut app, "", "");
    assert!(red_text(&mut app).contains("needs a password that is not empty"));
    assert!(!path.exists() && app.keystore_path.is_none());

    press(&mut app, KeyCode::Char('n'));
    type_alias(&mut app, &path.to_string_lossy());
    type_new_password(&mut app, "secret", "secret");
    assert!(screen(&mut app, 200, 24).contains("Created the PKCS12 keystore"));
    assert!(pkcs12_entries(&path, "secret").is_empty());
    assert!(app.document.is_some() && !app.modified);
}

#[test]
fn an_incompletely_read_pkcs12_keystore_cannot_be_changed() {
    let directory = TestDirectory::new();
    let path = directory.path().join("partial.p12");
    let data = include_bytes!("../../tests/fixtures/invalid-ciphertext-no-mac.p12");
    fs::write(&path, data).unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    assert_eq!(app.warning, Some(INCOMPLETE_WARNING));
    for key in ['i', 'p', 'w', 'W'] {
        press(&mut app, KeyCode::Char(key));
        assert!(
            red_text(&mut app).contains(INCOMPLETE_NOT_EDITABLE),
            "{key}"
        );
    }
    assert_eq!(fs::read(&path).unwrap(), data);
}
