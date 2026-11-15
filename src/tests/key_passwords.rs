use super::*;

#[test]
fn a_key_password_is_changed_after_unlocking_the_key() {
    let directory = TestDirectory::new();
    for name in ["store.jks", "store.jceks"] {
        let (mut app, path, key) = keystore_with_keys(&directory, name);
        let original = fs::read(&path).unwrap();
        assert!(
            screen(&mut app, 120, 24).contains("d Delete | P Key password"),
            "{name}"
        );

        // A certificate has no password of its own.
        press(&mut app, KeyCode::Char('P'));
        assert!(
            red_text(&mut app).contains("Only private and secret keys"),
            "{name}"
        );
        assert!(app.new_password.is_none(), "{name}");

        // `own` needs its current password first, typed once and masked.
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Char('P'));
        assert!(
            screen(&mut app, 120, 24).contains("Current password of key 'own': _"),
            "{name}"
        );
        type_password(&mut app, "wrong");
        assert!(screen(&mut app, 120, 24).contains("Current password of key 'own': *****_"));
        press(&mut app, KeyCode::Enter);
        assert!(
            red_text(&mut app).contains("Incorrect key password."),
            "{name}"
        );
        assert!(
            screen(&mut app, 120, 24).contains("Current password of key 'own': _"),
            "{name}"
        );
        type_password(&mut app, "keypass");
        press(&mut app, KeyCode::Enter);
        assert!(
            screen(&mut app, 120, 24).contains("New password for key 'own': _"),
            "{name}"
        );
        type_new_password(&mut app, "new-one", "new-two");
        assert!(
            red_text(&mut app).contains("The passwords do not match"),
            "{name}"
        );
        assert!(!app.modified, "{name}");
        type_new_password(&mut app, "new-own", "new-own");
        let rendered = screen(&mut app, 160, 24);
        assert!(rendered.contains("Password of key 'own' changed"), "{name}");
        assert!(rendered.contains("[modified]"), "{name}");

        // `shared` is unlocked by the keystore's password.
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Char('P'));
        assert!(
            screen(&mut app, 120, 24).contains("New password for key 'shared': _"),
            "{name}"
        );
        // Esc cancels.
        press(&mut app, KeyCode::Esc);
        press(&mut app, KeyCode::Char('P'));
        type_new_password(&mut app, "new-shared", "new-shared");
        assert_eq!(fs::read(&path).unwrap(), original, "{name}");

        press(&mut app, KeyCode::Char('w'));
        assert!(!app.modified, "{name}");
        // The same keys come back with the new passwords only, and the
        // keystore keeps its own password and entries.
        assert_eq!(saved_key(&path, 1, "new-own"), Ok(key.clone()), "{name}");
        assert_eq!(saved_key(&path, 2, "new-shared"), Ok(key.clone()), "{name}");
        for (index, old) in [(1, "keypass"), (2, "changeit")] {
            assert_eq!(
                saved_key(&path, index, old),
                Err(key_protection::Error::Password)
            );
        }
        assert_eq!(
            keystore::load_entries(&fs::read(&path).unwrap(), "changeit").unwrap(),
            app.entries,
            "{name}"
        );

        // Now `own` asks for the new current password, not the old one.
        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Char('P'));
        type_password(&mut app, "keypass");
        press(&mut app, KeyCode::Enter);
        assert!(
            red_text(&mut app).contains("Incorrect key password."),
            "{name}"
        );
        type_password(&mut app, "new-own");
        press(&mut app, KeyCode::Enter);
        assert!(
            screen(&mut app, 120, 24).contains("New password for key 'own': _"),
            "{name}"
        );
    }
}

#[test]
fn key_passwords_follow_the_rules_of_the_keystore_format() {
    let directory = TestDirectory::new();
    // JCEKS protects keys with printable ASCII passwords only.
    let (mut app, _, _) = keystore_with_keys(&directory, "store.jceks");
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Char('P'));
    type_new_password(&mut app, "pässword", "pässword");
    assert!(red_text(&mut app).contains("printable ASCII"));
    assert!(!app.modified);

    // PKCS12 keys share the keystore's password.
    let path = directory.path().join("store.p12");
    fs::write(
        &path,
        include_bytes!("../../tests/fixtures/trusted-cert.p12"),
    )
    .unwrap();
    let mut app = App::default();
    app.open_file(path);
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('P'));
    assert!(red_text(&mut app).contains("share the keystore's password"));
    assert!(app.new_password.is_none());

    // A certificate file cannot be changed, and no file means no action.
    let path = directory.path().join("bundle.pem");
    fs::write(&path, test_support::BUNDLE_PEM).unwrap();
    let mut app = App::default();
    app.open_file(path);
    press(&mut app, KeyCode::Char('P'));
    assert!(red_text(&mut app).contains(NOT_EDITABLE));
    let mut app = App::default();
    press(&mut app, KeyCode::Char('P'));
    assert!(app.message.is_none() && app.new_password.is_none());
}

#[test]
fn a_key_with_unsupported_protection_is_reported() {
    let directory = TestDirectory::new();
    let path = directory.path().join("store.jks");
    // The synthetic key of the mixed keystore is not a protected key.
    fs::write(&path, mixed_keystore()).unwrap();
    let mut app = App::default();
    app.open_file(path);
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Char('P'));
    assert!(red_text(&mut app).contains("protection is not supported"));
    assert!(app.new_password.is_none());
}

#[test]
fn save_as_with_another_format_name_converts_the_keystore() {
    let directory = TestDirectory::new();
    let (mut app, path, key) = keystore_with_keys(&directory, "store.jks");
    let original = fs::read(&path).unwrap();
    press(&mut app, KeyCode::Char('W'));
    assert!(screen(&mut app, 200, 24).contains("A .jks, .jceks, or .p12 name converts"));
    // A key with a password of its own cannot follow the keystore.
    type_alias(&mut app, "store.p12");
    assert!(red_text(&mut app).contains("the key 'own' has a password of its own"));
    assert!(app.save_as.is_some());
    assert!(!directory.path().join("store.p12").exists());
    press(&mut app, KeyCode::Esc);

    // Once it shares the keystore's password, the keystore converts.
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Char('P'));
    type_password(&mut app, "keypass");
    press(&mut app, KeyCode::Enter);
    type_new_password(&mut app, "changeit", "changeit");
    let listed = app.entries.len();
    press(&mut app, KeyCode::Char('W'));
    type_alias(&mut app, "store.p12");
    let converted = canonical_path::canonicalize(&directory.path().join("store.p12")).unwrap();
    let rendered = screen(&mut app, 200, 24);
    assert!(rendered.contains("' as PKCS12."), "{:?}", app.message);
    assert!(!rendered.contains("[modified]"));
    assert_eq!(app.keystore_path.as_deref(), Some(converted.as_path()));
    assert_eq!(app.entries, pkcs12_entries(&converted, "changeit"));
    assert_eq!(app.entries.len(), listed);
    let kinds: Vec<_> = app
        .entries
        .iter()
        .map(|entry| (entry.alias.as_str(), entry.kind()))
        .collect();
    assert_eq!(
        kinds,
        [
            ("cert", "Trusted certificate"),
            ("own", "Private key"),
            ("shared", "Private key")
        ]
    );
    // The source file is untouched; the unsaved key password went along.
    assert_eq!(fs::read(&path).unwrap(), original);

    // And back, to JCEKS: the keys are the same, under the same password.
    press(&mut app, KeyCode::Char('W'));
    type_alias(&mut app, "back.JCEKS");
    assert!(
        screen(&mut app, 200, 24).contains("' as JCEKS."),
        "{:?}",
        app.message
    );
    let back = directory.path().join("back.JCEKS");
    assert!(keystore::is_jceks(&fs::read(&back).unwrap()));
    for index in [1, 2] {
        assert_eq!(saved_key(&back, index, "changeit"), Ok(key.clone()));
    }
    assert_eq!(app.entries.len(), listed);
    // A name without a known extension keeps the format.
    press(&mut app, KeyCode::Char('W'));
    type_alias(&mut app, "copy");
    assert!(keystore::is_jceks(
        &fs::read(directory.path().join("copy")).unwrap()
    ));
    // And on to JKS.
    press(&mut app, KeyCode::Char('W'));
    type_alias(&mut app, "last.jks");
    assert!(screen(&mut app, 200, 24).contains("' as JKS."));
    assert_eq!(
        saved_key(&directory.path().join("last.jks"), 1, "changeit"),
        Ok(key)
    );
}

#[test]
fn keystores_that_cannot_be_converted_are_left_alone() {
    use crate::keystore::{SECRET_KEY_TAG, VERSION_02};
    let directory = TestDirectory::new();
    let convert = |name: &str, data: Vec<u8>, password: &str, target: &str| {
        let path = directory.path().join(name);
        fs::write(&path, data).unwrap();
        let mut app = App::default();
        app.open_file(path.clone());
        if app.password_prompt.is_some() {
            type_password(&mut app, password);
            press(&mut app, KeyCode::Enter);
        }
        assert!(app.document.is_some(), "{name}");
        press(&mut app, KeyCode::Char('W'));
        type_alias(&mut app, target);
        assert!(!directory.path().join(target).exists(), "{target}");
        assert_eq!(app.keystore_path.as_deref(), Some(path.as_path()), "{name}");
        red_text(&mut app)
    };
    // PKCS12 needs a password.
    let error = convert("empty.jks", empty_keystore(), "", "empty.p12");
    assert!(
        error.contains("needs a password that is not empty"),
        "{error}"
    );
    // JCEKS secret keys are sealed Java objects.
    let mut builder = test_support::Builder::jceks(VERSION_02, 1);
    builder.entry(SECRET_KEY_TAG, b"aes", VERSION_02, 0);
    let error = convert(
        "secret.jceks",
        builder.finish("changeit"),
        "changeit",
        "secret.jks",
    );
    assert!(
        error.contains(
            "the secret key 'aes' stops it, because a JKS keystore cannot hold secret keys"
        ),
        "{error}"
    );
    // A key that is not protected as Java protects keys.
    let error = convert("mixed.jks", mixed_keystore(), "changeit", "mixed.p12");
    assert!(
        error.contains("the key 'server-key' uses protection that is not supported"),
        "{error}"
    );
    // A chain that is not linked by issuer names cannot be kept in PKCS12,
    // which rebuilds chains from them.
    let key = test_support::synthetic_pkcs8(b"synthetic, not a private key");
    let protected =
        key_protection::protect(&key, "changeit", false, &mut test_support::TestRng(0)).unwrap();
    let mut builder = test_support::Builder::new(VERSION_02, 1);
    builder.entry_header(keystore::PRIVATE_KEY_TAG, b"key");
    builder.payload(&protected);
    builder.u32_field(2);
    for subject in ["leaf", "unrelated"] {
        builder.raw_string(b"X.509");
        builder.payload(&test_support::metadata_certificate(
            subject,
            subject,
            &[1],
            &[],
        ));
    }
    let error = convert(
        "unlinked.jks",
        builder.finish("changeit"),
        "changeit",
        "unlinked.p12",
    );
    assert!(
        error.contains("would not read back with the same entries"),
        "{error}"
    );
    // The same keystore converts to JCEKS, which stores chains as they are.
    let path = directory.path().join("unlinked.jks");
    let mut app = App::default();
    app.open_file(path);
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('W'));
    type_alias(&mut app, "unlinked.jceks");
    assert!(
        screen(&mut app, 200, 24).contains("' as JCEKS."),
        "{:?}",
        app.message
    );
    assert_eq!(app.entries[0].certificates().len(), 2);
}
