use super::*;

#[test]
fn importing_a_key_pair_adds_a_private_key_entry() {
    use crate::test_support::{TestRng, ed25519_certificate, ed25519_pkcs8};
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    let write = |name: &str, data: &[u8]| fs::write(directory.path().join(name), data).unwrap();
    let ca = ed25519_certificate("ca", "ca", 9, 9);
    let leaf = ed25519_certificate("Leaf", "ca", 7, 9);
    let key = ed25519_pkcs8(7);
    write(
        "pair.pem",
        key_pem("PRIVATE KEY", &key, &[&ca, &leaf]).as_bytes(),
    );

    // A PEM file with the key and its certificates: only the alias is asked.
    import(&mut app, "pair");
    assert!(screen(&mut app, 120, 24).contains("Alias for the imported key pair: leaf_"));
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 24).contains("Imported key pair as 'leaf'."));
    assert!(app.modified);
    let imported = &app.entries[app.selected_entry().unwrap()];
    assert_eq!(
        (imported.alias.as_str(), imported.kind()),
        ("leaf", "Private key")
    );
    assert_eq!(imported.certificates(), [leaf.clone(), ca.clone()]);
    // The key is protected with the keystore's password when saved.
    press(&mut app, KeyCode::Char('w'));
    assert!(!app.modified, "{:?}", app.message);
    assert_eq!(aliases(&path), ["leaf", "root-cert", "server-key"]);
    assert_eq!(saved_key(&path, 0, "changeit"), Ok(key.clone()));
    assert_eq!(
        app.entries,
        keystore::load_entries(&fs::read(&path).unwrap(), "changeit").unwrap()
    );

    // A key file on its own: its certificate file is asked for next.
    write("only.key", &ed25519_pkcs8(5));
    write("five.crt", &ed25519_certificate("five", "five", 5, 5));
    write("other.crt", &ca);
    import(&mut app, "only");
    assert!(screen(&mut app, 120, 24).contains(" Certificate file of the imported key "));
    type_password(&mut app, "other");
    press(&mut app, KeyCode::Enter);
    assert!(
        red_text(&mut app)
            .contains("Not imported: no certificate in 'other.crt' matches the private key.")
    );
    assert!(app.key_import.is_none() && app.alias_prompt.is_none());
    // Leaving the browser leaves the import.
    import(&mut app, "only");
    press(&mut app, KeyCode::Esc);
    assert!(app.key_import.is_none() && !app.importing);
    import(&mut app, "only");
    type_password(&mut app, "five");
    press(&mut app, KeyCode::Enter);
    assert!(app.key_import.is_none() && !app.importing);
    // The alias is checked like any other.
    type_alias(&mut app, "LEAF");
    assert!(red_text(&mut app).contains("An entry named 'leaf' already exists."));
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.entries.len(), 3);

    // An encrypted key asks for its password until it is right.
    let encrypted = crown::x509::pbe::encrypt_private_key(
        &ed25519_pkcs8(5),
        b"secret",
        crown::x509::pbe::Pbes2Cipher::Aes256Cbc { iv: Vec::new() },
        1,
        &mut TestRng(3),
    )
    .unwrap()
    .encode();
    let five = ed25519_certificate("five", "five", 5, 5);
    write(
        "locked.pem",
        key_pem("ENCRYPTED PRIVATE KEY", &encrypted, &[&five]).as_bytes(),
    );
    import(&mut app, "locked");
    assert!(screen(&mut app, 120, 24).contains("Password of 'locked.pem': _"));
    assert!(!press(&mut app, KeyCode::Char('q')));
    press(&mut app, KeyCode::Char('x'));
    press(&mut app, KeyCode::Backspace);
    press(&mut app, KeyCode::Tab);
    assert!(screen(&mut app, 120, 24).contains("Password of 'locked.pem': *_"));
    press(&mut app, KeyCode::Enter);
    assert!(red_text(&mut app).contains("Incorrect password."));
    assert!(screen(&mut app, 120, 24).contains("Password of 'locked.pem': _"));
    press(&mut app, KeyCode::Esc);
    assert!(app.key_import.is_none());
    // The same key as DER, with its certificate in another file.
    write("der.p8", &encrypted);
    import(&mut app, "der");
    type_password(&mut app, "secret");
    press(&mut app, KeyCode::Enter);
    type_password(&mut app, "five");
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 24).contains("Alias for the imported key pair: five_"));
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.entries[0].kind(), "Private key");
    assert_eq!(app.entries[0].certificates(), [five]);

    // Key files that cannot be read say why.
    write(
        "many.pem",
        format!("{0}{0}", key_pem("PRIVATE KEY", &key, &[])).as_bytes(),
    );
    import(&mut app, "many");
    assert!(red_text(&mut app).contains("'many.pem' holds several private keys"));
    fs::remove_file(directory.path().join("many.pem")).unwrap();
    app.import_file(&directory.path().join("many.pem"));
    let message = app.message.as_ref().unwrap();
    assert!(message.0.starts_with("Cannot read") && message.1);
}

#[test]
fn entries_are_copied_from_another_keystore() {
    let directory = TestDirectory::new();
    let (_, _, key) = keystore_with_keys(&directory, "source.jks");
    let (mut app, path) = editing(&directory);

    import(&mut app, "source");
    assert!(screen(&mut app, 120, 24).contains("Password of 'source.jks': _"));
    type_password(&mut app, "wrong");
    press(&mut app, KeyCode::Enter);
    assert!(red_text(&mut app).contains("Incorrect password."));
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains(" Import entries from 'source.jks' "));
    assert!(rendered.contains("> [ ] cert | Trusted certificate"));
    assert!(rendered.contains("[ ] own | Private key (key password needed)"));
    assert!(rendered.contains("[ ] shared | Private key"));
    assert!(rendered.contains("Space Choose | a All | Up/Down j/k Move | Enter Import"));

    // A key with a separate password prompts for it; Esc returns to the list.
    assert!(!press(&mut app, KeyCode::Char('q')));
    press(&mut app, KeyCode::Char('j'));
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 24).contains("Password of key 'own': _"));
    assert!(app.key_unlock.is_some() && app.copying.is_none());
    type_password(&mut app, "wrong");
    press(&mut app, KeyCode::Enter);
    assert!(red_text(&mut app).contains("Incorrect password."));
    assert!(app.key_unlock.is_some());
    press(&mut app, KeyCode::Esc);
    assert!(app.key_unlock.is_none() && app.copying.is_some() && app.alias_prompt.is_none());

    // The selection wraps; `a` chooses all entries that can be copied, including locked keys.
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Up);
    press(&mut app, KeyCode::Char('k'));
    assert!(screen(&mut app, 120, 24).contains("> [ ] own"));
    press(&mut app, KeyCode::Char('a'));
    let rendered = screen(&mut app, 120, 24);
    assert!(
        rendered.contains("[x] cert")
            && rendered.contains("[x] own")
            && rendered.contains("[x] shared")
    );
    press(&mut app, KeyCode::Char('a'));
    assert!(screen(&mut app, 120, 24).contains("[ ] cert"));
    press(&mut app, KeyCode::Char('a'));
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 24).contains("Password of key 'own': _"));
    type_password(&mut app, "keypass");
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.message,
        Some(("Imported 3 entries from 'source.jks'.".into(), false))
    );
    assert!(app.modified && app.copying.is_none() && app.key_unlock.is_none());
    assert_eq!(app.entries.len(), 5);
    press(&mut app, KeyCode::Char('w'));
    assert!(!app.modified, "{:?}", app.message);
    assert_eq!(
        aliases(&path),
        ["cert", "own", "root-cert", "server-key", "shared"]
    );
    assert_eq!(saved_key(&path, 1, "changeit"), Ok(key.clone()));
    assert_eq!(saved_key(&path, 4, "changeit"), Ok(key));
    assert_eq!(
        app.entries,
        keystore::load_entries(&fs::read(&path).unwrap(), "changeit").unwrap()
    );

    // Aliases that exist are marked, and skipped without prompting when several are copied.
    import(&mut app, "source");
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("[ ] cert | Trusted certificate (alias exists)"));
    assert!(rendered.contains("[ ] own | Private key (alias exists, key password needed)"));
    press(&mut app, KeyCode::Char('a'));
    press(&mut app, KeyCode::Enter);
    assert!(app.key_unlock.is_none());
    assert_eq!(
        app.message,
        Some((
            "Imported 0 entries from 'source.jks'. Skipped, alias exists: cert, own, shared."
                .into(),
            true
        ))
    );
    assert!(!app.modified);
    // A single entry, here the highlighted one, is given its alias.
    import(&mut app, "source");
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Up);
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 24).contains("Alias for the imported key pair: shared_"));
    type_alias(&mut app, "copy");
    assert!(screen(&mut app, 120, 24).contains("Imported key pair as 'copy'."));
    import(&mut app, "source");
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 24).contains("Alias for the imported certificate: cert_"));
    press(&mut app, KeyCode::Esc);
    // Leaving the list copies nothing.
    import(&mut app, "source");
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Esc);
    assert!(app.copying.is_none());
    assert_eq!(app.entries.len(), 6);

    // An entry that fails stops the copy; those before it stay.
    let path = directory.path().join("open.p12");
    fs::write(
        &path,
        include_bytes!("../../tests/fixtures/passwordless.p12"),
    )
    .unwrap();
    let mut app = App::default();
    app.open_file(path);
    import(&mut app, "source");
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('a'));
    press(&mut app, KeyCode::Enter);
    type_password(&mut app, "keypass");
    press(&mut app, KeyCode::Enter);
    let (message, failed) = app.message.clone().unwrap();
    assert!(failed && app.modified);
    assert!(
        message.starts_with("Imported 1 entry from 'source.jks'. 'own' failed: Not imported"),
        "{message}"
    );
    // Without a list, its keys do nothing.
    let mut app = App::default();
    app.handle_selection(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.message.is_none());
}

#[test]
fn key_pairs_are_imported_from_and_into_pkcs12_keystores() {
    use crate::test_support::{TestRng, ed25519_certificate, ed25519_pkcs8};
    let directory = TestDirectory::new();
    let write = |name: &str, data: &[u8]| fs::write(directory.path().join(name), data).unwrap();
    let ca = ed25519_certificate("ca", "ca", 9, 9);
    let leaf = ed25519_certificate("leaf", "ca", 7, 9);
    let five = ed25519_certificate("five", "five", 5, 5);
    let key = ed25519_pkcs8(7);
    let mut rng = TestRng(1);
    let mut source = pkcs12::Writable::empty("srcpass");
    write("none.p12", &source.encode(&mut rng).unwrap());
    source
        .insert_private_key("Source", &key, &[leaf.clone(), ca.clone()], &mut rng)
        .unwrap();
    write("source.p12", &source.encode(&mut rng).unwrap());
    source
        .insert_private_key(
            "second",
            &ed25519_pkcs8(5),
            std::slice::from_ref(&five),
            &mut rng,
        )
        .unwrap();
    write("two.p12", &source.encode(&mut rng).unwrap());
    write(
        "pair.pem",
        key_pem("PRIVATE KEY", &key, &[&leaf, &ca]).as_bytes(),
    );

    let path = directory.path().join("store.p12");
    fs::write(
        &path,
        pkcs12::Writable::empty("changeit")
            .encode(&mut rng)
            .unwrap(),
    )
    .unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    assert!(app.document.is_some());

    // A PKCS12 file gives its only key pair, under its alias.
    import(&mut app, "source");
    assert!(screen(&mut app, 120, 24).contains("Password of 'source.p12': _"));
    type_password(&mut app, "wrong");
    press(&mut app, KeyCode::Enter);
    assert!(red_text(&mut app).contains("Incorrect password."));
    type_password(&mut app, "srcpass");
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 24).contains("Alias for the imported key pair: source_"));
    press(&mut app, KeyCode::Enter);
    assert!(app.modified, "{:?}", app.message);
    assert_eq!(app.entries.len(), 1);
    assert_eq!(app.entries[0].certificates(), [leaf.clone(), ca.clone()]);
    press(&mut app, KeyCode::Char('w'));
    assert!(!app.modified, "{:?}", app.message);
    assert_eq!(app.entries, pkcs12_entries(&path, "changeit"));
    let (_, saved) = pkcs12::parse(&fs::read(&path).unwrap())
        .unwrap()
        .open("changeit")
        .ok()
        .unwrap();
    assert_eq!(saved.unwrap().private_key(0).unwrap().as_slice(), key);

    // The same key pair is not added twice.
    import(&mut app, "pair");
    type_alias(&mut app, "again");
    assert!(red_text(&mut app).contains("the keystore already holds this key pair as 'source'"));
    press(&mut app, KeyCode::Esc);
    // An empty PKCS12 keystore has nothing to copy.
    import(&mut app, "none");
    type_password(&mut app, "srcpass");
    press(&mut app, KeyCode::Enter);
    assert!(red_text(&mut app).contains("'none.p12' holds no entries."));
    assert!(app.key_import.is_none() && app.copying.is_none());
    // One with several entries lists them. Entries whose alias exists are
    // skipped, and the others keep their alias.
    import(&mut app, "two");
    type_password(&mut app, "srcpass");
    press(&mut app, KeyCode::Enter);
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains(" Import entries from 'two.p12' "));
    assert!(rendered.contains("[ ] Source | Private key (alias exists)"));
    assert!(rendered.contains("[ ] second | Private key"));
    press(&mut app, KeyCode::Char('a'));
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.message,
        Some((
            "Imported 1 entry from 'two.p12'. Skipped, alias exists: source.".into(),
            false
        ))
    );
    assert_eq!(app.entries.len(), 2);
    assert_eq!(app.entries[0].certificates(), [five]);
    press(&mut app, KeyCode::Char('w'));
    assert!(!app.modified, "{:?}", app.message);
    let (_, saved) = pkcs12::parse(&fs::read(&path).unwrap())
        .unwrap()
        .open("changeit")
        .ok()
        .unwrap();
    assert_eq!(
        saved.unwrap().private_key(0).unwrap().as_slice(),
        ed25519_pkcs8(5)
    );

    // A passwordless truststore has no password to protect a key with, and
    // neither has a Java store whose empty password is a NUL character. The
    // certificate request in the key's file is passed over.
    let mut text = key_pem("PRIVATE KEY", &key, &[&leaf]).into_bytes();
    text.extend_from_slice(test_support::KEYTOOL_REQUEST);
    write("request.pem", &text);
    for (name, data) in [
        (
            "open.p12",
            &include_bytes!("../../tests/fixtures/passwordless.p12")[..],
        ),
        (
            "empty.p12",
            include_bytes!("../../tests/fixtures/empty-password.p12"),
        ),
        (
            "nul.p12",
            include_bytes!("../../tests/fixtures/nul-password.p12"),
        ),
    ] {
        let path = directory.path().join(name);
        fs::write(&path, data).unwrap();
        let mut app = App::default();
        app.open_file(path.clone());
        assert!(app.document.is_some(), "{name}");
        let listed = app.entries.len();
        import(&mut app, "request");
        press(&mut app, KeyCode::Enter);
        assert!(
            red_text(&mut app).contains("a key needs a keystore password that is not empty"),
            "{name}"
        );
        assert!(!app.modified, "{name}");
        assert_eq!(app.entries.len(), listed, "{name}");
        assert_eq!(fs::read(&path).unwrap(), data, "{name}");
    }
}

#[test]
fn exporting_a_private_key_writes_a_new_protected_file() {
    let directory = TestDirectory::new();
    let (mut app, _, key) = keystore_with_keys(&directory, "store.jks");
    let file = |name: &str| directory.path().join(name);
    assert!(
        screen(&mut app, 120, 24)
            .contains("Entry: e Export | c Request | R CA reply | C Chain | S Sign | r Rename")
    );
    // Only a private key that the keystore's password unlocks is exported.
    press(&mut app, KeyCode::Char('e'));
    assert!(red_text(&mut app).contains("Only private and secret keys are exported with e"));
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Char('e'));
    assert!(red_text(&mut app).contains("the key 'own' has a password of its own"));
    assert!(app.key_export.is_none());
    press(&mut app, KeyCode::Down);
    let chain = app.entries[2].certificates().to_vec();

    // The suggested name exports a PKCS12 keystore.
    press(&mut app, KeyCode::Char('e'));
    let rendered = screen(&mut app, 200, 24);
    assert!(rendered.contains("Export key to: ") && rendered.contains("shared.p12 "));
    assert!(rendered.contains(".p12 Keystore | .pem Key and certificates | .key .p8 Key only"));
    assert!(!press(&mut app, KeyCode::Char('q')));
    press(&mut app, KeyCode::Backspace);
    press(&mut app, KeyCode::Esc);
    assert!(app.key_export.is_none());
    press(&mut app, KeyCode::Char('e'));
    press(&mut app, KeyCode::Enter);
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("Password for the exported key: _"));
    assert!(!rendered.contains("Empty: unencrypted"));
    // PKCS12 needs a password.
    type_new_password(&mut app, "", "");
    assert!(red_text(&mut app).contains("a PKCS12 file needs a password that is not empty"));
    assert!(!file("shared.p12").exists());
    press(&mut app, KeyCode::Char('e'));
    press(&mut app, KeyCode::Enter);
    type_new_password(&mut app, "exportpw", "exportpw");
    assert!(
        screen(&mut app, 200, 24).contains("Exported key 'shared' to '"),
        "{:?}",
        app.message
    );
    assert!(!app.modified);
    let (verified, exported) = pkcs12::parse(&fs::read(file("shared.p12")).unwrap())
        .unwrap()
        .open("exportpw")
        .ok()
        .unwrap();
    assert_eq!(verified.entries.len(), 1);
    assert_eq!(verified.entries[0].alias, "shared");
    assert_eq!(verified.entries[0].certificates(), chain);
    assert_eq!(exported.unwrap().private_key(0).unwrap().as_slice(), key);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(file("shared.p12"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // An existing file is never replaced.
    press(&mut app, KeyCode::Char('e'));
    assert!(screen(&mut app, 200, 24).contains("shared-2.p12 "));
    type_alias(&mut app, "shared.p12");
    assert!(red_text(&mut app).contains("already exists; choose another name."));
    // A .pem name holds the key and its certificates; without a password
    // the key is unencrypted, which is asked about first.
    type_alias(&mut app, "shared.pem");
    assert!(screen(&mut app, 120, 24).contains("Empty: unencrypted | Enter Confirm"));
    type_new_password(&mut app, "", "");
    assert!(
        screen(&mut app, 200, 24)
            .contains("Write the private key 'shared' unencrypted? Press y to write it")
    );
    press(&mut app, KeyCode::Char('n'));
    assert!(!file("shared.pem").exists());
    press(&mut app, KeyCode::Char('e'));
    type_alias(&mut app, "shared.pem");
    type_new_password(&mut app, "", "");
    press(&mut app, KeyCode::Char('y'));
    let text = fs::read_to_string(file("shared.pem")).unwrap();
    let blocks = crown::asn1::pem::parse(&text).unwrap();
    assert_eq!(blocks.len(), 1 + chain.len());
    assert_eq!(
        (blocks[0].label.as_str(), &blocks[0].data),
        ("PRIVATE KEY", &key)
    );
    assert_eq!(
        (blocks[1].label.as_str(), &blocks[1].data),
        ("CERTIFICATE", &chain[0])
    );

    // .key and .p8 names hold the key alone, here encrypted.
    for (name, der) in [("shared.key", false), ("shared.p8", true)] {
        press(&mut app, KeyCode::Char('e'));
        type_alias(&mut app, name);
        type_new_password(&mut app, "exportpw", "exportpw");
        let data = fs::read(file(name)).unwrap();
        let encrypted = if der {
            data
        } else {
            let blocks = crown::asn1::pem::parse(std::str::from_utf8(&data).unwrap()).unwrap();
            assert_eq!(blocks.len(), 1);
            assert_eq!(blocks[0].label, "ENCRYPTED PRIVATE KEY");
            blocks[0].data.clone()
        };
        assert!(!encrypted.windows(key.len()).any(|window| window == key));
        assert_eq!(
            pkcs12::decrypt_key(&encrypted, b"exportpw")
                .unwrap()
                .as_slice(),
            key,
            "{name}"
        );
    }
    // Mistyped passwords export nothing.
    press(&mut app, KeyCode::Char('e'));
    type_alias(&mut app, "typo.key");
    type_new_password(&mut app, "one", "two");
    assert!(red_text(&mut app).contains("The passwords do not match"));
    press(&mut app, KeyCode::Esc);
    assert!(!file("typo.key").exists());
    // A file that cannot be created says so.
    press(&mut app, KeyCode::Char('e'));
    type_alias(&mut app, "missing/shared.key");
    type_new_password(&mut app, "exportpw", "exportpw");
    assert!(red_text(&mut app).contains("Cannot create"));

    // Without a private key to export, nothing is asked.
    let (mut app, _) = editing(&directory);
    press(&mut app, KeyCode::Char('d'));
    press(&mut app, KeyCode::Char('y'));
    press(&mut app, KeyCode::Char('d'));
    press(&mut app, KeyCode::Char('y'));
    assert!(app.entries.is_empty());
    press(&mut app, KeyCode::Char('e'));
    assert!(app.key_export.is_none() && app.message.is_none());
    let mut app = App::default();
    press(&mut app, KeyCode::Char('e'));
    app.handle_key_export(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    app.export_key(&file("none.key"), 0, "", false);
    assert!(app.key_export.is_none() && app.message.is_none());
    assert!(!file("none.key").exists());
}

#[test]
fn changing_the_password_is_written_on_save() {
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    assert!(screen(&mut app, 120, 24).contains("W Save as | p Password"));
    press(&mut app, KeyCode::Char('p'));
    assert!(screen(&mut app, 120, 24).contains("New keystore password: _"));
    // Letters are typed, masked, instead of quitting.
    assert!(!press(&mut app, KeyCode::Char('q')));
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("New keystore password: *_"));
    press(&mut app, KeyCode::Backspace);

    type_new_password(&mut app, "new-päss", "new-pass");
    assert!(red_text(&mut app).contains("The passwords do not match"));
    assert!(!app.modified);
    // The prompt starts over with the first entry.
    assert!(screen(&mut app, 120, 24).contains("New keystore password: _"));
    type_password(&mut app, "new-päss");
    press(&mut app, KeyCode::Enter);
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("Type the password again: _"));
    assert!(!rendered.contains("new-päss"));
    type_password(&mut app, "new-päss");
    press(&mut app, KeyCode::Enter);
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("Password changed"));
    assert!(rendered.contains("[modified]"));
    assert!(app.new_password.is_none());
    assert_eq!(aliases(&path), ["root-cert", "server-key"]);

    press(&mut app, KeyCode::Char('w'));
    let saved = fs::read(&path).unwrap();
    assert!(keystore::load_entries(&saved, "changeit").is_none());
    assert_eq!(
        keystore::load_entries(&saved, "new-päss").unwrap(),
        app.entries
    );
    // Only the digest differs: entries, and so key protection, are untouched.
    let original = mixed_keystore();
    assert_eq!(saved[..saved.len() - 20], original[..original.len() - 20]);

    // Esc cancels at either step.
    for steps in [0, 1] {
        press(&mut app, KeyCode::Char('p'));
        for _ in 0..steps {
            press(&mut app, KeyCode::Enter);
        }
        assert!(!press(&mut app, KeyCode::Esc));
        assert!(app.new_password.is_none() && !app.modified);
    }
}

#[test]
fn private_keys_without_certificates_are_copied_into_every_format() {
    use crate::test_support::{TestRng, ed25519_pkcs8};
    let directory = TestDirectory::new();
    let mut rng = TestRng(3);
    let mut source = pkcs12::Writable::empty("srcpass");
    for (alias, seed) in [("bare", 3), ("other", 4)] {
        source
            .insert_private_key(alias, &ed25519_pkcs8(seed), &[], &mut rng)
            .unwrap();
    }
    fs::write(
        directory.path().join("bare.p12"),
        source.encode(&mut rng).unwrap(),
    )
    .unwrap();

    for name in ["store.jks", "store.jceks", "store.p12"] {
        let path = directory.path().join(name);
        let data = if name.ends_with(".p12") {
            pkcs12::Writable::empty("changeit")
                .encode(&mut rng)
                .unwrap()
        } else {
            keystore::Writable::empty(name.ends_with(".jceks")).encode("changeit")
        };
        fs::write(&path, data).unwrap();
        let mut app = App::default();
        app.open_file(path.clone());
        type_password(&mut app, "changeit");
        press(&mut app, KeyCode::Enter);
        assert!(app.document.is_some(), "{name}");

        // Both keys are copied: neither panics, and in PKCS12 the second
        // is not taken for the first, as neither has a certificate.
        import(&mut app, "bare");
        type_password(&mut app, "srcpass");
        press(&mut app, KeyCode::Enter);
        assert!(
            screen(&mut app, 120, 24).contains("[ ] other | Private key"),
            "{name}"
        );
        press(&mut app, KeyCode::Char('a'));
        press(&mut app, KeyCode::Enter);
        assert_eq!(
            app.message,
            Some(("Imported 2 entries from 'bare.p12'.".into(), false)),
            "{name}"
        );
        // A single one goes through the alias prompt.
        import(&mut app, "bare");
        type_password(&mut app, "srcpass");
        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Enter);
        type_alias(&mut app, "copy");
        assert!(
            screen(&mut app, 120, 24).contains("Imported key pair as 'copy'."),
            "{name}"
        );
        assert_eq!(shown_aliases(&app), ["bare", "copy", "other"], "{name}");
        for entry in &app.entries {
            assert_eq!(entry.kind(), Kind::PrivateKey.label(), "{name}");
            assert!(entry.certificates().is_empty(), "{name}");
            assert!(entry.certificate.is_none(), "{name}");
        }

        // The keys are saved without a chain and read back.
        press(&mut app, KeyCode::Char('w'));
        assert!(!app.modified, "{name}: {:?}", app.message);
        let mut saved = Vec::new();
        if name.ends_with(".p12") {
            assert_eq!(app.entries, pkcs12_entries(&path, "changeit"), "{name}");
            let (_, writable) = pkcs12::parse(&fs::read(&path).unwrap())
                .unwrap()
                .open("changeit")
                .ok()
                .unwrap();
            let writable = writable.unwrap();
            for index in 0..app.entries.len() {
                saved.push(writable.private_key(index).unwrap().to_vec());
            }
        } else {
            assert_eq!(
                app.entries,
                keystore::load_entries(&fs::read(&path).unwrap(), "changeit").unwrap(),
                "{name}"
            );
            for index in 0..app.entries.len() {
                saved.push(saved_key(&path, index, "changeit").unwrap());
            }
        }
        let expected: Vec<Vec<u8>> = app
            .entries
            .iter()
            .map(|entry| ed25519_pkcs8(if entry.alias == "other" { 4 } else { 3 }))
            .collect();
        assert_eq!(saved, expected, "{name}");
    }
}

#[test]
fn failed_certificate_read_clears_pending_key_import() {
    use crate::test_support::{ed25519_certificate, ed25519_pkcs8};
    let directory = TestDirectory::new();
    let (mut app, _) = editing(&directory);
    let write = |name: &str, data: &[u8]| fs::write(directory.path().join(name), data).unwrap();
    write("only.key", &ed25519_pkcs8(5));
    fs::File::create(directory.path().join("huge.crt"))
        .unwrap()
        .set_len(MAX_KEYSTORE_SIZE + 1)
        .unwrap();
    write("five.crt", &ed25519_certificate("five", "five", 5, 5));

    // Importing a standalone key enters the certificate-picker stage with the
    // decrypted key held in `key_import`.
    import(&mut app, "only");
    assert!(app.key_import.is_some());
    assert!(screen(&mut app, 120, 24).contains(" Certificate file of the imported key "));

    // If reading the chosen certificate file fails, the pending key is dropped
    // and subsequent `o` and `i` picker flows are not corrupted.
    type_password(&mut app, "huge");
    press(&mut app, KeyCode::Enter);
    assert!(red_text(&mut app).contains("Cannot read"));
    assert!(app.key_import.is_none() && !app.importing);

    press(&mut app, KeyCode::Char('o'));
    assert!(!screen(&mut app, 120, 24).contains(" Certificate file of the imported key "));
    press(&mut app, KeyCode::Esc);

    press(&mut app, KeyCode::Char('i'));
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains(" Import certificate or key pair from file "));
    assert!(!rendered.contains(" Certificate file of the imported key "));
    type_password(&mut app, "five");
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 24).contains("Alias for the imported certificate: five_"));
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 24).contains("Imported certificate as 'five'."));
    assert_eq!(app.entries[0].kind(), "Trusted certificate");
}

#[test]
fn legacy_openssl_pem_export_and_import() {
    use crate::{
        generate::{self, Algorithm},
        signing,
        test_support::{TestRng, ed25519_certificate, ed25519_pkcs8},
    };
    use crown::{
        asn1::Asn1Time,
        ec::CurveId,
        x509::{cert::Certificate, keys::PrivateKeyInfo, name::Name},
    };

    let clear = |app: &mut App| {
        app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    };
    let directory = TestDirectory::new();
    let file = |name: &str| directory.path().join(name);
    let mut rng = TestRng(55);
    let mut os_rng = save::OsRng::default();
    let rsa_key = generate::key_pair(Algorithm::Rsa(1024), &mut os_rng).unwrap();
    let ec_key = generate::key_pair(Algorithm::Ec(CurveId::P256), &mut rng).unwrap();
    let ed_key = ed25519_pkcs8(7);
    let time = |seconds| Asn1Time::from_unix(seconds, true);
    let rsa_decoded = PrivateKeyInfo::parse(&rsa_key).unwrap().decode().unwrap();
    let rsa_cert = Certificate::self_signed(
        Name::from_common_name("rsa-leaf"),
        signing::signature_algorithm(&rsa_decoded).unwrap(),
        &rsa_decoded,
        time(0),
        time(1_000_000_000),
        vec![],
        &mut rng,
    )
    .unwrap()
    .encode();
    let ec_decoded = PrivateKeyInfo::parse(&ec_key).unwrap().decode().unwrap();
    let ec_cert = Certificate::self_signed(
        Name::from_common_name("ec-leaf"),
        signing::signature_algorithm(&ec_decoded).unwrap(),
        &ec_decoded,
        time(0),
        time(1_000_000_000),
        vec![],
        &mut rng,
    )
    .unwrap()
    .encode();
    let ed_cert = ed25519_certificate("ed-leaf", "ed-leaf", 7, 7);

    let mut store = pkcs12::Writable::empty("storepw");
    store
        .insert_private_key("ec", &ec_key, &[ec_cert], &mut rng)
        .unwrap();
    store
        .insert_private_key("ed", &ed_key, &[ed_cert], &mut rng)
        .unwrap();
    store
        .insert_private_key("rsa", &rsa_key, &[rsa_cert], &mut rng)
        .unwrap();
    let store_path = file("keys.p12");
    fs::write(&store_path, store.encode(&mut rng).unwrap()).unwrap();
    let mut app = App::default();
    app.open_file(store_path);
    type_password(&mut app, "storepw");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.entries.len(), 3);

    // Entries are sorted: 0 = "ec", 1 = "ed", 2 = "rsa".
    // 1. Export EC key as encrypted legacy OpenSSL PEM (.pem includes certificates).
    press(&mut app, KeyCode::Char('e'));
    // Default .p12 does not offer Tab toggle.
    assert!(!screen(&mut app, 200, 24).contains("Tab OpenSSL"));
    press(&mut app, KeyCode::Tab);
    assert!(!screen(&mut app, 200, 24).contains("Export key to (OpenSSL):"));
    // Switching to .pem enables Tab toggle.
    clear(&mut app);
    type_password(&mut app, "ec-legacy.pem");
    assert!(screen(&mut app, 200, 24).contains("Tab OpenSSL"));
    press(&mut app, KeyCode::Tab);
    let rendered = screen(&mut app, 200, 24);
    assert!(rendered.contains("Export key to (OpenSSL):"));
    assert!(rendered.contains("Tab PKCS #8"));
    press(&mut app, KeyCode::Enter);
    type_new_password(&mut app, "legacypw", "legacypw");
    // Encrypted legacy OpenSSL PEM asks for MD5 confirmation.
    let rendered = screen(&mut app, 200, 24);
    assert!(rendered.contains("Legacy OpenSSL PEM uses weaker MD5 key derivation"));
    // Declining writes nothing.
    press(&mut app, KeyCode::Char('n'));
    assert!(!file("ec-legacy.pem").exists());

    // Confirming with `y` writes the encrypted EC PRIVATE KEY + CERTIFICATE.
    press(&mut app, KeyCode::Char('e'));
    clear(&mut app);
    type_password(&mut app, "ec-legacy.pem");
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Enter);
    type_new_password(&mut app, "legacypw", "legacypw");
    press(&mut app, KeyCode::Char('y'));
    assert!(screen(&mut app, 200, 24).contains("Exported key 'ec' to '"));
    let ec_pem = fs::read_to_string(file("ec-legacy.pem")).unwrap();
    assert!(ec_pem.starts_with(
        "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,"
    ));
    assert!(ec_pem.contains("-----BEGIN CERTIFICATE-----"));

    // 2. Ed25519 key does not offer Tab toggle even for .key.
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Char('e'));
    clear(&mut app);
    type_password(&mut app, "ed.key");
    assert!(!screen(&mut app, 200, 24).contains("Tab OpenSSL"));
    press(&mut app, KeyCode::Tab);
    assert!(!screen(&mut app, 200, 24).contains("Export key to (OpenSSL):"));
    press(&mut app, KeyCode::Esc);

    // 3. Export RSA key as plain legacy OpenSSL .key (key only, unencrypted confirm).
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Char('e'));
    clear(&mut app);
    type_password(&mut app, "rsa-plain.key");
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Enter);
    type_new_password(&mut app, "", "");
    assert!(screen(&mut app, 200, 24).contains("Write the private key 'rsa' unencrypted?"));
    press(&mut app, KeyCode::Char('y'));
    let rsa_plain = fs::read_to_string(file("rsa-plain.key")).unwrap();
    assert!(rsa_plain.starts_with("-----BEGIN RSA PRIVATE KEY-----\n"));
    assert!(!rsa_plain.contains("Proc-Type"));
    assert!(!rsa_plain.contains("-----BEGIN CERTIFICATE-----"));

    // Also export RSA key as encrypted legacy OpenSSL .pem (key + cert).
    press(&mut app, KeyCode::Char('e'));
    clear(&mut app);
    type_password(&mut app, "rsa-enc.pem");
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Enter);
    type_new_password(&mut app, "rsapw", "rsapw");
    press(&mut app, KeyCode::Char('y'));
    let rsa_enc = fs::read_to_string(file("rsa-enc.pem")).unwrap();
    assert!(rsa_enc.starts_with(
        "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,"
    ));

    // 4. Re-import the encrypted legacy EC and RSA PEM files into a fresh keystore.
    let (mut app, _) = editing(&directory);
    import(&mut app, "ec-legacy");
    assert!(screen(&mut app, 120, 24).contains("Password of 'ec-legacy.pem': _"));
    type_password(&mut app, "wrong");
    press(&mut app, KeyCode::Enter);
    assert!(red_text(&mut app).contains("Incorrect password."));
    type_password(&mut app, "legacypw");
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 24).contains("Alias for the imported key pair: ec-leaf_"));
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 24).contains("Imported key pair as 'ec-leaf'."));

    import(&mut app, "rsa-enc");
    type_password(&mut app, "rsapw");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 24).contains("Imported key pair as 'rsa-leaf'."));
}
