use super::*;

/// An empty PKCS12 keystore `name` with `password`, opened.
fn pkcs12_app(directory: &TestDirectory, name: &str, password: &str) -> (App, PathBuf) {
    let path = directory.path().join(name);
    let mut rng = test_support::TestRng(1);
    fs::write(
        &path,
        pkcs12::Writable::empty(password).encode(&mut rng).unwrap(),
    )
    .unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    type_password(&mut app, password);
    press(&mut app, KeyCode::Enter);
    assert!(app.document.is_some());
    (app, path)
}

/// Chooses the file starting with `name` as the secret key to import.
fn import_secret(app: &mut App, name: &str) {
    press(app, KeyCode::Char('G'));
    press(app, KeyCode::Char('i'));
    type_password(app, name);
    press(app, KeyCode::Enter);
}

#[test]
fn secret_keys_are_generated_and_imported_from_files() {
    let directory = TestDirectory::new();
    let (mut app, path) = pkcs12_app(&directory, "store.p12", "changeit");
    let file = |name: &str| directory.path().join(name);
    fs::write(file("token.hex"), "00:11 22334455\n66778899aabbccddeeff\n").unwrap();
    fs::write(file("raw.bin"), [0xff; 20]).unwrap();
    fs::write(file("empty.bin"), b"").unwrap();
    app.handle_secret_choice(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

    // The algorithm is chosen first; letters such as q do nothing.
    press(&mut app, KeyCode::Char('G'));
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("New secret key: < AES (256 bits) >"));
    assert!(rendered.contains("Left/Right Change | Enter Next | i Import from file | Esc Cancel"));
    assert!(!press(&mut app, KeyCode::Char('q')));
    press(&mut app, KeyCode::Left);
    assert!(screen(&mut app, 120, 24).contains("< AES (192 bits) >"));
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Right);
    assert!(screen(&mut app, 120, 24).contains("< HmacSHA1 (160 bits) >"));
    press(&mut app, KeyCode::Esc);
    assert!(app.secret_choice.is_none() && !app.modified);

    // The alias is asked next, suggesting the algorithm.
    press(&mut app, KeyCode::Char('G'));
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 24).contains("Alias for the generated secret key: aes_"));
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.message,
        Some(("Generated AES (256 bits) secret key 'aes'.".into(), false))
    );
    assert!(app.modified);
    assert_eq!(app.entries[0].kind(), "Secret key");
    let generated = app.document.as_ref().unwrap().secret_key(0).ok().unwrap();
    assert_eq!(
        (generated.algorithm.as_str(), generated.key.len()),
        ("AES", 32)
    );
    // An alias is used once.
    press(&mut app, KeyCode::Char('G'));
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Enter);
    assert!(red_text(&mut app).contains("An entry named 'aes' already exists."));
    press(&mut app, KeyCode::Esc);

    // A key is read from a file instead; Esc in the browser gives up.
    press(&mut app, KeyCode::Char('G'));
    press(&mut app, KeyCode::Char('i'));
    assert!(screen(&mut app, 120, 24).contains(" Secret key file, as bytes or hex digits "));
    press(&mut app, KeyCode::Esc);
    assert!(app.file_picker.is_none() && !app.importing_secret);
    import_secret(&mut app, "empty");
    assert!(
        red_text(&mut app).contains("'empty.bin' holds no secret key: a key is 1 to 1024 bytes")
    );
    app.import_secret_file(&file("missing.bin"));
    assert!(red_text(&mut app).contains("Cannot read"));

    // Hex digits spell a key of 16 bytes, which AES or any HMAC takes.
    import_secret(&mut app, "token");
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("Secret key from 'token.hex': < AES (128 bits) >"));
    assert!(rendered.contains("Left/Right Change | Enter Next | Esc Cancel"));
    assert!(!rendered.contains("i Import from file"));
    press(&mut app, KeyCode::Char('i'));
    assert!(app.secret_choice.is_some() && app.file_picker.is_none());
    press(&mut app, KeyCode::Left);
    assert!(screen(&mut app, 120, 24).contains("< HmacSHA512 (128 bits) >"));
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 24).contains("Alias for the imported secret key: token_"));
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.message,
        Some(("Imported secret key as 'token'.".into(), false))
    );
    // Twenty bytes as they are make an HMAC key, not an AES key.
    import_secret(&mut app, "raw");
    assert!(
        screen(&mut app, 120, 24).contains("Secret key from 'raw.bin': < HmacSHA1 (160 bits) >")
    );
    press(&mut app, KeyCode::Enter);
    type_alias(&mut app, "Raw");

    // The keys are written on save, under the keystore's password.
    press(&mut app, KeyCode::Char('w'));
    assert!(!app.modified, "{:?}", app.message);
    assert_eq!(app.entries, pkcs12_entries(&path, "changeit"));
    let data = fs::read(&path).unwrap();
    let (_, saved) = pkcs12::parse(&data).unwrap().open("changeit").ok().unwrap();
    let saved = save::Document::Pkcs12(saved.unwrap());
    let key = |alias: &str| {
        let index = app.entries.iter().position(|e| e.alias == alias).unwrap();
        let key = saved.secret_key(index).ok().unwrap();
        (key.algorithm.clone(), key.key.to_vec())
    };
    assert_eq!(key("aes"), ("AES".into(), generated.key.to_vec()));
    assert_eq!(
        key("token"),
        (
            "AES".into(),
            vec![
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        )
    );
    assert_eq!(key("raw"), ("HmacSHA1".into(), vec![0xff; 20]));

    // A key needs a keystore password, and an algorithm PKCS12 can name.
    let odd = secret_key::SecretKey {
        algorithm: "Blowfish".into(),
        key: zeroize::Zeroizing::new(vec![1; 8]),
    };
    let document = app.document.as_mut().unwrap();
    assert_eq!(
        document.import_secret_key(&mut app.entries, "odd".into(), &odd),
        Err("Not added: PKCS12 has no name for the algorithm 'Blowfish'.".into())
    );
    let (mut open, _) = pkcs12_app(&directory, "open.p12", "");
    press(&mut open, KeyCode::Char('G'));
    press(&mut open, KeyCode::Enter);
    press(&mut open, KeyCode::Enter);
    assert!(red_text(&mut open).contains("Not added: a key needs a keystore password"));
    assert!(open.entries.is_empty() && !open.modified);

    // A JKS keystore holds no secret keys.
    let (mut jks, _) = editing(&directory);
    press(&mut jks, KeyCode::Char('G'));
    assert!(red_text(&mut jks).contains("A JKS keystore cannot hold secret keys"));
    assert!(jks.secret_choice.is_none());
    let document = jks.document.as_mut().unwrap();
    assert!(
        document
            .import_secret_key(&mut jks.entries, "odd".into(), &odd)
            .unwrap_err()
            .contains("a JKS keystore cannot hold secret keys")
    );
}

#[test]
fn a_secret_key_is_exported_unencrypted_after_a_confirmation() {
    let directory = TestDirectory::new();
    let (mut app, path) = pkcs12_app(&directory, "store.p12", "changeit");
    let file = |name: &str| directory.path().join(name);
    fs::write(file("token.hex"), "0011223344556677").unwrap();
    import_secret(&mut app, "token");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.entries[0].alias, "token");
    app.handle_secret_export(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    let stored = fs::read(&path).unwrap();

    // The file name is asked first; Esc gives up.
    press(&mut app, KeyCode::Char('e'));
    let rendered = screen(&mut app, 200, 24);
    assert!(rendered.contains(&format!(
        "Export secret key to: {} ",
        file("token.bin").display()
    )));
    assert!(
        rendered.contains(".hex .txt Hex digits | any other name The key's bytes | Enter Next")
    );
    assert!(!press(&mut app, KeyCode::Char('q')));
    press(&mut app, KeyCode::Esc);
    assert!(app.secret_export.is_none());

    // Any key but y cancels the question, and nothing is written.
    press(&mut app, KeyCode::Char('e'));
    type_alias(&mut app, "out.HEX");
    assert!(
        screen(&mut app, 120, 24).contains("Write the secret key 'token' unencrypted? Press y")
    );
    press(&mut app, KeyCode::Char('n'));
    assert!(!file("out.HEX").exists());
    press(&mut app, KeyCode::Char('e'));
    type_alias(&mut app, "out.HEX");
    press(&mut app, KeyCode::Char('y'));
    assert_eq!(
        app.message,
        Some((
            format!(
                "Exported the HmacSHA1 secret key 'token' (64 bits) to '{}'.",
                file("out.HEX").display()
            ),
            false
        ))
    );
    assert_eq!(
        fs::read_to_string(file("out.HEX")).unwrap(),
        "0011223344556677\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(file("out.HEX")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // Any other name holds the key's bytes.
    press(&mut app, KeyCode::Char('e'));
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('y'));
    assert_eq!(
        fs::read(file("token.bin")).unwrap(),
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
    );
    // An existing file is never replaced.
    press(&mut app, KeyCode::Char('e'));
    type_alias(&mut app, "token.bin");
    assert!(red_text(&mut app).contains("already exists; choose another name."));
    assert!(app.secret_export.is_some() && app.confirm.is_none());
    press(&mut app, KeyCode::Esc);
    // The keystore is not written by an export.
    assert_eq!(fs::read(&path).unwrap(), stored);

    // A key that no longer opens is not exported.
    let document = app.document.take();
    app.export_secret(&file("late.bin"), 0);
    app.ask_secret_export(0);
    assert!(app.secret_export.is_none() && !file("late.bin").exists());
    app.document = document;
    let (mut other, _) = pkcs12_app(&directory, "other.p12", "changeit");
    other
        .document
        .as_mut()
        .unwrap()
        .import_certificate(
            &mut other.entries,
            "cert".into(),
            test_support::fixture_certificate_der(),
        )
        .unwrap();
    other.ask_secret_export(0);
    assert!(
        red_text(&mut other).contains("Not exported: the secret key 'cert' could not be decrypted"),
        "{:?}",
        other.message
    );
    other.export_secret(&file("late.bin"), 0);
    assert!(red_text(&mut other).contains("Not exported: the secret key 'cert'"));
    assert!(!file("late.bin").exists());
}

/// An empty JCEKS keystore `name` with the password `changeit`, opened.
fn jceks_app(directory: &TestDirectory, name: &str) -> (App, PathBuf) {
    let path = directory.path().join(name);
    fs::write(&path, keystore::Writable::empty(true).encode("changeit")).unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    assert!(app.document.is_some());
    (app, path)
}

#[test]
fn jceks_secret_keys_are_sealed_converted_and_given_passwords() {
    let directory = TestDirectory::new();
    let (mut app, path) = jceks_app(&directory, "store.jceks");
    let file = |name: &str| directory.path().join(name);

    // Four steps right of AES (256 bits) is HmacSHA512.
    press(&mut app, KeyCode::Char('G'));
    for _ in 0..4 {
        press(&mut app, KeyCode::Right);
    }
    press(&mut app, KeyCode::Enter);
    type_alias(&mut app, "Mac");
    assert_eq!(
        app.message,
        Some((
            "Generated HmacSHA512 (512 bits) secret key 'mac'.".into(),
            false
        ))
    );
    press(&mut app, KeyCode::Char('w'));
    assert!(!app.modified, "{:?}", app.message);
    assert_eq!(
        app.entries,
        keystore::load_entries(&fs::read(&path).unwrap(), "changeit").unwrap()
    );
    let original = app.document.as_ref().unwrap().secret_key(0).ok().unwrap();
    assert_eq!(
        (original.algorithm.as_str(), original.key.len()),
        ("HmacSHA512", 64)
    );

    // The key converts to PKCS12 and back, and is the same key.
    press(&mut app, KeyCode::Char('W'));
    type_alias(&mut app, "copy.p12");
    assert!(
        screen(&mut app, 200, 24).contains("as PKCS12."),
        "{:?}",
        app.message
    );
    assert!(app.document.as_ref().unwrap().secret_key(0) == Ok(original.clone()));
    press(&mut app, KeyCode::Char('W'));
    type_alias(&mut app, "back.jceks");
    assert!(
        screen(&mut app, 200, 24).contains("as JCEKS."),
        "{:?}",
        app.message
    );
    assert!(app.document.as_ref().unwrap().secret_key(0) == Ok(original.clone()));
    // JKS has no place for it.
    press(&mut app, KeyCode::Char('W'));
    type_alias(&mut app, "none.jks");
    assert!(red_text(&mut app).contains("Not converted: the secret key 'mac' stops it"));
    assert!(!file("none.jks").exists());
    press(&mut app, KeyCode::Esc);

    // A secret key takes a password of its own, like a private key.
    press(&mut app, KeyCode::Char('P'));
    assert!(screen(&mut app, 120, 24).contains("New password for key 'mac': _"));
    type_new_password(&mut app, "own", "own");
    assert!(screen(&mut app, 120, 24).contains("Password of key 'mac' changed"));
    assert!(app.modified);
    press(&mut app, KeyCode::Char('e'));
    assert!(red_text(&mut app).contains(
        "Not exported: the secret key 'mac' has a password of its own; give it the keystore's password first (P)."
    ));
    // Converting prompts for the secret key's own password; Esc returns to
    // the "save as" prompt without writing.
    press(&mut app, KeyCode::Char('W'));
    type_alias(&mut app, "late.p12");
    assert!(screen(&mut app, 120, 24).contains("Password of key 'mac': _"));
    assert!(app.key_unlock.is_some() && app.save_as.is_some());
    press(&mut app, KeyCode::Esc);
    assert!(app.key_unlock.is_none() && app.save_as.is_some());
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Char('P'));
    assert!(screen(&mut app, 120, 24).contains("Current password of key 'mac': _"));
    type_password(&mut app, "wrong");
    press(&mut app, KeyCode::Enter);
    assert!(red_text(&mut app).contains("Incorrect key password."));
    type_password(&mut app, "own");
    press(&mut app, KeyCode::Enter);
    type_new_password(&mut app, "changeit", "changeit");
    assert!(app.document.as_ref().unwrap().secret_key(0) == Ok(original));
    // A JCEKS key password is printable ASCII.
    press(&mut app, KeyCode::Char('P'));
    type_new_password(&mut app, "pässword", "pässword");
    assert!(red_text(&mut app).contains("can only use printable ASCII characters"));

    // An algorithm PKCS12 has no name for stays in JCEKS.
    let odd = secret_key::SecretKey {
        algorithm: "Blowfish".into(),
        key: zeroize::Zeroizing::new(vec![1; 8]),
    };
    let document = app.document.as_mut().unwrap();
    let to = document
        .import_secret_key(&mut app.entries, "odd".into(), &odd)
        .unwrap();
    assert!(document.secret_key(to) == Ok(odd));
    app.refresh_visible();
    press(&mut app, KeyCode::Char('W'));
    type_alias(&mut app, "odd.p12");
    assert!(red_text(&mut app).contains(
        "Not converted: PKCS12 has no name for the algorithm 'Blowfish' of the secret key 'odd'."
    ));
    assert!(!file("odd.p12").exists());
}

#[test]
fn secret_keys_that_cannot_be_read_are_reported() {
    let directory = TestDirectory::new();
    use crate::keystore::{SECRET_KEY_TAG, VERSION_02};
    // A sealed object with synthetic content, and a certificate.
    let mut builder = test_support::Builder::jceks(VERSION_02, 2);
    builder.entry(SECRET_KEY_TAG, b"aes", VERSION_02, 0);
    builder.entry(keystore::TRUSTED_CERT_TAG, b"cert", VERSION_02, 1);
    let path = directory.path().join("store.jceks");
    fs::write(&path, builder.finish("changeit")).unwrap();
    let mut app = App::default();
    app.open_file(path);
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.entries[0].kind(), "Secret key");

    press(&mut app, KeyCode::Char('e'));
    assert!(
        red_text(&mut app).contains(
            "Not exported: the secret key 'aes' is sealed in a way that is not supported."
        )
    );
    press(&mut app, KeyCode::Char('P'));
    assert!(red_text(&mut app).contains("This key's protection is not supported."));
    let document = app.document.as_mut().unwrap();
    assert_eq!(
        document.set_key_password(0, None, "new"),
        Err("This key's protection is not supported.".into())
    );
    assert!(document.secret_key(1) == Err("is not a secret key".into()));
    // It cannot be copied to another keystore either.
    let (mut target, _) = pkcs12_app(&directory, "target.p12", "changeit");
    import(&mut target, "store");
    type_password(&mut target, "changeit");
    press(&mut target, KeyCode::Enter);
    let rendered = screen(&mut target, 120, 24);
    assert!(
        rendered.contains("[-] aes | Secret key (its key cannot be read)"),
        "{rendered}"
    );
}

#[test]
fn secret_keys_are_copied_from_another_keystore() {
    let directory = TestDirectory::new();
    let (mut source, source_path) = pkcs12_app(&directory, "source.p12", "sourcepw");
    for _ in 0..2 {
        press(&mut source, KeyCode::Char('G'));
        press(&mut source, KeyCode::Enter);
        let alias = if source.entries.is_empty() {
            "one"
        } else {
            "two"
        };
        type_alias(&mut source, alias);
    }
    press(&mut source, KeyCode::Char('w'));
    assert!(!source.modified, "{:?}", source.message);
    let key = |app: &App, alias: &str| {
        let index = app.entries.iter().position(|e| e.alias == alias).unwrap();
        app.document
            .as_ref()
            .unwrap()
            .secret_key(index)
            .ok()
            .unwrap()
    };

    // Several entries keep their aliases.
    let (mut app, _) = pkcs12_app(&directory, "store.p12", "changeit");
    import(&mut app, "source");
    type_password(&mut app, "sourcepw");
    press(&mut app, KeyCode::Enter);
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("> [ ] one | Secret key"), "{rendered}");
    press(&mut app, KeyCode::Char('a'));
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.message,
        Some(("Imported 2 entries from 'source.p12'.".into(), false))
    );
    assert!(key(&app, "one") == key(&source, "one"));
    assert!(key(&app, "two") == key(&source, "two"));
    assert!(key(&app, "one") != key(&app, "two"));

    // A single entry is given its alias in the prompt.
    source
        .document
        .as_mut()
        .unwrap()
        .remove(&mut source.entries, 1);
    source.modified = true;
    press(&mut source, KeyCode::Char('w'));
    assert_eq!(pkcs12_entries(&source_path, "sourcepw").len(), 1);
    import(&mut app, "source");
    type_password(&mut app, "sourcepw");
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 24).contains("Alias for the imported secret key: one_"));
    type_alias(&mut app, "Again");
    assert_eq!(
        app.message,
        Some(("Imported secret key as 'again'.".into(), false))
    );
    assert!(key(&app, "again") == key(&source, "one"));

    // A JKS keystore rejects a single secret key up front without opening the alias prompt.
    let (mut jks, _) = editing(&directory);
    import(&mut jks, "source");
    type_password(&mut jks, "sourcepw");
    press(&mut jks, KeyCode::Enter);
    assert!(jks.alias_prompt.is_none());
    assert!(
        red_text(&mut jks).contains("a JKS keystore cannot hold secret keys"),
        "{:?}",
        jks.message
    );

    // In bulk copy into JKS, secret keys are blocked up front so 'a' copies
    // only the supported entries without partial failure.
    let cert_path = directory.path().join("extra.pem");
    fs::write(&cert_path, test_support::TRUSTED_CERT_PEM).unwrap();
    import(&mut source, "extra");
    type_alias(&mut source, "extra-cert");
    press(&mut source, KeyCode::Char('w'));
    assert_eq!(source.entries.len(), 2);

    let original_count = jks.entries.len();
    import(&mut jks, "source");
    type_password(&mut jks, "sourcepw");
    press(&mut jks, KeyCode::Enter);
    let rendered = screen(&mut jks, 120, 24);
    assert!(
        rendered.contains("[-] one | Secret key (a JKS keystore cannot hold secret keys)"),
        "{rendered}"
    );
    assert!(
        rendered.contains("[ ] extra-cert | Trusted certificate"),
        "{rendered}"
    );
    press(&mut jks, KeyCode::Char('a'));
    press(&mut jks, KeyCode::Enter);
    // Only the single non-blocked entry ('extra-cert') was chosen, so it opens the alias prompt.
    assert!(
        screen(&mut jks, 120, 24).contains("Alias for the imported certificate: extra-cert_"),
        "{:?}",
        jks.message
    );
    press(&mut jks, KeyCode::Enter);
    assert_eq!(jks.entries.len(), original_count + 1);
    assert!(jks.entries.iter().any(|e| e.alias == "extra-cert"));
    assert!(!jks.entries.iter().any(|e| e.alias == "one"));
}
