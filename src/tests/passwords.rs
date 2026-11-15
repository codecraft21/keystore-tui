use super::*;

#[test]
fn java_unicode_keystores_open_through_the_password_prompt() {
    let directory = TestDirectory::new();
    for (name, data, password, alias) in [
        (
            "unicode-password.jks",
            UNICODE_PASSWORD_JKS,
            "pässwörd-😀",
            "root-cert",
        ),
        (
            "unicode-alias.jks",
            UNICODE_ALIAS_JKS,
            "changeit",
            "certificate-😀",
        ),
        // Detected by content, so a JCEKS store named .p12 still opens.
        (
            "trusted-cert.p12",
            test_support::KEYTOOL_JCEKS,
            "changeit",
            "root-cert",
        ),
    ] {
        let path = directory.path().join(name);
        fs::write(&path, data).unwrap();
        let mut app = App::default();
        app.open_file(path.clone());
        assert!(app.password_prompt.is_some());
        assert!(app.entries.is_empty());
        type_password(&mut app, password);
        assert!(screen(&mut app, 100, 24).contains(&format!(
            "Password: {}",
            "*".repeat(password.chars().count())
        )));
        assert!(!screen(&mut app, 100, 24).contains(password));
        press(&mut app, KeyCode::Enter);
        assert!(app.password_prompt.is_none());
        assert!(app.error.is_none());
        assert_eq!(app.keystore_path, Some(path));
        assert_eq!(app.entries[0].alias, alias);
        assert!(screen(&mut app, 100, 24).contains(alias));
    }
}

#[test]
fn pkcs12_renamed_as_jks_opens_after_password_verification() {
    let directory = TestDirectory::new();
    let path = directory.path().join("renamed.jks");
    fs::write(
        &path,
        include_bytes!("../../tests/fixtures/trusted-cert.p12"),
    )
    .unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    assert!(app.password_prompt.is_some());
    type_password(&mut app, "wrong");
    press(&mut app, KeyCode::Enter);
    assert!(app.entries.is_empty());
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.keystore_path, Some(path));
    assert_eq!(app.entries[0].alias, "root-cert");
    assert!(app.warning.is_none());
}

#[test]
fn passwordless_cacerts_opens_without_a_prompt() {
    let directory = TestDirectory::new();
    let path = directory.path().join("cacerts");
    fs::write(
        &path,
        include_bytes!("../../tests/fixtures/passwordless.p12"),
    )
    .unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    assert_eq!(app.keystore_path, Some(path));
    assert!(app.password_prompt.is_none());
    assert!(app.error.is_none());
    assert_eq!(app.entries.len(), 1);
    assert_eq!(app.entries[0].alias, "root-cert");
    assert_eq!(app.entries[0].certificate, Some(fixture_summary()));
}

#[test]
fn encrypted_cacerts_without_mac_prompts_and_allows_password_retry() {
    let directory = TestDirectory::new();
    let path = directory.path().join("cacerts");
    fs::write(
        &path,
        include_bytes!("../../tests/fixtures/encrypted-no-mac.p12"),
    )
    .unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    assert!(app.password_prompt.is_some());
    assert!(app.entries.is_empty());
    type_password(&mut app, "wrong");
    press(&mut app, KeyCode::Enter);
    assert!(app.password_prompt.is_some());
    assert!(app.entries.is_empty());
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    assert!(app.password_prompt.is_none());
    assert!(app.error.is_none());
    assert_eq!(app.keystore_path, Some(path));
    assert_eq!(app.entries.len(), 1);
    assert_eq!(app.entries[0].certificate, Some(fixture_summary()));
}

#[test]
fn openssl_stores_without_mac_prompt_until_the_right_password() {
    let directory = TestDirectory::new();
    for (name, data) in [
        (
            "aes.p12",
            include_bytes!("../../tests/fixtures/openssl-no-mac-aes.p12").as_slice(),
        ),
        (
            "rc4.p12",
            include_bytes!("../../tests/fixtures/openssl-no-mac-rc4.p12").as_slice(),
        ),
    ] {
        let path = directory.path().join(name);
        fs::write(&path, data).unwrap();
        let mut app = App::default();
        app.open_file(path);
        assert!(app.password_prompt.is_some());
        // RC4 has no padding, and this password passes the AES padding check.
        type_password(&mut app, "wrong130");
        press(&mut app, KeyCode::Enter);
        assert!(app.password_prompt.is_some());
        assert!(app.entries.is_empty());
        type_password(&mut app, "changeit");
        press(&mut app, KeyCode::Enter);
        assert!(app.password_prompt.is_none());
        assert_eq!(app.entries.len(), 1);
        assert!(app.warning.is_none());
    }
}

#[test]
fn reopening_and_cancelling_preserves_the_previous_keystore() {
    let directory = TestDirectory::new();
    let original = directory.path().join("a.jks");
    fs::write(&original, empty_keystore()).unwrap();
    fs::write(directory.path().join("b.jks"), empty_keystore()).unwrap();
    let original = canonical_path::canonicalize(&original).unwrap();
    let mut app = App {
        keystore_path: Some(original.clone()),
        ..App::default()
    };

    assert!(!press(&mut app, KeyCode::Char('o')));
    assert!(screen(&mut app, 200, 24).contains("b.jks"));
    press(&mut app, KeyCode::End);
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.file_picker.is_none());
    assert!(screen(&mut app, 200, 24).contains(&format!("Path: '{}'", original.display())));
    assert_eq!(app.keystore_path, Some(original));

    app.handle_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL));
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.keystore_path,
        Some(canonical_path::canonicalize(&directory.path().join("b.jks")).unwrap())
    );
}

#[test]
fn password_is_masked_and_failed_verification_can_be_retried() {
    let directory = TestDirectory::new();
    fs::write(directory.path().join("valid.jks"), mixed_keystore()).unwrap();
    let mut app = browsing(directory.path());
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    type_password(&mut app, "wrong-q");
    let content = screen(&mut app, 100, 24);
    assert!(content.contains("Password: *******"));
    assert!(!content.contains("wrong-q"));

    press(&mut app, KeyCode::Enter);
    assert!(app.keystore_path.is_none());
    assert!(app.entries.is_empty());
    assert!(app.password_prompt.as_ref().unwrap().password.0.is_empty());
    assert!(red_text(&mut app).contains("Incorrect password or keystore integrity check failed"));
    assert!(!screen(&mut app, 100, 24).contains("root-cert"));

    type_password(&mut app, "changeit!");
    press(&mut app, KeyCode::Backspace);
    press(&mut app, KeyCode::Enter);
    assert!(app.password_prompt.is_none());
    assert_eq!(app.entries.len(), 2);
    assert!(app.error.is_none());
}

#[test]
fn cancelling_a_password_prompt_preserves_the_loaded_entries() {
    let directory = TestDirectory::new();
    let original = directory.path().join("a-original.jks");
    fs::write(&original, mixed_keystore()).unwrap();
    fs::write(directory.path().join("b-other.jks"), KEYTOOL_JKS).unwrap();
    let mut app = browsing(directory.path());
    press(&mut app, KeyCode::Enter);
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);

    press(&mut app, KeyCode::Char('o'));
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    type_password(&mut app, "partial");
    let other = canonical_path::canonicalize(&directory.path().join("b-other.jks")).unwrap();
    assert!(screen(&mut app, 200, 24).contains(&format!("Path: '{}'", other.display())));
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.password_prompt.is_none());
    assert_eq!(
        app.keystore_path,
        Some(canonical_path::canonicalize(&original).unwrap())
    );
    assert!(screen(&mut app, 200, 24).contains(&format!(
        "Path: '{}'",
        canonical_path::canonicalize(&original).unwrap().display()
    )));
    assert_eq!(app.entries.len(), 2);
    assert!(screen(&mut app, 100, 24).contains("server-key"));
    press(&mut app, KeyCode::Enter);
    assert!(app.entry_details.is_some());
    assert!(screen(&mut app, 200, 30).contains(&format!(
        "Path: '{}'",
        canonical_path::canonicalize(&original).unwrap().display()
    )));
    press(&mut app, KeyCode::Esc);

    press(&mut app, KeyCode::Char('o'));
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    assert!(app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
}
