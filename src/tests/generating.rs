use super::*;

/// Fills in the form for a new key pair named `name` and confirms it.
fn fill_key_pair_form(app: &mut App, name: &str) {
    press(app, KeyCode::Char('g'));
    press(app, KeyCode::Down);
    type_password(app, name);
    press(app, KeyCode::Enter);
}

#[test]
fn generating_a_key_pair_adds_a_private_key_entry() {
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);

    press(&mut app, KeyCode::Char('g'));
    let rendered = screen(&mut app, 120, 30);
    assert!(rendered.contains(" Generate key pair "));
    assert!(rendered.contains("Up/Down Tab Field | Left/Right Change | Enter Next"));
    // Esc closes the form, and letters are typed into it.
    press(&mut app, KeyCode::Esc);
    assert!(app.generating.is_none() && !app.modified);
    press(&mut app, KeyCode::Char('g'));
    press(&mut app, KeyCode::Down);
    for ch in "Q.test".chars() {
        assert!(!press(&mut app, KeyCode::Char(ch)));
    }
    assert!(screen(&mut app, 120, 30).contains("Common name (CN)     Q.test_"));

    // The alias is asked before the key is generated; Esc goes back to the
    // form as it was filled in.
    press(&mut app, KeyCode::Enter);
    assert!(app.generating.is_none());
    assert!(screen(&mut app, 120, 30).contains("Alias for the generated key pair: q.test_"));
    press(&mut app, KeyCode::Esc);
    assert!(app.alias_prompt.is_none());
    assert!(screen(&mut app, 120, 30).contains("Common name (CN)     Q.test_"));
    press(&mut app, KeyCode::Enter);
    type_alias(&mut app, "ROOT-cert");
    assert!(red_text(&mut app).contains("An entry named 'root-cert' already exists."));
    assert!(app.generation.is_none() && !app.finish_generation());

    type_alias(&mut app, "New");
    assert!(app.alias_prompt.is_none() && !app.modified);
    let waiting = buffer(&mut app, 120, 30);
    let cyan: String = waiting
        .content
        .iter()
        .filter(|cell| cell.fg == Color::Cyan)
        .map(|cell| cell.symbol())
        .collect();
    assert!(
        cyan.contains("Generating EC P-256 key pair 'new'..."),
        "{cyan}"
    );
    assert!(app.finish_generation());
    assert!(!app.finish_generation());
    assert_eq!(
        app.message,
        Some(("Generated EC P-256 key pair 'new'.".into(), false))
    );
    assert!(app.modified);
    let generated = &app.entries[app.selected_entry().unwrap()];
    assert_eq!(
        (generated.alias.as_str(), generated.kind()),
        ("new", "Private key")
    );
    let summary = generated.certificate.as_ref().unwrap();
    assert_eq!(
        (summary.subject.as_str(), summary.algorithm.as_str()),
        ("CN=Q.test", "EC")
    );
    let chain = generated.certificates().to_vec();
    assert_eq!(chain.len(), 1);

    // The key is written on save, protected with the keystore's password.
    press(&mut app, KeyCode::Char('w'));
    assert!(!app.modified, "{:?}", app.message);
    assert_eq!(aliases(&path), ["new", "root-cert", "server-key"]);
    let key = saved_key(&path, 0, "changeit").unwrap();
    assert_eq!(
        key_import::matching_chain(&key, std::slice::from_ref(&chain)),
        Ok(Some(chain))
    );
    assert_eq!(
        app.entries,
        keystore::load_entries(&fs::read(&path).unwrap(), "changeit").unwrap()
    );
}

#[test]
fn key_pairs_are_generated_into_pkcs12_keystores_with_a_password() {
    let directory = TestDirectory::new();
    let mut rng = test_support::TestRng(1);
    let mut app = App::default();
    for (name, password) in [("store.p12", "changeit"), ("open.p12", "")] {
        let path = directory.path().join(name);
        fs::write(
            &path,
            pkcs12::Writable::empty(password).encode(&mut rng).unwrap(),
        )
        .unwrap();
        app.open_file(path.clone());
        type_password(&mut app, password);
        press(&mut app, KeyCode::Enter);
        assert!(app.document.is_some());
        fill_key_pair_form(&mut app, "host.test");
        if password.is_empty() {
            press(&mut app, KeyCode::Enter);
            assert!(app.finish_generation());
            assert!(red_text(&mut app).contains("a key needs a keystore password"));
            assert!(app.entries.is_empty() && !app.modified);
            continue;
        }
        press(&mut app, KeyCode::Enter);
        assert!(app.finish_generation(), "{:?}", app.message);
        assert_eq!(
            app.message,
            Some(("Generated EC P-256 key pair 'host.test'.".into(), false))
        );
        press(&mut app, KeyCode::Char('w'));
        assert!(!app.modified, "{:?}", app.message);
        assert_eq!(app.entries, pkcs12_entries(&path, password));
        assert_eq!(app.entries[0].kind(), "Private key");
    }

    // A keystore closed in between has nowhere to put the key pair.
    fill_key_pair_form(&mut app, "late.test");
    press(&mut app, KeyCode::Enter);
    app.document = None;
    assert!(app.finish_generation());
    assert!(red_text(&mut app).contains("No keystore is open."));
}

#[test]
fn a_certificate_request_is_made_for_a_private_key() {
    use crown::x509::csr::CertificationRequest;
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    let stored = fs::read(&path).unwrap();

    // Only a private key that the keystore's password unlocks can sign.
    press(&mut app, KeyCode::Char('c'));
    assert!(red_text(&mut app).contains("Only a private key can sign a certificate request."));
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Char('c'));
    assert!(red_text(&mut app).contains("No request made: the key 'server-key'"));
    assert!(app.requesting.is_none());

    fill_key_pair_form(&mut app, "Host.test");
    press(&mut app, KeyCode::Enter);
    assert!(app.finish_generation(), "{:?}", app.message);
    press(&mut app, KeyCode::Char('c'));
    let rendered = screen(&mut app, 120, 30);
    assert!(rendered.contains(" Certificate request for 'host.test' "));
    assert!(rendered.contains("Common name (CN)     Host.test_"));
    assert!(rendered.contains("Up/Down Tab Field | Left/Right Change | Enter Next"));
    // Letters are typed into the form, and Esc closes it.
    assert!(!press(&mut app, KeyCode::Char('q')));
    press(&mut app, KeyCode::Esc);
    assert!(app.requesting.is_none());

    // The file name is asked next; Esc goes back to the form.
    press(&mut app, KeyCode::Char('c'));
    press(&mut app, KeyCode::Enter);
    let expected = directory.path().join("host.test.csr");
    let rendered = screen(&mut app, 200, 30);
    assert!(rendered.contains(&format!(
        "Save certificate request as: {} ",
        expected.display()
    )));
    assert!(rendered.contains("A .der name saves DER, any other PEM | Enter Save"));
    assert!(!rendered.contains(" Certificate request for 'host.test' "));
    press(&mut app, KeyCode::Esc);
    assert!(screen(&mut app, 120, 30).contains(" Certificate request for 'host.test' "));
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.message,
        Some((
            format!(
                "Saved a certificate request for 'host.test' to '{}'.",
                expected.display()
            ),
            false
        ))
    );
    assert!(app.requesting.is_none());
    let text = fs::read_to_string(&expected).unwrap();
    assert!(text.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
    let request = CertificationRequest::from_pem(&text).unwrap();
    assert_eq!(request.verify_signature(), Ok(true));
    assert_eq!(request.info().subject.common_name().unwrap(), "Host.test");
    // The request holds the public key of the entry's certificate.
    let leaf = &app.entries[app.selected_entry().unwrap()].certificates()[0];
    assert_eq!(
        request.info().subject_public_key_info.encode(),
        crown::x509::cert::Certificate::parse(leaf)
            .unwrap()
            .subject_public_key_info()
            .encode()
    );
    // The keystore file is not touched.
    assert_eq!(fs::read(&path).unwrap(), stored);

    // A .der name writes DER, and an existing file is never replaced.
    press(&mut app, KeyCode::Char('c'));
    press(&mut app, KeyCode::Enter);
    type_alias(&mut app, "request.der");
    let der = fs::read(directory.path().join("request.der")).unwrap();
    assert_eq!(
        CertificationRequest::parse(&der)
            .unwrap()
            .verify_signature(),
        Ok(true)
    );
    press(&mut app, KeyCode::Char('c'));
    press(&mut app, KeyCode::Enter);
    type_alias(&mut app, "request.der");
    assert!(red_text(&mut app).contains("already exists; choose another name."));
    assert!(app.requesting.is_some());
    // A keystore closed in between has no key to sign with.
    app.document = None;
    type_alias(&mut app, "late.csr");
    assert!(red_text(&mut app).contains("No keystore is open."));
    assert!(!directory.path().join("late.csr").exists());
}

#[test]
fn a_request_needs_a_readable_key_and_certificate() {
    let directory = TestDirectory::new();
    let (mut app, _) = editing(&directory);
    // A key whose certificate is not a certificate.
    let key = test_support::ed25519_pkcs8(4);
    app.document
        .as_mut()
        .unwrap()
        .import_key_pair(&mut app.entries, "broken".into(), &key, &[vec![0x30, 0]])
        .unwrap();
    app.refresh_visible();
    press(&mut app, KeyCode::Char('c'));
    assert!(red_text(&mut app).contains("No request made: the key's certificate cannot be read."));

    // A key that stops being readable after the form is not signed with.
    let leaf = test_support::ed25519_certificate("late", "late", 6, 6);
    let to = app
        .document
        .as_mut()
        .unwrap()
        .import_key_pair(
            &mut app.entries,
            "late".into(),
            &test_support::ed25519_pkcs8(6),
            &[leaf],
        )
        .unwrap();
    app.refresh_visible();
    let row = app.visible.iter().position(|&index| index == to).unwrap();
    app.entries_state.select(Some(row));
    press(&mut app, KeyCode::Char('c'));
    assert!(app.requesting.is_some(), "{:?}", app.message);
    press(&mut app, KeyCode::Enter);
    // Deleting the two entries before it puts a key that does not open,
    // 'server-key', at the place the request was started for.
    assert_eq!(to, 1);
    let document = app.document.as_mut().unwrap();
    document.remove(&mut app.entries, 0);
    document.remove(&mut app.entries, 0);
    assert_eq!(app.entries[to].alias, "server-key");
    app.refresh_visible();
    press(&mut app, KeyCode::Enter);
    assert!(
        red_text(&mut app).contains("No request made: the key '"),
        "{:?}",
        app.message
    );
}
