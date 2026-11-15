use super::*;

#[test]
fn a_ca_reply_replaces_the_chain_of_its_private_key() {
    use crate::test_support::{ed25519_certificate, ed25519_pkcs8};
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    let write = |name: &str, data: String| fs::write(directory.path().join(name), data).unwrap();
    let key = ed25519_pkcs8(7);
    let own = ed25519_certificate("leaf", "leaf", 7, 7);
    let leaf = ed25519_certificate("leaf", "ca", 7, 9);
    let ca = ed25519_certificate("ca", "ca", 9, 9);
    let other = ed25519_certificate("other", "other", 5, 5);
    write("bare.pem", key_pem("CERTIFICATE", &leaf, &[]));
    write("full.pem", key_pem("CERTIFICATE", &ca, &[&leaf]));
    write("other.pem", key_pem("CERTIFICATE", &other, &[]));
    write("none.pem", key_pem("CERTIFICATE REQUEST", &[0x30, 0], &[]));

    // Only a private key that the keystore's password unlocks takes a reply.
    press(&mut app, KeyCode::Char('R'));
    assert!(red_text(&mut app).contains("Only a private key takes a CA reply"));
    select(&mut app, "server-key");
    press(&mut app, KeyCode::Char('R'));
    assert!(red_text(&mut app).contains("No reply imported: the key 'server-key'"));
    assert!(app.file_picker.is_none() && app.reply.is_none());

    let document = app.document.as_mut().unwrap();
    let to = document
        .import_key_pair(
            &mut app.entries,
            "leaf".into(),
            &key,
            std::slice::from_ref(&own),
        )
        .unwrap();
    app.select_changed(to);
    app.modified = true;
    press(&mut app, KeyCode::Char('w'));
    assert!(!app.modified, "{:?}", app.message);
    let created = |path: &Path| {
        let (_, writable) = keystore::parse(fs::read(path).unwrap())
            .unwrap()
            .open("changeit")
            .ok()
            .unwrap();
        writable.created(0)
    };
    let first_created = created(&path);

    // Esc in the browser gives up.
    press(&mut app, KeyCode::Char('R'));
    assert!(screen(&mut app, 120, 24).contains(" CA reply for 'leaf' "));
    press(&mut app, KeyCode::Esc);
    assert!(app.file_picker.is_none() && app.reply.is_none());

    // Files without a certificate for this key change nothing.
    reply(&mut app, "none");
    assert!(red_text(&mut app).contains("'none.pem' holds no certificate."));
    reply(&mut app, "other");
    assert!(red_text(&mut app).contains(
        "No reply imported: no certificate in 'other.pem' holds the public key of 'leaf'."
    ));
    app.import_reply(to, &directory.path().join("missing.pem"));
    assert!(red_text(&mut app).contains("Cannot read"));
    assert!(!app.modified);
    assert_eq!(app.entries[to].certificates(), [own]);

    // A reply with the certificate alone: no issuer is held, so the chain
    // is that certificate.
    reply(&mut app, "bare");
    assert_eq!(
        app.message,
        Some((
            "Replaced the certificate chain of 'leaf' with the certificate from 'bare.pem'.".into(),
            false
        ))
    );
    assert!(app.modified);
    assert_eq!(app.entries[to].certificates(), std::slice::from_ref(&leaf));
    assert_eq!(selected_alias(&app), "leaf");
    // The full reply brings the issuer, whatever the order in the file.
    reply(&mut app, "full");
    assert!(
        screen(&mut app, 200, 24)
            .contains("Replaced the certificate chain of 'leaf' with the 2 certificates from")
    );
    assert_eq!(app.entries[to].certificates(), [leaf.clone(), ca.clone()]);
    press(&mut app, KeyCode::Char('w'));
    assert!(!app.modified, "{:?}", app.message);
    assert_eq!(
        app.entries,
        keystore::load_entries(&fs::read(&path).unwrap(), "changeit").unwrap()
    );
    // The key and its creation date are as they were.
    assert_eq!(saved_key(&path, 0, "changeit"), Ok(key));
    assert_eq!(created(&path), first_created);

    // The same reply again changes nothing, and with the issuer in the
    // keystore the certificate alone gives the same chain.
    for name in ["full", "bare"] {
        reply(&mut app, name);
        assert_eq!(
            app.message,
            Some((
                format!("'leaf' already has the chain in '{name}.pem'; nothing changed."),
                false
            ))
        );
        assert!(!app.modified);
    }

    // A keystore closed in between has no key to give the chain to.
    app.document = None;
    app.import_reply(to, &directory.path().join("full.pem"));
    assert!(red_text(&mut app).contains("No keystore is open."));
}

#[test]
fn a_ca_reply_replaces_the_chain_in_a_pkcs12_keystore() {
    use crate::test_support::{TestRng, ed25519_certificate, ed25519_pkcs8};
    let directory = TestDirectory::new();
    let key = ed25519_pkcs8(7);
    let own = ed25519_certificate("leaf", "leaf", 7, 7);
    let old_ca = ed25519_certificate("old", "old", 8, 8);
    let old = ed25519_certificate("leaf", "old", 7, 8);
    let leaf = ed25519_certificate("leaf", "ca", 7, 9);
    let ca = ed25519_certificate("ca", "ca", 9, 9);
    fs::write(
        directory.path().join("reply.pem"),
        key_pem("CERTIFICATE", &leaf, &[&ca]),
    )
    .unwrap();
    let mut rng = TestRng(1);
    let mut store = pkcs12::Writable::empty("changeit");
    store
        .insert_private_key("first", &key, &[old.clone(), old_ca.clone()], &mut rng)
        .unwrap();
    let path = directory.path().join("store.p12");
    fs::write(&path, store.encode(&mut rng).unwrap()).unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.entries[0].certificates(), [old, old_ca.clone()]);

    reply(&mut app, "reply");
    assert!(app.modified, "{:?}", app.message);
    assert_eq!(app.entries.len(), 1);
    assert_eq!(app.entries[0].certificates(), [leaf.clone(), ca.clone()]);
    press(&mut app, KeyCode::Char('w'));
    assert!(!app.modified, "{:?}", app.message);
    assert_eq!(app.entries, pkcs12_entries(&path, "changeit"));
    let data = fs::read(&path).unwrap();
    let (_, saved) = pkcs12::parse(&data).unwrap().open("changeit").ok().unwrap();
    assert_eq!(saved.unwrap().private_key(0).unwrap().as_slice(), key);
    // The old issuer, which nothing else uses, is gone from the file.
    let certificates = |password: &str| {
        pkcs12::parse(&data)
            .unwrap()
            .verify(password)
            .unwrap()
            .entries
            .len()
    };
    assert_eq!(certificates("changeit"), 1);

    // A certificate pairs with one key only: a second key with the same
    // public key cannot take the reply the first one has.
    let document = app.document.as_mut().unwrap();
    let second = document
        .import_key_pair(&mut app.entries, "second".into(), &key, &[own])
        .unwrap();
    app.select_changed(second);
    reply(&mut app, "reply");
    assert!(
        red_text(&mut app)
            .contains("Not replaced: the certificate already belongs to the key 'first'.")
    );
    // A chain that is not linked by issuer names would not be listed again.
    let document = app.document.as_mut().unwrap();
    let unlinked = [ed25519_certificate("leaf", "gone", 7, 6), old_ca];
    let error = document
        .replace_chain(&mut app.entries, second, &unlinked)
        .unwrap_err();
    assert!(error.contains("would not list this chain again"), "{error}");
    assert_eq!(
        document.replace_chain(&mut app.entries, second, &[]),
        Err("Not replaced: the chain is empty.".into())
    );
    assert_eq!(app.entries.len(), 2);
}

/// Appends the certificate in the file starting with `name` to the chain of
/// the selected key.
fn append(app: &mut App, name: &str) {
    press(app, KeyCode::Char('C'));
    press(app, KeyCode::Char('a'));
    type_password(app, name);
    press(app, KeyCode::Enter);
}

#[test]
fn a_chain_is_edited_one_certificate_at_a_time() {
    use crate::test_support::{ed25519_certificate, ed25519_pkcs8};
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    let write = |name: &str, data: String| fs::write(directory.path().join(name), data).unwrap();
    let leaf = ed25519_certificate("leaf", "issuing", 7, 8);
    let issuing = ed25519_certificate("issuing", "root", 8, 9);
    let root = ed25519_certificate("root", "root", 9, 9);
    let other = ed25519_certificate("other", "other", 5, 5);
    write("issuing.pem", key_pem("CERTIFICATE", &issuing, &[]));
    write("root.pem", key_pem("CERTIFICATE", &root, &[]));
    write("other.pem", key_pem("CERTIFICATE", &other, &[]));
    write("two.pem", key_pem("CERTIFICATE", &issuing, &[&root]));

    // Only a private key has a chain to edit.
    press(&mut app, KeyCode::Char('C'));
    assert!(red_text(&mut app).contains("Only a private key has a certificate chain to edit."));
    assert!(app.chain_menu.is_none());

    let document = app.document.as_mut().unwrap();
    let to = document
        .import_key_pair(
            &mut app.entries,
            "leaf".into(),
            &ed25519_pkcs8(7),
            std::slice::from_ref(&leaf),
        )
        .unwrap();
    app.select_changed(to);
    press(&mut app, KeyCode::Char('C'));
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("Chain of 'leaf': 1 certificate "));
    assert!(rendered.contains("a Append from file | x Remove last | Esc Cancel | Ctrl+C Quit"));
    // Other keys, `q` among them, do nothing here; Esc leaves.
    assert!(!press(&mut app, KeyCode::Char('q')));
    assert!(app.chain_menu.is_some());
    press(&mut app, KeyCode::Esc);
    assert!(app.chain_menu.is_none());
    // The key's own certificate stays.
    press(&mut app, KeyCode::Char('C'));
    press(&mut app, KeyCode::Char('x'));
    assert!(red_text(&mut app).contains("The chain holds only the key's own certificate"));
    assert!(app.chain_menu.is_none() && !app.modified);

    // Esc in the browser gives up.
    press(&mut app, KeyCode::Char('C'));
    press(&mut app, KeyCode::Char('a'));
    assert!(screen(&mut app, 120, 24).contains(" Certificate to append to the chain of 'leaf' "));
    press(&mut app, KeyCode::Esc);
    assert!(app.file_picker.is_none() && app.appending.is_none());

    // Only the issuer of the last certificate is appended, from a file
    // with that one certificate.
    append(&mut app, "other");
    assert!(red_text(&mut app).contains("'other' did not issue 'leaf'"));
    append(&mut app, "root");
    assert!(red_text(&mut app).contains("'root' did not issue 'leaf'"));
    append(&mut app, "two");
    assert!(red_text(&mut app).contains("holds 2 certificates"));
    app.append_to_chain(to, &directory.path().join("missing.pem"));
    assert!(red_text(&mut app).contains("Cannot read"));
    assert!(!app.modified);

    append(&mut app, "issuing");
    assert_eq!(
        app.message,
        Some(("Appended 'issuing' to the chain of 'leaf'.".into(), false))
    );
    assert!(app.modified);
    assert_eq!(selected_alias(&app), "leaf");
    append(&mut app, "issuing");
    assert!(red_text(&mut app).contains("'issuing' is already in the chain."));
    append(&mut app, "root");
    assert_eq!(
        app.entries[to].certificates(),
        [leaf.clone(), issuing.clone(), root]
    );
    press(&mut app, KeyCode::Char('C'));
    assert!(screen(&mut app, 120, 24).contains("Chain of 'leaf': 3 certificates "));
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Char('w'));
    assert!(!app.modified, "{:?}", app.message);
    assert_eq!(
        app.entries,
        keystore::load_entries(&fs::read(&path).unwrap(), "changeit").unwrap()
    );

    press(&mut app, KeyCode::Char('C'));
    press(&mut app, KeyCode::Char('x'));
    assert_eq!(
        app.message,
        Some(("Removed 'root' from the chain of 'leaf'.".into(), false))
    );
    assert!(app.modified);
    assert_eq!(app.entries[to].certificates(), [leaf, issuing]);

    // A keystore closed in between has no chain to change.
    app.document = None;
    app.append_to_chain(to, &directory.path().join("root.pem"));
    assert!(red_text(&mut app).contains("No keystore is open."));
}

#[test]
fn a_pkcs12_chain_is_edited_as_far_as_it_is_listed_again() {
    use crate::test_support::{TestRng, ed25519_certificate, ed25519_pkcs8};
    let directory = TestDirectory::new();
    let leaf = ed25519_certificate("leaf", "issuing", 7, 8);
    let issuing = ed25519_certificate("issuing", "root", 8, 9);
    let root = ed25519_certificate("root", "root", 9, 9);
    for (name, certificate) in [("issuing.pem", &issuing), ("root.pem", &root)] {
        fs::write(
            directory.path().join(name),
            key_pem("CERTIFICATE", certificate, &[]),
        )
        .unwrap();
    }
    let mut rng = TestRng(1);
    let mut store = pkcs12::Writable::empty("changeit");
    store
        .insert_private_key(
            "leaf",
            &ed25519_pkcs8(7),
            std::slice::from_ref(&leaf),
            &mut rng,
        )
        .unwrap();
    let path = directory.path().join("store.p12");
    fs::write(&path, store.encode(&mut rng).unwrap()).unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);

    append(&mut app, "issuing");
    assert!(app.modified, "{:?}", app.message);
    assert_eq!(
        app.entries[0].certificates(),
        [leaf.clone(), issuing.clone()]
    );
    press(&mut app, KeyCode::Char('w'));
    assert!(!app.modified, "{:?}", app.message);
    assert_eq!(app.entries, pkcs12_entries(&path, "changeit"));

    // PKCS12 lists a chain from the certificates it holds: a trusted root
    // joins the chain by itself, and cannot be taken out of it.
    press(&mut app, KeyCode::Char('i'));
    type_password(&mut app, "root");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.entries.len(), 2, "{:?}", app.message);
    select(&mut app, "leaf");
    let chain = [leaf.clone(), issuing.clone(), root];
    assert_eq!(app.entries[0].certificates(), chain);
    press(&mut app, KeyCode::Char('C'));
    press(&mut app, KeyCode::Char('x'));
    assert!(red_text(&mut app).contains("the keystore would not list this chain again"));
    assert_eq!(app.entries[0].certificates(), chain);

    // Without the trusted root, the last certificate comes off.
    select(&mut app, "root");
    press(&mut app, KeyCode::Char('d'));
    press(&mut app, KeyCode::Char('y'));
    select(&mut app, "leaf");
    assert_eq!(app.entries[0].certificates(), [leaf.clone(), issuing]);
    press(&mut app, KeyCode::Char('C'));
    press(&mut app, KeyCode::Char('x'));
    assert_eq!(
        app.message,
        Some(("Removed 'issuing' from the chain of 'leaf'.".into(), false))
    );
    assert_eq!(app.entries[0].certificates(), [leaf]);
    press(&mut app, KeyCode::Char('w'));
    assert_eq!(app.entries, pkcs12_entries(&path, "changeit"));
}
