use super::*;

/// Adds a certificate authority, `ca`, with the Ed25519 key `[9; 32]`, and
/// selects it. Returns its certificate.
fn add_authority(app: &mut App) -> Vec<u8> {
    let key = test_support::ed25519_pkcs8(9);
    let asked = signing::Request {
        subject: signing::Subject {
            common_name: "Test CA",
            ..signing::Subject::default()
        }
        .name(),
        days: 30,
        names: Vec::new(),
        purpose: signing::Purpose::CertificateAuthority,
    };
    let certificate =
        signing::self_signed(&key, &asked, 1_767_225_600, &mut test_support::TestRng(0)).unwrap();
    let document = app.document.as_mut().unwrap();
    let to = document
        .import_key_pair(
            &mut app.entries,
            "ca".into(),
            &key,
            std::slice::from_ref(&certificate),
        )
        .unwrap();
    app.select_changed(to);
    certificate
}

/// Chooses the file starting with `name` as the request the selected key
/// signs.
fn sign_request(app: &mut App, name: &str) {
    press(app, KeyCode::Char('S'));
    press(app, KeyCode::Char('r'));
    type_password(app, name);
    press(app, KeyCode::Enter);
}

#[test]
fn a_certificate_request_is_signed_into_a_new_certificate_file() {
    use crown::x509::{cert::Certificate, csr::CertificationRequest};
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    let file = |name: &str| directory.path().join(name);
    fs::write(file("device.csr"), test_support::KEYTOOL_REQUEST).unwrap();
    fs::write(file("none.pem"), test_support::TRUSTED_CERT_PEM).unwrap();
    let asked = test_support::ed25519_request("device", &[]);
    fs::write(file("trailing.der"), [&asked[..], &[0]].concat()).unwrap();

    // Only a private key that the keystore's password unlocks signs.
    press(&mut app, KeyCode::Char('S'));
    assert!(red_text(&mut app).contains("Only a private key can sign certificates."));
    select(&mut app, "server-key");
    press(&mut app, KeyCode::Char('S'));
    assert!(red_text(&mut app).contains("Nothing signed: the key 'server-key'"));
    assert!(app.sign_menu.is_none());

    let ca = add_authority(&mut app);
    app.modified = true;
    press(&mut app, KeyCode::Char('w'));
    assert!(!app.modified, "{:?}", app.message);
    let stored = fs::read(&path).unwrap();

    // The menu takes r, g, and Esc; other keys, such as q, do nothing.
    press(&mut app, KeyCode::Char('S'));
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("Sign with 'ca': "));
    assert!(rendered.contains(
        "r Request file | g New key pair | l Revocation list | Esc Cancel | Ctrl+C Quit"
    ));
    assert!(!rendered.contains("Warning"));
    assert!(!press(&mut app, KeyCode::Char('q')));
    assert!(app.sign_menu.is_some());
    press(&mut app, KeyCode::Esc);
    assert!(app.sign_menu.is_none());
    app.handle_sign_menu(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
    assert!(app.file_picker.is_none());

    // Esc in the browser gives up.
    press(&mut app, KeyCode::Char('S'));
    press(&mut app, KeyCode::Char('r'));
    assert!(screen(&mut app, 120, 24).contains(" Certificate request to sign with 'ca' "));
    press(&mut app, KeyCode::Esc);
    assert!(app.file_picker.is_none() && app.signing_request.is_none());

    // Files without a single readable request are not signed.
    sign_request(&mut app, "none");
    assert!(red_text(&mut app).contains("'none.pem' holds no certificate request."));
    app.sign_request_file(0, &file("missing.csr"));
    assert!(red_text(&mut app).contains("Cannot read"));
    sign_request(&mut app, "trailing");
    assert!(app.signing.is_none());
    assert!(red_text(&mut app).contains("'trailing.der' holds no certificate request."));

    sign_request(&mut app, "device");
    let rendered = screen(&mut app, 120, 30);
    for expected in [
        " Sign request with 'ca' ",
        "Subject              O=keystore-tui,CN=CSR TUI test fixture",
        "Public key           EC 256 bits",
        "[x] Subject Alternative Name: DNS: csr.example.test",
        "Up/Down Tab Field | Left/Right Space Change | Enter Next",
    ] {
        assert!(rendered.contains(expected), "missing {expected:?}");
    }
    // Letters are typed into the form, and Esc closes it.
    assert!(!press(&mut app, KeyCode::Char('q')));
    press(&mut app, KeyCode::Esc);
    assert!(app.signing.is_none());

    // The file name is asked next; Esc goes back to the form.
    sign_request(&mut app, "device");
    press(&mut app, KeyCode::Down);
    type_password(&mut app, "01a4");
    press(&mut app, KeyCode::Enter);
    let expected = file("device.pem");
    let rendered = screen(&mut app, 200, 30);
    assert!(rendered.contains(&format!("Save certificate as: {} ", expected.display())));
    assert!(rendered.contains("A .der name saves DER, any other PEM | Enter Save"));
    press(&mut app, KeyCode::Esc);
    assert!(screen(&mut app, 120, 30).contains("Serial number (hex)  01a4_"));
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.message,
        Some((
            format!(
                "Signed the request in 'device.csr' with 'ca' and saved the certificate to '{}'.",
                expected.display()
            ),
            false
        ))
    );
    assert!(app.signing.is_none());

    // The file holds the new certificate, then the signer's chain.
    let blocks = crown::asn1::pem::parse(&fs::read_to_string(&expected).unwrap()).unwrap();
    assert_eq!(blocks.len(), 2);
    assert!(blocks.iter().all(|block| block.label == "CERTIFICATE"));
    assert_eq!(blocks[1].data, ca);
    let issued = Certificate::parse(&blocks[0].data).unwrap();
    let authority = Certificate::parse(&ca).unwrap();
    assert_eq!(issued.verify_signature(authority.public_key()), Ok(true));
    assert_eq!(issued.issuer().encode(), authority.subject().encode());
    assert_eq!(issued.serial_number(), [1, 0xa4]);
    let request =
        CertificationRequest::from_pem(std::str::from_utf8(test_support::KEYTOOL_REQUEST).unwrap())
            .unwrap();
    assert_eq!(issued.subject().encode(), request.info().subject.encode());
    assert_eq!(
        issued.subject_public_key_info().encode(),
        request.info().subject_public_key_info.encode()
    );
    assert_eq!(
        issued
            .tbs()
            .subject_alt_names()
            .unwrap()
            .iter()
            .filter_map(|name| name.to_text())
            .collect::<Vec<_>>(),
        ["csr.example.test"]
    );
    assert_eq!(
        issued
            .tbs()
            .authority_key_identifier()
            .unwrap()
            .key_identifier,
        authority.tbs().subject_key_identifier()
    );
    // The keystore is not changed.
    assert!(!app.modified);
    assert_eq!(fs::read(&path).unwrap(), stored);

    // A chain does not fit a DER file; the certificate alone does.
    sign_request(&mut app, "device");
    press(&mut app, KeyCode::Enter);
    type_alias(&mut app, "only.der");
    assert!(red_text(&mut app).contains("use a .pem name for the chain"));
    assert!(app.signing.is_some());
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Enter);
    type_alias(&mut app, "only.der");
    assert!(app.signing.is_none(), "{:?}", app.message);
    let only = Certificate::parse(&fs::read(file("only.der")).unwrap()).unwrap();
    assert_eq!(only.verify_signature(authority.public_key()), Ok(true));
    assert_eq!(only.serial_number().len(), 16);

    // An existing file is never replaced.
    sign_request(&mut app, "device");
    press(&mut app, KeyCode::Enter);
    type_alias(&mut app, "device.pem");
    assert!(red_text(&mut app).contains("already exists; choose another name."));
    // A keystore closed in between has no key to sign with.
    app.document = None;
    type_alias(&mut app, "late.pem");
    assert!(red_text(&mut app).contains("No keystore is open."));
    assert!(!file("late.pem").exists());
}

#[test]
fn signing_needs_a_readable_key_and_certificate_and_warns_without_a_ca() {
    let directory = TestDirectory::new();
    let (mut app, _) = editing(&directory);
    fs::write(
        directory.path().join("device.csr"),
        test_support::KEYTOOL_REQUEST,
    )
    .unwrap();
    // A key whose certificate is not a certificate.
    let key = test_support::ed25519_pkcs8(4);
    let document = app.document.as_mut().unwrap();
    let to = document
        .import_key_pair(&mut app.entries, "broken".into(), &key, &[vec![0x30, 0]])
        .unwrap();
    app.select_changed(to);
    press(&mut app, KeyCode::Char('S'));
    assert!(red_text(&mut app).contains("Nothing signed: the key's certificate cannot be read."));
    assert!(app.sign_warning(to).is_none());

    // A certificate that is not a CA's signs with a warning.
    let leaf = test_support::ed25519_certificate("late", "late", 6, 6);
    let document = app.document.as_mut().unwrap();
    let to = document
        .import_key_pair(
            &mut app.entries,
            "late".into(),
            &test_support::ed25519_pkcs8(6),
            &[leaf],
        )
        .unwrap();
    app.select_changed(to);
    press(&mut app, KeyCode::Char('S'));
    let shown = buffer(&mut app, 120, 24);
    let yellow: String = shown
        .content
        .iter()
        .filter(|cell| cell.fg == Color::Yellow)
        .map(|cell| cell.symbol())
        .collect();
    assert!(yellow.contains("Warning: its certificate is not a CA certificate."));
    press(&mut app, KeyCode::Esc);

    // A key that stops being readable after the form is not signed with.
    sign_request(&mut app, "device");
    assert!(app.signing.is_some(), "{:?}", app.message);
    press(&mut app, KeyCode::Enter);
    // Deleting the two entries before it puts a key that does not open,
    // 'server-key', at the place the signing was started for.
    assert_eq!(to, 1);
    let document = app.document.as_mut().unwrap();
    document.remove(&mut app.entries, 0);
    document.remove(&mut app.entries, 0);
    assert_eq!(app.entries[to].alias, "server-key");
    app.refresh_visible();
    press(&mut app, KeyCode::Enter);
    assert!(
        red_text(&mut app).contains("Nothing signed: the key 'server-key'"),
        "{:?}",
        app.message
    );
    assert!(app.signing.is_some());
}

#[test]
fn a_generated_key_pair_is_signed_by_another_private_key() {
    use crown::x509::cert::Certificate;
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    let ca = add_authority(&mut app);

    press(&mut app, KeyCode::Char('S'));
    press(&mut app, KeyCode::Char('g'));
    assert!(app.sign_menu.is_none());
    assert!(screen(&mut app, 120, 30).contains(" Generate key pair signed by 'ca' "));
    press(&mut app, KeyCode::Down);
    type_password(&mut app, "Leaf.test");
    press(&mut app, KeyCode::Enter);
    // Esc goes back to the form, which still names its signer.
    press(&mut app, KeyCode::Esc);
    assert!(screen(&mut app, 120, 30).contains(" Generate key pair signed by 'ca' "));
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Enter);
    assert!(app.finish_generation());
    assert_eq!(
        app.message,
        Some((
            "Generated EC P-256 key pair 'leaf.test', signed by 'ca'.".into(),
            false
        ))
    );
    let generated = &app.entries[app.selected_entry().unwrap()];
    assert_eq!(generated.alias, "leaf.test");
    let chain = generated.certificates().to_vec();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[1], ca);
    let leaf = Certificate::parse(&chain[0]).unwrap();
    let authority = Certificate::parse(&ca).unwrap();
    assert_eq!(leaf.verify_signature(authority.public_key()), Ok(true));
    assert_eq!(leaf.issuer().encode(), authority.subject().encode());
    assert_eq!(leaf.subject().common_name().unwrap(), "Leaf.test");

    press(&mut app, KeyCode::Char('w'));
    assert!(!app.modified, "{:?}", app.message);
    assert_eq!(
        app.entries,
        keystore::load_entries(&fs::read(&path).unwrap(), "changeit").unwrap()
    );
    let key = saved_key(&path, 1, "changeit").unwrap();
    assert_eq!(
        key_import::matching_chain(&key, std::slice::from_ref(&chain)),
        Ok(Some(chain))
    );

    // A signer that no longer opens, or is gone, signs nothing.
    for (removed, expected) in [
        (2, "Nothing signed: the key 'root-cert'"),
        (3, "The signing key is gone."),
    ] {
        select(&mut app, "ca");
        press(&mut app, KeyCode::Char('S'));
        press(&mut app, KeyCode::Char('g'));
        press(&mut app, KeyCode::Down);
        type_password(&mut app, "next.test");
        press(&mut app, KeyCode::Enter);
        let document = app.document.as_mut().unwrap();
        for _ in 0..removed {
            document.remove(&mut app.entries, 0);
        }
        app.refresh_visible();
        // The signer is read when the generation starts, so none starts.
        press(&mut app, KeyCode::Enter);
        assert!(!app.finish_generation());
        assert!(red_text(&mut app).contains(expected), "{:?}", app.message);
        add_authority(&mut app);
    }
}

#[test]
fn a_key_pair_is_signed_in_a_pkcs12_keystore() {
    let directory = TestDirectory::new();
    let mut rng = test_support::TestRng(1);
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
    // An empty keystore has nothing to sign with, and nothing is asked.
    press(&mut app, KeyCode::Char('S'));
    app.handle_signing(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.sign_menu.is_none() && app.signing.is_none() && app.message.is_none());
    let ca = add_authority(&mut app);

    press(&mut app, KeyCode::Char('S'));
    press(&mut app, KeyCode::Char('g'));
    press(&mut app, KeyCode::Down);
    type_password(&mut app, "leaf.test");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Enter);
    assert!(app.finish_generation());
    assert_eq!(
        app.message,
        Some((
            "Generated EC P-256 key pair 'leaf.test', signed by 'ca'.".into(),
            false
        ))
    );
    press(&mut app, KeyCode::Char('w'));
    assert!(!app.modified, "{:?}", app.message);
    assert_eq!(app.entries, pkcs12_entries(&path, "changeit"));
    let leaf = app
        .entries
        .iter()
        .find(|entry| entry.alias == "leaf.test")
        .unwrap();
    assert_eq!(leaf.certificates().len(), 2);
    assert_eq!(leaf.certificates()[1], ca);
}

#[test]
fn a_revocation_list_is_signed_into_a_new_file_and_read_back() {
    use crown::x509::{cert::Certificate, crl::CertificateList};
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    let file = |name: &str| directory.path().join(name);
    let ca = add_authority(&mut app);
    app.modified = true;
    press(&mut app, KeyCode::Char('w'));
    assert!(!app.modified, "{:?}", app.message);
    let stored = fs::read(&path).unwrap();
    app.handle_revoking(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

    press(&mut app, KeyCode::Char('S'));
    press(&mut app, KeyCode::Char('l'));
    assert!(app.sign_menu.is_none());
    let rendered = screen(&mut app, 120, 30);
    assert!(rendered.contains(" Revocation list signed by 'ca' "));
    assert!(rendered.contains("CRL number           1"));
    assert!(rendered.contains("Up/Down Tab Field | Enter Next | Ctrl+U Clear | Esc Cancel"));
    // Letters are typed into the form, and Esc closes it.
    assert!(!press(&mut app, KeyCode::Char('q')));
    press(&mut app, KeyCode::Esc);
    assert!(app.revoking.is_none());

    // The file name is asked next; Esc goes back to the form.
    press(&mut app, KeyCode::Char('S'));
    press(&mut app, KeyCode::Char('l'));
    type_password(&mut app, "01a4=keyCompromise, 0f");
    press(&mut app, KeyCode::Enter);
    let expected = file("ca.crl");
    let rendered = screen(&mut app, 200, 30);
    assert!(rendered.contains(&format!("Save revocation list as: {} ", expected.display())));
    assert!(rendered.contains("A .der name saves DER, any other PEM | Enter Save"));
    press(&mut app, KeyCode::Esc);
    assert!(screen(&mut app, 120, 30).contains("Revoked serials      01a4=keyCompromise, 0f_"));
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.message,
        Some((
            format!(
                "Signed a revocation list of 2 certificates with 'ca' and saved it to '{}'.",
                expected.display()
            ),
            false
        ))
    );
    assert!(app.revoking.is_none());
    let text = fs::read_to_string(&expected).unwrap();
    assert!(text.starts_with("-----BEGIN X509 CRL-----"));
    let list = CertificateList::from_pem(&text).unwrap();
    let authority = Certificate::parse(&ca).unwrap();
    assert_eq!(list.verify_signature(authority.public_key()), Ok(true));
    assert_eq!(list.tbs().issuer.encode(), authority.subject().encode());
    assert!(list.is_revoked(&[1, 0xa4]).is_some() && list.is_revoked(&[0x0f]).is_some());
    // The keystore is not changed.
    assert!(!app.modified);
    assert_eq!(fs::read(&path).unwrap(), stored);

    // A .der name writes DER, and an existing file is never replaced.
    press(&mut app, KeyCode::Char('S'));
    press(&mut app, KeyCode::Char('l'));
    type_password(&mut app, "7f");
    press(&mut app, KeyCode::Enter);
    type_alias(&mut app, "one.der");
    assert!(
        screen(&mut app, 200, 30).contains("Signed a revocation list of 1 certificate with 'ca'")
    );
    let list = CertificateList::parse(&fs::read(file("one.der")).unwrap()).unwrap();
    assert_eq!(list.verify_signature(authority.public_key()), Ok(true));
    press(&mut app, KeyCode::Char('S'));
    press(&mut app, KeyCode::Char('l'));
    press(&mut app, KeyCode::Enter);
    type_alias(&mut app, "one.der");
    assert!(red_text(&mut app).contains("already exists; choose another name."));
    assert!(app.revoking.is_some());
    // A keystore closed in between has no key to sign with.
    let document = app.document.take();
    type_alias(&mut app, "late.crl");
    assert!(red_text(&mut app).contains("No keystore is open."));
    assert!(!file("late.crl").exists());
    // Nor has a key that no longer opens: deleting the entry before it puts
    // a trusted certificate at the place the signing was started for.
    app.document = document;
    app.document.as_mut().unwrap().remove(&mut app.entries, 0);
    app.refresh_visible();
    type_alias(&mut app, "late.crl");
    assert!(
        red_text(&mut app).contains("Nothing signed: the key 'root-cert'"),
        "{:?}",
        app.message
    );
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Esc);
    assert!(app.revoking.is_none());

    // The list opens from the browser straight into its details.
    app.modified = false;
    app.open_file(expected.clone());
    assert_eq!(app.entries.len(), 1);
    assert_eq!(app.entries[0].kind(), "Revocation list");
    assert!(app.entry_details.is_some());
    let rendered = screen(&mut app, 120, 50);
    assert!(rendered.contains("Test CA — Revocation list"));
    assert!(rendered.contains("Revoked certificates (2):"));
    assert!(rendered.contains("Reason Code: keyCompromise"));
    // In the list, a revocation list has no key or expiry to show.
    press(&mut app, KeyCode::Esc);
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("Revocation list"));
    // A revocation list is not a certificate to import or a request to sign.
    assert!(editing::read_certificate(&expected, text.as_bytes()).is_err());
}
