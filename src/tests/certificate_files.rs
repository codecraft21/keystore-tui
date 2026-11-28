use super::*;

#[test]
fn certificate_files_open_without_a_prompt_in_file_order() {
    use crown::asn1::pem;
    let directory = TestDirectory::new();
    let der = test_support::fixture_certificate_der();
    let leaf = test_support::metadata_certificate("zz-leaf", "JKS TUI test fixture", &[1], &[]);
    let pem_path = directory.path().join("bundle.crt");
    let text = [
        pem::encode("CERTIFICATE", &leaf),
        pem::encode("PRIVATE KEY", b"synthetic, not a key"),
        pem::encode("CERTIFICATE", der),
    ]
    .concat();
    fs::write(&pem_path, text).unwrap();
    // A DER certificate is recognised by content even without a known name.
    let der_path = directory.path().join("unnamed");
    fs::write(&der_path, der).unwrap();

    let mut app = App::default();
    app.open_file(pem_path);
    assert!(app.password_prompt.is_none());
    assert_eq!(shown_aliases(&app), ["zz-leaf", "JKS TUI test fixture"]);
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("Certificate"));
    assert!(rendered.contains("private keys, were not read"));
    press(&mut app, KeyCode::Enter);
    let details = screen(&mut app, 120, 50);
    assert!(details.find("CN=JKS TUI test fixture").unwrap() < details.find("CN=zz-leaf").unwrap());

    app.open_file(der_path);
    assert!(app.error.is_none());
    assert!(app.warning.is_none());
    assert_eq!(shown_aliases(&app), ["JKS TUI test fixture"]);
    // A single certificate opens straight into its details.
    assert!(app.entry_details.is_some());
    press(&mut app, KeyCode::Esc);

    let bad = directory.path().join("bad.pem");
    fs::write(
        &bad,
        "-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    app.open_file(bad);
    assert!(red_text(&mut app).contains("not a valid certificate file"));
    assert_eq!(shown_aliases(&app), ["JKS TUI test fixture"]);
}

#[test]
fn certificate_requests_open_without_a_prompt_or_expiry() {
    let directory = TestDirectory::new();
    let path = directory.path().join("server.csr");
    fs::write(&path, test_support::KEYTOOL_REQUEST).unwrap();
    // A DER request is recognised by content even without a known name.
    let der_path = directory.path().join("unnamed");
    fs::write(&der_path, test_support::OPENSSL_REQUEST_DER).unwrap();

    let mut app = App::default();
    app.open_file(path);
    assert!(app.password_prompt.is_none());
    assert!(app.error.is_none());
    assert_eq!(shown_aliases(&app), ["CSR TUI test fixture"]);
    // A single request opens straight into its details.
    assert!(app.entry_details.is_some());
    press(&mut app, KeyCode::Esc);
    let rendered = screen(&mut app, 120, 24);
    let row = rendered
        .lines()
        .find(|line| line.contains("CSR TUI test fixture"))
        .unwrap();
    for column in ["Certificate request", "EC", "256 bits", " - "] {
        assert!(row.contains(column), "missing {column:?} in {row}");
    }
    press(&mut app, KeyCode::Char('s'));
    assert_eq!(shown_aliases(&app), ["CSR TUI test fixture"]);
    press(&mut app, KeyCode::Enter);
    let details = screen(&mut app, 120, 50);
    assert!(details.contains("CN=CSR TUI test fixture [verified]"));
    assert!(details.contains("Requested extensions:"));
    press(&mut app, KeyCode::Esc);

    app.open_file(der_path);
    assert!(app.error.is_none());
    assert_eq!(shown_aliases(&app), ["OpenSSL CSR fixture"]);
}

#[test]
fn browser_lists_certificate_files() {
    let directory = TestDirectory::new();
    for name in ["a.pem", "b.CER", "c.p7b", "d.txt", "e.csr", "f.P10"] {
        fs::write(directory.path().join(name), b"").unwrap();
    }
    let mut app = browsing(directory.path());
    let rendered = screen(&mut app, 100, 24);
    for name in ["a.pem", "b.CER", "c.p7b", "e.csr", "f.P10"] {
        assert!(rendered.contains(name), "missing {name}");
    }
    assert!(!rendered.contains("d.txt"));
}

#[test]
fn details_export_certificates_next_to_the_opened_file() {
    let directory = TestDirectory::new();
    let leaf = test_support::metadata_certificate("leaf", "root", &[1], &[]);
    let root = test_support::metadata_certificate("root", "root", &[2], &[]);
    let mut app = App::default();
    app.show_entries(
        directory.path().join("store.jks"),
        vec![KeystoreEntry {
            alias: "server".into(),
            certificate: None,
            content: Content::Certificates {
                kind: Kind::PrivateKey,
                certificates: vec![leaf.clone(), root.clone()],
            },
            chain_warning: None,
        }],
    );
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 40).contains("x Export certificate"));

    // Letters, including q, are typed into the name; Esc cancels only the prompt.
    press(&mut app, KeyCode::Char('x'));
    assert!(screen(&mut app, 120, 40).contains("Save certificate to: "));
    assert!(!press(&mut app, KeyCode::Char('q')));
    assert!(app.entry_details.as_ref().unwrap().exporting());
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.entry_details.is_some());
    assert!(!app.entry_details.as_ref().unwrap().exporting());

    press(&mut app, KeyCode::Char('x'));
    press(&mut app, KeyCode::Enter);
    let saved = directory.path().join("server.pem");
    assert!(
        screen(&mut app, 200, 40).contains(&format!("Saved certificate to '{}'.", saved.display()))
    );
    assert_eq!(
        fs::read_to_string(&saved).unwrap(),
        crown::asn1::pem::encode("CERTIFICATE", &leaf)
    );

    // The root is selected one row up; DER is chosen by the .der name.
    press(&mut app, KeyCode::Up);
    press(&mut app, KeyCode::Char('x'));
    app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    type_password(&mut app, "root.der");
    press(&mut app, KeyCode::Enter);
    assert_eq!(fs::read(directory.path().join("root.der")).unwrap(), root);

    // A chain cannot be DER; the prompt stays open with a red error.
    app.handle_key(KeyEvent::new(KeyCode::Char('X'), KeyModifiers::SHIFT));
    let rendered = screen(&mut app, 120, 40);
    assert!(rendered.contains("Save chain to: "));
    assert!(rendered.contains("A .p7b/.p7c name saves PKCS#7, .der DER, any other PEM"));
    app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    type_password(&mut app, "chain.der");
    press(&mut app, KeyCode::Enter);
    assert!(red_text(&mut app).contains("use a .pem or .p7b name"));
    assert!(app.entry_details.as_ref().unwrap().exporting());
    // A .p7b name writes the chain as DER PKCS#7 SignedData.
    app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    type_password(&mut app, "chain.p7b");
    press(&mut app, KeyCode::Enter);
    assert!(!app.entry_details.as_ref().unwrap().exporting());
    let p7b = fs::read(directory.path().join("chain.p7b")).unwrap();
    assert!(!certificate_file::is_pem(&p7b));
    let parsed = certificate_file::parse(&p7b).unwrap();
    let leaf_entry = parsed
        .entries
        .iter()
        .find(|entry| entry.certificates().len() == 2)
        .unwrap();
    assert_eq!(leaf_entry.certificates(), [leaf.clone(), root.clone()]);
    app.handle_key(KeyEvent::new(KeyCode::Char('X'), KeyModifiers::SHIFT));
    press(&mut app, KeyCode::Enter);
    let chain = fs::read_to_string(directory.path().join("server-chain.pem")).unwrap();
    assert_eq!(
        chain,
        [leaf, root]
            .map(|der| crown::asn1::pem::encode("CERTIFICATE", &der))
            .concat()
    );
    assert!(press(&mut app, KeyCode::Char('q')));
}

#[test]
fn the_opened_file_directory_is_absolute() {
    let working_directory = std::env::current_dir().unwrap();
    assert_eq!(
        path_bar::directory(Path::new("store.jks")),
        working_directory
    );
    assert_eq!(
        path_bar::directory(Path::new("certs/server.pem")),
        working_directory.join("certs")
    );
    // `/` on Unix, the current drive's root, such as `D:\`, on Windows.
    let root = working_directory.ancestors().last().unwrap();
    let certs = root.join("stores").join("certs");
    assert_eq!(path_bar::directory(&certs.join("server.pem")), certs);
}

#[test]
fn the_opened_file_directory_resolves_parent_components() {
    let directory = TestDirectory::in_working_directory();
    let certs = directory.path().join("certs");
    fs::create_dir(&certs).unwrap();
    let relative = test_support::relative_to_working_directory(&certs);
    let path = relative.join("..").join("certs").join("server.pem");
    assert_eq!(path_bar::directory(&path), certs);
}

#[test]
fn details_opened_through_a_relative_path_export_to_the_suggested_folder() {
    let directory = TestDirectory::in_working_directory();
    let relative = test_support::relative_to_working_directory(directory.path());
    let path = relative.join("server.pem");
    fs::write(
        &path,
        crown::asn1::pem::encode("CERTIFICATE", test_support::fixture_certificate_der()),
    )
    .unwrap();
    let mut app = App::default();
    app.open_file(path);
    press(&mut app, KeyCode::Enter);
    assert!(app.entry_details.is_some());

    press(&mut app, KeyCode::Char('x'));
    let suggested = directory.path().join("JKS_TUI_test_fixture.pem");
    let suggestion = format!("Save certificate to: {}", suggested.display());
    assert!(screen(&mut app, 200, 40).contains(&suggestion));
    press(&mut app, KeyCode::Enter);
    assert!(
        screen(&mut app, 200, 40)
            .contains(&format!("Saved certificate to '{}'.", suggested.display()))
    );
    assert!(suggested.is_file());
    assert!(!relative.join(&relative).exists());
}

#[test]
fn the_file_browser_opens_in_the_directory_of_a_bare_or_relative_name() {
    let directory = TestDirectory::in_working_directory();
    let relative = test_support::relative_to_working_directory(directory.path());
    for path in [PathBuf::from("store.jks"), relative.join("store.jks")] {
        let mut app = App {
            keystore_path: Some(path),
            ..App::default()
        };
        press(&mut app, KeyCode::Char('o'));
        assert!(app.error.is_none(), "{:?}", app.error);
        assert!(app.file_picker.is_some());
    }
}

#[test]
fn weak_certificates_are_flagged_in_the_list_details_and_hierarchy() {
    use crown::asn1::pem;
    let directory = TestDirectory::new();
    let path = directory.path().join("weak.pem");
    let weak = test_support::sha1_signed_certificate("weak-leaf", "JKS TUI test fixture");
    let text = [
        pem::encode("CERTIFICATE", &weak),
        pem::encode("CERTIFICATE", test_support::fixture_certificate_der()),
    ]
    .concat();
    fs::write(&path, text).unwrap();
    let mut app = App::default();
    app.open_file(path);
    assert_eq!(shown_aliases(&app), ["weak-leaf", "JKS TUI test fixture"]);
    let yellow = |app: &mut App, width: u16, height: u16| -> String {
        buffer(app, width, height)
            .content
            .iter()
            .filter(|cell| cell.fg == Color::Yellow)
            .map(|cell| cell.symbol())
            .collect()
    };
    let list = screen(&mut app, 120, 24);
    assert!(list.contains("Crypto"), "{list}");
    // The selected weak row uses the amber highlight; the other row is not weak.
    assert!(yellow(&mut app, 120, 24).is_empty());
    press(&mut app, KeyCode::Down);
    // A styled cell fills its column width.
    assert_eq!(yellow(&mut app, 120, 24).trim_end(), "Weak");
    press(&mut app, KeyCode::Up);
    let rendered = buffer(&mut app, 120, 24);
    let selected_row = rendered
        .content
        .chunks(120)
        .find(|row| row.iter().any(|cell| cell.symbol() == ">"))
        .unwrap();
    let amber: String = selected_row
        .iter()
        .filter(|cell| cell.bg == Color::Rgb(255, 175, 0))
        .map(|cell| cell.symbol())
        .collect();
    assert_eq!(amber.trim_end(), "Weak");

    press(&mut app, KeyCode::Enter);
    let details = screen(&mut app, 120, 50);
    assert!(
        details.contains("Weak: signed with SHA-1, which is no longer secure."),
        "{details}"
    );
    assert!(details.contains("CN=weak-leaf [weak]"), "{details}");
    // The self-signed fixture issuer is not weak.
    assert!(!details.contains("CN=JKS TUI test fixture [weak]"));
    press(&mut app, KeyCode::Up);
    let issuer = screen(&mut app, 120, 50);
    assert!(!issuer.contains("Weak:"), "{issuer}");
}
