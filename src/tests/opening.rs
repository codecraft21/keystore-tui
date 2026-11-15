use super::*;

#[test]
fn malformed_counts_report_an_error_and_preserve_the_loaded_keystore() {
    let directory = TestDirectory::new();
    let original = directory.path().join("original.jks");
    fs::write(&original, empty_keystore()).unwrap();
    let mut app = App::default();
    app.open_file(original.clone());

    let mut data = empty_keystore();
    data[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    let malformed = directory.path().join("malformed.jks");
    fs::write(&malformed, data).unwrap();
    app.open_file(malformed);
    assert!(app.password_prompt.is_none());
    assert_eq!(app.keystore_path, Some(original));
    assert!(red_text(&mut app).contains("not a valid JKS keystore"));

    let truncated = directory.path().join("truncated.jceks");
    fs::write(&truncated, &test_support::KEYTOOL_JCEKS[..20]).unwrap();
    app.open_file(truncated);
    assert!(red_text(&mut app).contains("not a valid JCEKS keystore"));
}

#[test]
fn example_fixture_has_twenty_certificates_and_two_expired_entries() {
    let mut app = App::default();
    app.open_file(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/example.jks"));
    assert!(app.password_prompt.is_none());
    assert!(app.error.is_none());
    assert_eq!(app.entries.len(), 20);
    let now = Asn1Time::new(2026, 10, 28, 0, 0, 0, true)
        .unwrap()
        .to_unix();
    let mut expired = Vec::new();
    for entry in &app.entries {
        assert!(matches!(
            entry.content,
            Content::Certificates {
                kind: Kind::TrustedCertificate,
                ..
            }
        ));
        let summary = entry.certificate.as_ref().unwrap();
        assert_eq!(summary.algorithm, "EC");
        assert_eq!(summary.key_size, Some(256));
        if entry_list::expiry_status(summary, now) == ExpiryStatus::Expired {
            expired.push(entry.alias.as_str());
        }
    }
    assert_eq!(expired, ["example-01-expired", "example-02-expired"]);
}

#[test]
fn entry_list_shows_certificate_algorithm_key_size_and_expiry() {
    let mut app = App::default();
    let expired = Summary {
        not_after: Some(Asn1Time::new(2001, 2, 3, 0, 0, 0, true).unwrap()),
        ..fixture_summary()
    };
    app.show_entries(
        PathBuf::from("/keystore.jks"),
        vec![
            KeystoreEntry {
                alias: "current".into(),
                certificate: Some(fixture_summary()),
                content: Content::Certificates {
                    kind: Kind::TrustedCertificate,
                    certificates: vec![],
                },
                chain_warning: None,
            },
            KeystoreEntry {
                alias: "expired".into(),
                certificate: Some(expired),
                content: Content::Certificates {
                    kind: Kind::PrivateKey,
                    certificates: vec![],
                },
                chain_warning: None,
            },
            KeystoreEntry {
                alias: "secret".into(),
                certificate: None,
                content: Content::Certificates {
                    kind: Kind::SecretKey,
                    certificates: vec![],
                },
                chain_warning: None,
            },
        ],
    );
    let screen = screen(&mut app, 80, 24);
    for text in [
        "Algorithm",
        "Key size",
        "Expires",
        "EC",
        "256 bits",
        "2036-10-09",
    ] {
        assert!(screen.contains(text), "{text}\n{screen}");
    }
    assert!(
        screen
            .lines()
            .any(|line| line.contains("secret") && line.contains("-"))
    );
    assert_eq!(red_text(&mut app), "2001-02-03");

    press(&mut app, KeyCode::Down);
    let rendered = buffer(&mut app, 80, 24);
    let selected_row = rendered
        .content
        .chunks(80)
        .find(|row| row.iter().any(|cell| cell.symbol() == ">"))
        .unwrap();
    let expiry_start = selected_row
        .windows(10)
        .position(|cells| {
            cells.iter().map(|cell| cell.symbol()).collect::<String>() == "2001-02-03"
        })
        .unwrap();
    for (index, cell) in selected_row.iter().enumerate().skip(1).take(78) {
        let is_expiry = (expiry_start..expiry_start + 10).contains(&index);
        assert_eq!(
            cell.bg,
            if is_expiry {
                Color::Rgb(128, 0, 0)
            } else {
                Color::Rgb(175, 255, 255)
            }
        );
        assert!(cell.modifier.contains(ratatui::style::Modifier::BOLD));
        assert_eq!(
            cell.fg,
            if is_expiry {
                Color::Rgb(255, 255, 255)
            } else {
                Color::Rgb(0, 0, 0)
            }
        );
    }
    assert!(red_text(&mut app).is_empty());
    press(&mut app, KeyCode::Down);
    assert_eq!(red_text(&mut app), "2001-02-03");
}

#[test]
fn jks_renamed_as_p12_still_uses_jks_content() {
    let directory = TestDirectory::new();
    let path = directory.path().join("renamed.p12");
    fs::write(&path, empty_keystore()).unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    assert_eq!(app.keystore_path, Some(path));
    assert!(app.password_prompt.is_none());
    assert!(app.error.is_none());
}

#[test]
fn certificate_fixtures_hold_the_keystore_certificate() {
    assert_eq!(
        test_support::TRUSTED_CERT_CRT,
        test_support::fixture_certificate_der()
    );
    let file = certificate_file::parse(test_support::TRUSTED_CERT_PEM).unwrap();
    assert_eq!(file.entries.len(), 1);
    assert_eq!(file.entries[0].certificate, Some(fixture_summary()));
    let bundle = certificate_file::parse(test_support::BUNDLE_PEM).unwrap();
    assert_eq!(bundle.entries.len(), 2);
    assert_eq!(bundle.entries[0].certificate, Some(fixture_summary()));
    assert_ne!(bundle.entries[1].certificate, Some(fixture_summary()));
}

#[test]
fn pkcs12_without_mac_and_invalid_ciphertext_opens_as_incomplete() {
    let directory = TestDirectory::new();
    let path = directory.path().join("invalid.p12");
    fs::write(
        &path,
        include_bytes!("../../tests/fixtures/invalid-ciphertext-no-mac.p12"),
    )
    .unwrap();
    let mut app = App::default();
    app.open_file(path);
    assert!(app.password_prompt.is_none());
    assert!(app.entries.is_empty());
    assert!(screen(&mut app, 100, 24).contains("entry list is incomplete"));
}

#[test]
fn truncated_pkcs12_is_rejected_before_password_prompt() {
    let directory = TestDirectory::new();
    let path = directory.path().join("truncated.p12");
    let fixture = include_bytes!("../../tests/fixtures/trusted-cert.p12");
    fs::write(&path, &fixture[..fixture.len() - 1]).unwrap();
    let mut app = App::default();
    app.open_file(path);
    assert!(app.password_prompt.is_none());
    assert!(red_text(&mut app).contains("not a valid PKCS12 keystore"));
}

#[test]
fn partial_pkcs12_warning_persists_with_entries() {
    let directory = TestDirectory::new();
    let mut app = App::default();
    app.show_verified(
        directory.path().join("partial.p12"),
        Opened {
            verified: pkcs12::Verified {
                entries: vec![KeystoreEntry {
                    alias: "readable".into(),
                    certificate: None,
                    content: Content::Certificates {
                        kind: Kind::SecretKey,
                        certificates: vec![],
                    },
                    chain_warning: None,
                }],
                incomplete: true,
            },
            document: None,
        },
    );
    assert!(screen(&mut app, 100, 24).contains("readable"));
    assert!(screen(&mut app, 100, 24).contains("entry list is incomplete"));
    press(&mut app, KeyCode::Char('o'));
    press(&mut app, KeyCode::Esc);
    assert!(screen(&mut app, 100, 24).contains("entry list is incomplete"));
}

#[test]
fn a_missing_file_reports_an_error_and_allows_recovery() {
    let directory = TestDirectory::new();
    let path = directory.path().join("removed.jks");
    fs::write(&path, empty_keystore()).unwrap();
    let mut app = browsing(directory.path());
    press(&mut app, KeyCode::End);
    fs::remove_file(&path).unwrap();

    assert!(!press(&mut app, KeyCode::Enter));
    assert!(app.keystore_path.is_none());
    assert!(app.file_picker.is_some());
    assert!(screen(&mut app, 200, 24).contains("Could not open selection"));

    fs::write(&path, empty_keystore()).unwrap();
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.keystore_path,
        Some(canonical_path::canonicalize(&path).unwrap())
    );
}

#[test]
fn invalid_file_shows_a_red_error_and_valid_selection_recovers() {
    let directory = TestDirectory::new();
    fs::write(directory.path().join("a-invalid.jks"), "not a keystore").unwrap();
    fs::write(directory.path().join("b-valid.jks"), mixed_keystore()).unwrap();
    let mut app = browsing(directory.path());

    press(&mut app, KeyCode::Enter);
    assert!(app.file_picker.is_none());
    assert!(app.password_prompt.is_none());
    assert!(app.keystore_path.is_none());
    assert!(red_text(&mut app).contains("not a valid JKS keystore"));

    app.file_picker = Some(FilePicker::new(directory.path()).unwrap());
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    assert!(app.password_prompt.is_some());
    assert!(app.error.is_none());
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    assert!(app.password_prompt.is_none());
    let content = screen(&mut app, 100, 24);
    for expected in [
        "root-cert",
        "Trusted certificate",
        "server-key",
        "Private key",
        "keystore-tui",
    ] {
        assert!(content.contains(expected), "missing {expected}");
    }
    let title = content.lines().next().unwrap();
    assert!(!title.contains("entries"));
    assert!(!title.contains("b-valid.jks"));
    assert!(red_text(&mut app).is_empty());
}

#[test]
fn truncated_files_are_rejected_before_the_password_prompt() {
    let directory = TestDirectory::new();
    fs::write(
        directory.path().join("truncated.jks"),
        &KEYTOOL_JKS[..KEYTOOL_JKS.len() - 1],
    )
    .unwrap();
    let mut app = browsing(directory.path());
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    assert!(app.password_prompt.is_none());
    assert!(app.keystore_path.is_none());
    assert!(red_text(&mut app).contains("not a valid JKS keystore"));
}

#[test]
fn a_read_failure_is_reported_in_red_without_losing_the_loaded_keystore() {
    let directory = TestDirectory::new();
    let original = directory.path().join("original.jks");
    fs::write(&original, empty_keystore()).unwrap();
    let mut app = App::default();
    app.open_file(original.clone());
    app.open_file(directory.path().join("missing.jks"));
    assert!(red_text(&mut app).contains("Cannot read"));
    assert!(screen(&mut app, 200, 24).contains(&format!("Path: '{}'", original.display())));
    assert_eq!(app.keystore_path, Some(original));
    assert!(app.password_prompt.is_none());
}
