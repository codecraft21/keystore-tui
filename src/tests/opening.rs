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
fn browser_shows_directories_then_supported_keystore_files() {
    let directory = TestDirectory::new();
    fs::create_dir(directory.path().join("z-directory")).unwrap();
    fs::write(directory.path().join("a-keystore.jks"), "").unwrap();
    fs::write(directory.path().join("b-keystore.JKS"), "").unwrap();
    fs::write(directory.path().join("c-keystore.p12"), "").unwrap();
    fs::write(directory.path().join("d-keystore.PFX"), "").unwrap();
    fs::write(directory.path().join("e-keystore.jceks"), "").unwrap();
    fs::write(directory.path().join("cacerts"), "").unwrap();
    fs::write(directory.path().join("jssecacerts"), "").unwrap();
    // On a case-insensitive file system, such as macOS by default, `CACERTS`
    // is the same file as `cacerts`.
    let case_sensitive = !directory.path().join("CACERTS").exists();
    if case_sensitive {
        fs::write(directory.path().join("CACERTS"), "").unwrap();
    }
    fs::write(directory.path().join("ignored.txt"), "").unwrap();
    fs::write(directory.path().join("ignored.jks.bak"), "").unwrap();
    fs::write(directory.path().join("cacerts.bak"), "").unwrap();

    let mut app = browsing(directory.path());
    let rendered = screen(&mut app, 100, 24);
    assert!(rendered.find("../").unwrap() < rendered.find("z-directory/").unwrap());
    assert!(rendered.find("z-directory/").unwrap() < rendered.find("a-keystore.jks").unwrap());
    assert!(rendered.find("a-keystore.jks").unwrap() < rendered.find("b-keystore.JKS").unwrap());
    assert!(rendered.find("b-keystore.JKS").unwrap() < rendered.find("c-keystore.p12").unwrap());
    assert!(rendered.find("c-keystore.p12").unwrap() < rendered.find("d-keystore.PFX").unwrap());
    assert!(rendered.find("d-keystore.PFX").unwrap() < rendered.find("e-keystore.jceks").unwrap());
    assert!(!rendered.contains("ignored"));
    for name in ["cacerts", "jssecacerts"] {
        assert!(rendered.contains(name));
    }
    assert_eq!(rendered.contains("CACERTS"), case_sensitive);
    assert!(!rendered.contains("cacerts.bak"));
}

#[test]
fn browser_opens_cacerts_and_prompts_for_its_encrypted_contents() {
    let directory = TestDirectory::new();
    let path = directory.path().join("cacerts");
    fs::write(
        &path,
        include_bytes!("../../tests/fixtures/encrypted-no-mac.p12"),
    )
    .unwrap();
    let mut app = browsing(directory.path());
    assert!(screen(&mut app, 100, 24).contains("cacerts"));
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    assert!(app.file_picker.is_none());
    assert!(app.password_prompt.is_some());
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    assert!(app.password_prompt.is_none());
    assert!(app.error.is_none());
    assert_eq!(app.keystore_path, Some(path));
    assert_eq!(app.entries.len(), 1);
    assert_eq!(app.entries[0].certificate, Some(fixture_summary()));
}

#[test]
fn browser_cycles_through_parent_directories_and_files_in_both_directions() {
    let directory = TestDirectory::new();
    fs::create_dir(directory.path().join("nested")).unwrap();
    fs::write(directory.path().join("store.jks"), empty_keystore()).unwrap();

    let mut app = browsing(directory.path());
    assert!(screen(&mut app, 100, 24).contains("> nested/"));
    for expected in ["../", "store.jks", "nested/"] {
        assert!(!press(&mut app, KeyCode::Up));
        assert!(screen(&mut app, 100, 24).contains(&format!("> {expected}")));
    }
    for expected in ["store.jks", "../", "nested/"] {
        assert!(!press(&mut app, KeyCode::Down));
        assert!(screen(&mut app, 100, 24).contains(&format!("> {expected}")));
    }
    assert!(app.keystore_path.is_none());
    assert!(app.file_picker.is_some());
}

#[test]
fn browser_filters_by_typed_prefix() {
    let directory = TestDirectory::new();
    let nested = directory.path().join("query");
    fs::create_dir(&nested).unwrap();
    fs::write(nested.join("inner.jks"), "").unwrap();
    fs::write(directory.path().join("alpha.jks"), "").unwrap();
    fs::write(directory.path().join("Quux.p12"), "").unwrap();
    let mut app = browsing(directory.path());

    // `q` is typed rather than quitting, and matching ignores case.
    assert!(!press(&mut app, KeyCode::Char('q')));
    let rendered = screen(&mut app, 100, 24);
    assert!(rendered.contains("Filter: q"), "{rendered}");
    assert!(rendered.contains("> query/"));
    assert!(rendered.contains("Quux.p12"));
    assert!(!rendered.contains("alpha.jks"));
    assert!(!rendered.contains("../"));

    press(&mut app, KeyCode::Char('z'));
    assert!(screen(&mut app, 100, 24).contains("No entries start with \"qz\"."));
    press(&mut app, KeyCode::Backspace);

    // Entering a directory starts it unfiltered.
    press(&mut app, KeyCode::Enter);
    let rendered = screen(&mut app, 100, 24);
    assert!(!rendered.contains("Filter:"), "{rendered}");
    assert!(rendered.contains("> inner.jks"));
    press(&mut app, KeyCode::Left);

    // Esc first clears the filter, then closes the browser.
    press(&mut app, KeyCode::Char('A'));
    assert!(screen(&mut app, 100, 24).contains("> alpha.jks"));
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.file_picker.is_some());
    assert!(screen(&mut app, 100, 24).contains("../"));
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.file_picker.is_none());
}

#[test]
fn browser_wrapping_scrolls_between_ends_of_a_long_list() {
    let directory = TestDirectory::new();
    for index in 0..40 {
        fs::write(directory.path().join(format!("store-{index:02}.jks")), "").unwrap();
    }
    let mut app = browsing(directory.path());
    assert!(screen(&mut app, 100, 20).contains("> store-00.jks"));
    press(&mut app, KeyCode::Home);
    assert!(screen(&mut app, 100, 20).contains("> ../"));
    press(&mut app, KeyCode::Up);
    assert!(screen(&mut app, 100, 20).contains("> store-39.jks"));
    press(&mut app, KeyCode::Down);
    assert!(screen(&mut app, 100, 20).contains("> ../"));
}

#[test]
fn browser_cycles_safely_with_only_the_parent_entry() {
    let directory = TestDirectory::new();
    let mut app = browsing(directory.path());
    for key in [KeyCode::Up, KeyCode::Down, KeyCode::Home, KeyCode::End] {
        assert!(!press(&mut app, key));
        assert!(screen(&mut app, 100, 24).contains("> ../"));
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
fn single_certificate_files_from_the_browser_open_in_details() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for (name, heading) in [
        ("trusted-cert.pem", "Certificate hierarchy"),
        ("trusted-cert.crt", "Certificate hierarchy"),
        ("keytool-request.csr", "Request details"),
    ] {
        let mut app = App::default();
        app.open_file(fixtures.join(name));
        assert!(app.error.is_none(), "{name}");
        assert_eq!(app.entries.len(), 1, "{name}");
        assert!(app.entry_details.is_some(), "{name}");
        assert!(screen(&mut app, 100, 30).contains(heading), "{name}");
        assert!(!press(&mut app, KeyCode::Esc));
        assert!(app.entry_details.is_none(), "{name}");
        assert!(screen(&mut app, 100, 30).contains("1 entries | Sort: alias"));
    }

    // Several certificates, or a single-entry keystore, open on the list.
    for (name, count) in [("bundle.pem", 2), ("passwordless.p12", 1)] {
        let mut app = App::default();
        app.open_file(fixtures.join(name));
        assert!(app.error.is_none(), "{name}");
        assert_eq!(app.entries.len(), count, "{name}");
        assert!(app.entry_details.is_none(), "{name}");
    }
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
fn selecting_a_valid_empty_keystore_displays_its_absolute_path() {
    let directory = TestDirectory::new();
    let path = directory.path().join("my keystore-ü.JKS");
    let data = empty_keystore();
    fs::write(&path, &data).unwrap();
    let mut app = browsing(directory.path());

    press(&mut app, KeyCode::End);
    assert!(!press(&mut app, KeyCode::Enter));

    let expected = canonical_path::canonicalize(&path).unwrap();
    assert_eq!(app.keystore_path.as_deref(), Some(expected.as_path()));
    assert!(app.file_picker.is_none());
    let rendered = screen(&mut app, 200, 24);
    assert_eq!(
        rendered.lines().nth(20).unwrap().trim_end(),
        format!("Path: '{}'", expected.display())
    );
    // Only the path itself is blue, not the label or the quotes.
    let path_bar = buffer(&mut app, 200, 24);
    let path_end = 7 + expected.display().to_string().chars().count() as u16;
    for x in 0..=path_end {
        let color = if (7..path_end).contains(&x) {
            Color::Blue
        } else {
            Color::Reset
        };
        assert_eq!(path_bar[(x, 20)].fg, color, "column {x}");
    }
    let title = rendered.lines().next().unwrap();
    assert!(title.contains(" keystore-tui "));
    assert!(!title.contains(expected.to_str().unwrap()));
    assert!(!title.contains("entries"));
    assert!(screen(&mut app, 200, 24).contains("This keystore contains no entries."));
    assert!(app.password_prompt.is_none());
    assert_eq!(fs::read(&path).unwrap(), data);
}

#[test]
fn directories_can_be_entered_and_left_before_selecting() {
    let directory = TestDirectory::new();
    let nested = directory.path().join("nested");
    fs::create_dir(&nested).unwrap();
    let path = nested.join("nested-keystore.jks");
    fs::write(&path, empty_keystore()).unwrap();
    let mut app = browsing(directory.path());

    press(&mut app, KeyCode::Right);
    assert!(app.keystore_path.is_none());
    assert!(screen(&mut app, 200, 24).contains("nested-keystore.jks"));

    press(&mut app, KeyCode::Left);
    let parent = screen(&mut app, 200, 24);
    assert!(parent.contains("nested/"));
    assert!(!parent.contains("nested-keystore.jks"));

    press(&mut app, KeyCode::Enter);
    // Home selects ../, so Enter also navigates to the parent.
    press(&mut app, KeyCode::Home);
    press(&mut app, KeyCode::Enter);
    assert!(!screen(&mut app, 200, 24).contains("nested-keystore.jks"));

    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.keystore_path,
        Some(canonical_path::canonicalize(&path).unwrap())
    );
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
fn a_missing_directory_does_not_close_the_browser() {
    let directory = TestDirectory::new();
    let nested = directory.path().join("removed-directory");
    fs::create_dir(&nested).unwrap();
    let mut app = browsing(directory.path());
    press(&mut app, KeyCode::End);
    fs::remove_dir(&nested).unwrap();

    press(&mut app, KeyCode::Enter);
    let rendered = screen(&mut app, 200, 24);
    assert!(rendered.contains("Could not open selection"));
    assert!(rendered.contains("removed-directory/"));
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.file_picker.is_none());
}

#[test]
fn empty_directories_and_small_terminals_are_handled() {
    let directory = TestDirectory::new();
    let mut app = browsing(directory.path());
    assert!(
        screen(&mut app, 100, 24)
            .contains("No keystore (.jks, .jceks, .p12, .pfx, cacerts, jssecacerts)")
    );
    press(&mut app, KeyCode::Up);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Home);
    press(&mut app, KeyCode::End);
    screen(&mut app, 12, 5);
    screen(&mut app, 1, 1);
    assert!(app.keystore_path.is_none());
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.file_picker.is_none());
    assert!(press(&mut app, KeyCode::Esc));
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
