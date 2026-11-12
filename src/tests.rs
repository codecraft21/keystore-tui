use std::{
    fs,
    io::{self, Read},
    path::Path,
};

use crown::asn1::Asn1Time;
use ratatui::{Terminal, backend::TestBackend, buffer::Buffer};

use super::*;
use certificate::Summary;
use keystore::{Content, Kind};
use test_support::{
    KEYTOOL_JKS, TestDirectory, UNICODE_ALIAS_JKS, UNICODE_PASSWORD_JKS, empty_keystore,
    fixture_summary, mixed_keystore,
};

fn browsing(directory: &Path) -> App {
    App {
        file_picker: Some(FilePicker::new(directory).unwrap()),
        ..App::default()
    }
}

fn press(app: &mut App, code: KeyCode) -> bool {
    app.handle_key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn buffer(app: &mut App, width: u16, height: u16) -> Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| app.draw(frame)).unwrap();
    terminal.backend().buffer().clone()
}

fn screen(app: &mut App, width: u16, height: u16) -> String {
    buffer(app, width, height)
        .content
        .chunks(usize::from(width))
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

fn red_text(app: &mut App) -> String {
    buffer(app, 200, 24)
        .content
        .iter()
        .filter(|cell| cell.fg == Color::Red)
        .map(|cell| cell.symbol())
        .collect()
}

fn type_password(app: &mut App, password: &str) {
    for ch in password.chars() {
        assert!(!press(app, KeyCode::Char(ch)));
    }
}

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
        include_bytes!("../tests/fixtures/encrypted-no-mac.p12"),
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
    fs::write(&path, include_bytes!("../tests/fixtures/trusted-cert.p12")).unwrap();
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
    fs::write(&path, include_bytes!("../tests/fixtures/passwordless.p12")).unwrap();
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
        include_bytes!("../tests/fixtures/encrypted-no-mac.p12"),
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
            include_bytes!("../tests/fixtures/openssl-no-mac-aes.p12").as_slice(),
        ),
        (
            "rc4.p12",
            include_bytes!("../tests/fixtures/openssl-no-mac-rc4.p12").as_slice(),
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
        include_bytes!("../tests/fixtures/invalid-ciphertext-no-mac.p12"),
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
    let fixture = include_bytes!("../tests/fixtures/trusted-cert.p12");
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
        rendered.lines().nth(21).unwrap().trim_end(),
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
        assert_eq!(path_bar[(x, 21)].fg, color, "column {x}");
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

#[test]
fn path_bar_is_blank_until_loaded_and_clips_without_wrapping() {
    let mut app = App::default();
    assert_eq!(screen(&mut app, 40, 12).lines().nth(10).unwrap().trim(), "");

    app.show_entries(PathBuf::from("/a long directory/keystore.jks"), vec![]);
    app.error = Some("An opening error".to_string());
    let rendered = screen(&mut app, 20, 12);
    let lines: Vec<_> = rendered.lines().collect();
    assert_eq!(lines[8].trim_end(), "An opening error");
    assert_eq!(lines[10], "Path: '/a long direc");
    assert!(lines[11].starts_with("o Open file"));

    for (width, height) in [(1, 1), (5, 3), (20, 5), (0, 0)] {
        buffer(&mut app, width, height);
    }
}

#[test]
fn entry_list_scrolls_to_entries_below_the_viewport() {
    let directory = TestDirectory::new();
    let mut app = App::default();
    app.show_entries(
        directory.path().join("many.jks"),
        (0..40)
            .map(|index| KeystoreEntry {
                alias: format!("entry-{index:02}"),
                certificate: None,
                content: Content::Certificates {
                    kind: Kind::TrustedCertificate,
                    certificates: vec![],
                },
                chain_warning: None,
            })
            .collect(),
    );
    assert!(!screen(&mut app, 100, 20).contains("entry-39"));
    for _ in 0..39 {
        press(&mut app, KeyCode::Down);
        screen(&mut app, 100, 20);
    }
    assert!(screen(&mut app, 100, 20).contains("entry-39"));
    press(&mut app, KeyCode::Down);
    assert_eq!(selected_alias(&app), "entry-00");
    assert!(screen(&mut app, 100, 20).contains("entry-00"));
    press(&mut app, KeyCode::Up);
    assert_eq!(selected_alias(&app), "entry-39");
    assert!(screen(&mut app, 100, 20).contains("entry-39"));
}

#[test]
fn altgr_is_typed_on_windows_and_other_modifier_chords_are_ignored() {
    let directory = TestDirectory::new();
    let path = directory.path().join("valid.jks");
    fs::write(&path, mixed_keystore()).unwrap();
    let mut app = App::default();
    app.open_file(path);
    for (ch, modifiers) in [
        ('a', KeyModifiers::ALT),
        ('b', KeyModifiers::CONTROL),
        ('@', KeyModifiers::CONTROL | KeyModifiers::ALT),
        (
            '€',
            KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SHIFT,
        ),
        ('X', KeyModifiers::SHIFT),
    ] {
        app.handle_key(KeyEvent::new(KeyCode::Char(ch), modifiers));
    }
    // Only Windows reports AltGr as Ctrl+Alt; elsewhere it is a shortcut chord.
    let expected = if cfg!(windows) { "@€X" } else { "X" };
    assert_eq!(*app.password_prompt.as_ref().unwrap().password.0, expected);
}

#[test]
fn long_passwords_survive_buffer_growth_and_backspace() {
    let mut password = Password::default();
    let mut expected = "pässwörd-😀".repeat(20);
    for ch in expected.chars() {
        password.push(ch);
    }
    assert_eq!(*password.0, expected);
    for _ in 0..3 {
        password.pop();
        expected.pop();
        assert_eq!(*password.0, expected);
    }
    password.clear();
    assert!(password.0.is_empty());
    password.pop();
    assert!(password.0.is_empty());
}

struct CountingReader {
    read: u64,
}

impl Read for CountingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        buf.fill(0);
        self.read += buf.len() as u64;
        Ok(buf.len())
    }
}

#[test]
fn unbounded_input_is_rejected_after_reading_just_past_the_limit() {
    let mut reader = CountingReader { read: 0 };
    let error = read_bounded(&mut reader, u64::MAX, 1000).unwrap_err();
    assert!(error.to_string().contains("keystore limit"));
    assert_eq!(reader.read, 1001);
}

#[test]
fn oversized_files_are_rejected_without_reading_them_fully() {
    let directory = TestDirectory::new();
    let path = directory.path().join("large.jks");
    fs::write(&path, mixed_keystore()).unwrap();
    let size = fs::metadata(&path).unwrap().len();
    assert!(read_limited(&path, size).is_ok());
    let error = read_limited(&path, size - 1).unwrap_err();
    assert!(error.to_string().contains("keystore limit"));
}

#[test]
fn ctrl_alt_c_does_not_quit() {
    let mut app = App::default();
    let altgr_c = KeyEvent::new(
        KeyCode::Char('c'),
        KeyModifiers::CONTROL | KeyModifiers::ALT,
    );
    assert!(!app.handle_key(altgr_c));
    assert!(app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
}

#[test]
fn enter_opens_full_screen_details_and_escape_preserves_list_state() {
    let mut app = App::default();
    let certificates = vec![test_support::fixture_certificate_der().to_vec()];
    app.show_entries(
        PathBuf::from("/keystore.jks"),
        (0..40)
            .map(|i| KeystoreEntry {
                alias: format!("entry-{i:02}"),
                certificate: Some(fixture_summary()),
                content: Content::Certificates {
                    kind: Kind::TrustedCertificate,
                    certificates: certificates.clone(),
                },
                chain_warning: None,
            })
            .collect(),
    );
    for _ in 0..35 {
        press(&mut app, KeyCode::Down);
        screen(&mut app, 100, 20);
    }
    let previous = app.entries_state;
    let previous_screen = screen(&mut app, 100, 20);
    assert!(!press(&mut app, KeyCode::Enter));
    let details = screen(&mut app, 120, 50);
    for label in [
        "entry-35",
        "Certificate hierarchy",
        "Version:",
        "Subject:",
        "Issuer:",
        "Serial Number (hex):",
        "Serial Number (dec):",
        "Valid From:",
        "Valid Until:",
        "Public Key: EC 256 bits",
        "Signature Algorithm:",
        "Fingerprint (SHA-256):",
    ] {
        assert!(details.contains(label), "missing {label}");
    }
    assert!(details.contains("Path: '/keystore.jks'"));
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.entry_details.is_none());
    assert_eq!(app.entries_state, previous);
    assert_eq!(screen(&mut app, 100, 20), previous_screen);
    press(&mut app, KeyCode::Enter);
    assert!(press(&mut app, KeyCode::Char('q')));
    assert!(app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
    assert!(!app.handle_key(KeyEvent::new_with_kind(
        KeyCode::Esc,
        KeyModifiers::NONE,
        KeyEventKind::Release
    )));
    assert!(app.entry_details.is_some());
}

#[test]
fn enter_handles_empty_lists_and_entries_without_certificates() {
    let mut app = App::default();
    press(&mut app, KeyCode::Enter);
    assert!(app.entry_details.is_none());
    app.show_entries(PathBuf::from("/empty.jks"), vec![]);
    press(&mut app, KeyCode::Enter);
    assert!(app.entry_details.is_none());
    app.show_entries(
        PathBuf::from("/secret.p12"),
        vec![KeystoreEntry {
            alias: "secret".into(),
            certificate: None,
            content: Content::Certificates {
                kind: Kind::SecretKey,
                certificates: vec![],
            },
            chain_warning: None,
        }],
    );
    press(&mut app, KeyCode::Enter);
    let rendered = screen(&mut app, 100, 24);
    assert!(rendered.contains("Type: Secret key"));
    assert!(rendered.contains("No certificate is stored with this entry"));
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(press(&mut app, KeyCode::Esc));
}

fn certificate_entry(alias: &str, not_after: Asn1Time) -> KeystoreEntry {
    KeystoreEntry {
        alias: alias.into(),
        certificate: Some(Summary {
            not_after: Some(not_after),
            ..fixture_summary()
        }),
        content: Content::Certificates {
            kind: Kind::TrustedCertificate,
            certificates: vec![test_support::fixture_certificate_der().to_vec()],
        },
        chain_warning: None,
    }
}

fn triage_app() -> App {
    let mut app = App::default();
    let date = |year| Asn1Time::new(year, 1, 1, 0, 0, 0, true).unwrap();
    app.show_entries(
        PathBuf::from("/keystore.jks"),
        vec![
            certificate_entry("alpha", date(2040)),
            certificate_entry("beta-quit", date(2035)),
            KeystoreEntry {
                alias: "gamma".into(),
                certificate: None,
                content: Content::Certificates {
                    kind: Kind::SecretKey,
                    certificates: vec![],
                },
                chain_warning: None,
            },
            certificate_entry("zeta", date(2030)),
        ],
    );
    app
}

fn selected_alias(app: &App) -> &str {
    &app.entries[app.selected_entry().unwrap()].alias
}

fn shown_aliases(app: &App) -> Vec<&str> {
    app.visible
        .iter()
        .map(|&index| app.entries[index].alias.as_str())
        .collect()
}

#[test]
fn entry_selection_cycles_in_display_order_with_and_without_a_filter() {
    for (up, down) in [
        (KeyCode::Up, KeyCode::Down),
        (KeyCode::Char('k'), KeyCode::Char('j')),
    ] {
        let mut app = triage_app();
        for sort in [SortOrder::Alias, SortOrder::Expiry] {
            app.sort = sort;
            app.refresh_visible();
            let expected = shown_aliases(&app)
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            app.entries_state.select(Some(0));
            press(&mut app, up);
            assert_eq!(selected_alias(&app), expected.last().unwrap());
            for alias in &expected {
                press(&mut app, down);
                assert_eq!(selected_alias(&app), alias);
            }
        }
    }

    let mut app = triage_app();
    // This filter leaves zeta and beta-quit, in expiry order.
    app.sort = SortOrder::Expiry;
    press(&mut app, KeyCode::Char('/'));
    type_password(&mut app, "ta");
    assert_eq!(shown_aliases(&app), ["zeta", "beta-quit"]);
    assert_eq!(selected_alias(&app), "zeta");
    press(&mut app, KeyCode::Up);
    assert_eq!(selected_alias(&app), "beta-quit");
    press(&mut app, KeyCode::Down);
    assert_eq!(selected_alias(&app), "zeta");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Up);
    assert_eq!(selected_alias(&app), "beta-quit");
    press(&mut app, KeyCode::Down);
    assert_eq!(selected_alias(&app), "zeta");
}

#[test]
fn entry_selection_starts_at_the_first_row_when_none_is_selected() {
    for key in [KeyCode::Up, KeyCode::Down] {
        let mut app = triage_app();
        app.entries_state.select(None);
        press(&mut app, key);
        assert_eq!(app.entries_state.selected(), Some(0));
    }
}

#[test]
fn entry_selection_past_the_end_moves_from_the_last_row() {
    let last = triage_app().visible.len() - 1;
    for (key, expected) in [(KeyCode::Up, last - 1), (KeyCode::Down, 0)] {
        let mut app = triage_app();
        app.entries_state.select(Some(last + 5));
        press(&mut app, key);
        assert_eq!(app.entries_state.selected(), Some(expected));
    }
}

#[test]
fn entry_selection_handles_single_and_empty_lists() {
    let mut app = triage_app();
    press(&mut app, KeyCode::Char('/'));
    type_password(&mut app, "quit");
    for key in [KeyCode::Up, KeyCode::Down] {
        press(&mut app, key);
        assert_eq!(selected_alias(&app), "beta-quit");
    }
    type_password(&mut app, "no-match");
    for key in [KeyCode::Up, KeyCode::Down] {
        press(&mut app, key);
        assert_eq!(app.entries_state.selected(), None);
    }
    press(&mut app, KeyCode::Enter);
    for key in [
        KeyCode::Up,
        KeyCode::Down,
        KeyCode::Char('j'),
        KeyCode::Char('k'),
    ] {
        press(&mut app, key);
        assert_eq!(app.entries_state.selected(), None);
    }
    app.show_entries(PathBuf::from("/empty.jks"), vec![]);
    for key in [KeyCode::Up, KeyCode::Down] {
        press(&mut app, key);
        assert_eq!(app.entries_state.selected(), None);
    }
}

#[test]
fn filter_updates_live_and_types_shortcut_letters() {
    let mut app = triage_app();
    assert!(screen(&mut app, 100, 20).contains("4 entries | Sort: alias"));
    assert!(!press(&mut app, KeyCode::Char('/')));
    assert!(app.editing_filter);
    assert!(screen(&mut app, 100, 20).contains("Type to filter"));
    // Shortcut letters, including q, are typed rather than acted on.
    for ch in ['Q', 'u', 'i', 't', 's', 'o', 'j'] {
        assert!(!press(&mut app, KeyCode::Char(ch)));
    }
    assert_eq!(app.filter, "Quitsoj");
    assert_eq!(app.sort, SortOrder::Alias);
    assert!(app.file_picker.is_none());
    let rendered = screen(&mut app, 100, 20);
    assert!(rendered.contains("No matching entries."), "{rendered}");
    assert!(rendered.contains("Filter: Quitsoj_ | 0 of 4 entries"));
    assert!(!press(&mut app, KeyCode::Enter));
    assert!(app.entry_details.is_none());
    assert!(!app.editing_filter);
    press(&mut app, KeyCode::Char('/'));
    for _ in 0..3 {
        press(&mut app, KeyCode::Backspace);
    }
    assert_eq!(shown_aliases(&app), ["beta-quit"]);
    assert!(screen(&mut app, 100, 20).contains("Filter: Quit_ | 1 of 4 entries"));
    // Modifier chords are not typed, and Ctrl+C still quits while typing.
    app.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::ALT));
    assert_eq!(app.filter, "Quit");
    assert!(app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
}

#[test]
fn escape_cancels_filter_and_applied_filter_keeps_quit_keys() {
    let mut app = triage_app();
    press(&mut app, KeyCode::Char('/'));
    type_password(&mut app, "ZET");
    assert_eq!(shown_aliases(&app), ["zeta"]);
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(!app.editing_filter);
    assert!(app.filter.is_empty());
    assert_eq!(app.visible.len(), 4);
    assert_eq!(selected_alias(&app), "zeta");

    // An applied filter matches subjects too and survives Enter.
    press(&mut app, KeyCode::Char('/'));
    type_password(&mut app, "test fixture");
    press(&mut app, KeyCode::Enter);
    assert!(!app.editing_filter);
    assert_eq!(shown_aliases(&app), ["alpha", "beta-quit", "zeta"]);
    let rendered = screen(&mut app, 100, 20);
    assert!(rendered.contains("Filter: 'test fixture' | 3 of 4 entries | Sort: alias"));
    assert!(press(&mut app, KeyCode::Esc));
    assert!(press(&mut app, KeyCode::Char('q')));

    // Reopening `/` edits the applied filter; Esc clears it.
    press(&mut app, KeyCode::Char('/'));
    assert_eq!(app.filter, "test fixture");
    press(&mut app, KeyCode::Esc);
    assert!(app.filter.is_empty());
    assert!(screen(&mut app, 100, 20).contains("4 entries | Sort: alias"));
}

#[test]
fn enter_opens_the_selected_filtered_entry() {
    let mut app = triage_app();
    press(&mut app, KeyCode::Char('/'));
    type_password(&mut app, "ta");
    assert_eq!(shown_aliases(&app), ["beta-quit", "zeta"]);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Down);
    screen(&mut app, 100, 20);
    assert_eq!(selected_alias(&app), "beta-quit");
    press(&mut app, KeyCode::Up);
    assert_eq!(selected_alias(&app), "zeta");
    press(&mut app, KeyCode::Enter);
    assert!(app.entry_details.is_some());
    assert!(screen(&mut app, 120, 40).starts_with("zeta — "));
    press(&mut app, KeyCode::Esc);
    assert_eq!(selected_alias(&app), "zeta");
    assert_eq!(app.filter, "ta");

    // An empty result cannot open details.
    press(&mut app, KeyCode::Char('/'));
    type_password(&mut app, "nothing");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Enter);
    assert!(app.entry_details.is_none());
    assert!(screen(&mut app, 100, 20).contains("No matching entries."));
}

#[test]
fn sort_cycles_between_alias_and_expiry_keeping_the_selection() {
    let mut app = triage_app();
    press(&mut app, KeyCode::Down);
    assert_eq!(selected_alias(&app), "beta-quit");
    assert!(!press(&mut app, KeyCode::Char('s')));
    assert_eq!(app.sort, SortOrder::Expiry);
    assert_eq!(shown_aliases(&app), ["zeta", "beta-quit", "alpha", "gamma"]);
    assert_eq!(selected_alias(&app), "beta-quit");
    let rendered = screen(&mut app, 100, 20);
    assert!(rendered.contains("Sort: expiry"), "{rendered}");
    let aliases = ["zeta", "beta-quit", "alpha", "gamma"];
    let rows: Vec<_> = rendered
        .lines()
        .filter_map(|line| aliases.into_iter().find(|alias| line.contains(alias)))
        .collect();
    assert_eq!(rows, aliases);

    press(&mut app, KeyCode::Char('s'));
    assert_eq!(app.sort, SortOrder::Alias);
    assert_eq!(selected_alias(&app), "beta-quit");
    assert!(screen(&mut app, 100, 20).contains("Sort: alias"));

    // A hidden selection falls back to the first shown entry.
    press(&mut app, KeyCode::Char('/'));
    type_password(&mut app, "al");
    assert_eq!(shown_aliases(&app), ["alpha"]);
    assert_eq!(selected_alias(&app), "alpha");

    // The sort order persists when another keystore is shown; the filter does not.
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('s'));
    let entries = std::mem::take(&mut app.entries);
    app.show_entries(PathBuf::from("/other.jks"), entries);
    assert_eq!(app.sort, SortOrder::Expiry);
    assert!(app.filter.is_empty());
    assert_eq!(selected_alias(&app), "zeta");
}

#[test]
fn expiring_soon_dates_use_a_readable_warning_color() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let soon = Asn1Time::from_unix(now + 10 * 24 * 60 * 60, false);
    let soon_text = Summary {
        not_after: Some(soon),
        ..fixture_summary()
    }
    .expiry_text();
    let mut app = App::default();
    app.show_entries(
        PathBuf::from("/keystore.jks"),
        vec![
            certificate_entry("current", Asn1Time::from_unix(now + 400 * 86400, false)),
            certificate_entry("soon", soon),
            certificate_entry("expired", Asn1Time::new(2001, 2, 3, 0, 0, 0, true).unwrap()),
        ],
    );
    let colored = |app: &mut App, fg: Color| -> String {
        buffer(app, 100, 20)
            .content
            .iter()
            .filter(|cell| cell.fg == fg)
            .map(|cell| cell.symbol())
            .collect()
    };
    assert_eq!(colored(&mut app, Color::Yellow), soon_text);
    assert_eq!(red_text(&mut app), "2001-02-03");

    press(&mut app, KeyCode::Down);
    assert!(colored(&mut app, Color::Yellow).is_empty());
    let rendered = buffer(&mut app, 100, 20);
    let selected_row = rendered
        .content
        .chunks(100)
        .find(|row| row.iter().any(|cell| cell.symbol() == ">"))
        .unwrap();
    let warning: String = selected_row
        .iter()
        .filter(|cell| cell.bg == Color::Rgb(255, 175, 0))
        .inspect(|cell| {
            assert_eq!(cell.fg, Color::Rgb(0, 0, 0));
            assert!(cell.modifier.contains(ratatui::style::Modifier::BOLD));
        })
        .map(|cell| cell.symbol())
        .collect();
    assert_eq!(warning, soon_text);
    assert_eq!(red_text(&mut app), "2001-02-03");
}

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
    assert!(screen(&mut app, 120, 40).contains("Save chain to: "));
    app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    type_password(&mut app, "chain.der");
    press(&mut app, KeyCode::Enter);
    assert!(red_text(&mut app).contains("use a .pem name"));
    assert!(app.entry_details.as_ref().unwrap().exporting());
    press(&mut app, KeyCode::Esc);
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

/// Opens `mixed_keystore()`, saved as `store.jks`, with its password.
fn editing(directory: &TestDirectory) -> (App, PathBuf) {
    let path = directory.path().join("store.jks");
    fs::write(&path, mixed_keystore()).unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.entries.len(), 2);
    (app, path)
}

fn aliases(path: &Path) -> Vec<String> {
    keystore::load_entries(&fs::read(path).unwrap(), "changeit")
        .unwrap()
        .into_iter()
        .map(|entry| entry.alias)
        .collect()
}

#[test]
fn deleting_an_entry_asks_first_and_changes_the_file_only_on_save() {
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    assert!(screen(&mut app, 120, 24).contains("d Delete | w Save | W Save as"));

    press(&mut app, KeyCode::Char('d'));
    assert!(screen(&mut app, 120, 24).contains("Delete entry 'root-cert'? Press y"));
    // Any key other than `y` cancels, without acting as a shortcut.
    assert!(!press(&mut app, KeyCode::Char('q')));
    assert_eq!(app.entries.len(), 2);
    assert!(!app.modified);

    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Delete);
    press(&mut app, KeyCode::Char('y'));
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("Deleted entry 'server-key'."));
    assert!(rendered.contains(" keystore-tui [modified] "));
    assert!(!rendered.contains("Private key"));
    // The selection stays on a row that still exists.
    assert_eq!(app.selected_entry(), Some(0));
    assert_eq!(aliases(&path), ["root-cert", "server-key"]);

    press(&mut app, KeyCode::Char('w'));
    let rendered = screen(&mut app, 200, 24);
    assert!(rendered.contains("Saved '"));
    assert!(!rendered.contains("[modified]"));
    assert_eq!(aliases(&path), ["root-cert"]);
    press(&mut app, KeyCode::Char('w'));
    assert!(screen(&mut app, 120, 24).contains("No changes to save."));
    // The last entry can be deleted too, leaving an empty keystore.
    press(&mut app, KeyCode::Char('d'));
    press(&mut app, KeyCode::Char('y'));
    assert_eq!(app.selected_entry(), None);
    press(&mut app, KeyCode::Char('w'));
    assert!(aliases(&path).is_empty());
    assert!(press(&mut app, KeyCode::Char('q')));
}

#[test]
fn deleting_a_filtered_entry_removes_that_entry() {
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    press(&mut app, KeyCode::Char('/'));
    type_password(&mut app, "server");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('d'));
    assert!(screen(&mut app, 120, 24).contains("Delete entry 'server-key'?"));
    press(&mut app, KeyCode::Char('y'));
    press(&mut app, KeyCode::Char('w'));
    assert_eq!(aliases(&path), ["root-cert"]);
}

#[test]
fn unsaved_changes_are_confirmed_before_quitting_or_opening_a_file() {
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    press(&mut app, KeyCode::Char('d'));
    press(&mut app, KeyCode::Char('y'));

    for key in [KeyCode::Char('q'), KeyCode::Esc] {
        assert!(!press(&mut app, key));
        assert!(screen(&mut app, 120, 24).contains("Quit without saving the changes?"));
        assert!(!press(&mut app, KeyCode::Char('n')));
        assert!(app.confirm.is_none());
    }
    // From the details, the question replaces the view until it is answered.
    press(&mut app, KeyCode::Enter);
    assert!(!press(&mut app, KeyCode::Char('q')));
    assert!(screen(&mut app, 120, 24).contains("Quit without saving the changes?"));
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.entry_details.is_some());
    press(&mut app, KeyCode::Esc);

    press(&mut app, KeyCode::Char('o'));
    assert!(screen(&mut app, 120, 24).contains("discards the unsaved changes"));
    assert!(app.file_picker.is_none());
    press(&mut app, KeyCode::Char('y'));
    assert!(app.file_picker.is_some());
    // Cancelling the browser keeps the changes.
    press(&mut app, KeyCode::Esc);
    assert!(app.modified);

    assert!(!press(&mut app, KeyCode::Char('q')));
    assert!(press(&mut app, KeyCode::Char('y')));
    assert_eq!(aliases(&path), ["root-cert", "server-key"]);

    // Ctrl+C quits at once.
    let (mut app, _) = editing(&directory);
    press(&mut app, KeyCode::Char('d'));
    press(&mut app, KeyCode::Char('y'));
    assert!(app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
}

#[test]
fn save_as_writes_a_new_file_and_switches_to_it() {
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    press(&mut app, KeyCode::Char('d'));
    press(&mut app, KeyCode::Char('y'));
    press(&mut app, KeyCode::Char('W'));
    let copy = directory.path().join("store-copy.jks");
    assert!(screen(&mut app, 200, 24).contains(&format!("Save keystore as: {}_", copy.display())));
    // Letters are typed into the name instead of quitting.
    assert!(!press(&mut app, KeyCode::Char('q')));
    press(&mut app, KeyCode::Backspace);
    // An existing file is never replaced.
    app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    type_password(&mut app, "store.jks");
    press(&mut app, KeyCode::Enter);
    assert!(red_text(&mut app).contains("already exists"));
    assert!(app.save_as.is_some());
    app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    type_password(&mut app, "store-copy.jks");
    press(&mut app, KeyCode::Enter);

    let copy = canonical_path::canonicalize(&copy).unwrap();
    assert!(app.save_as.is_none());
    assert!(!app.modified);
    assert_eq!(app.keystore_path.as_deref(), Some(copy.as_path()));
    assert_eq!(aliases(&copy), ["server-key"]);
    assert_eq!(aliases(&path), ["root-cert", "server-key"]);
    // Later saves go to the new file.
    press(&mut app, KeyCode::Char('d'));
    press(&mut app, KeyCode::Char('y'));
    press(&mut app, KeyCode::Char('w'));
    assert!(aliases(&copy).is_empty());
    assert_eq!(aliases(&path), ["root-cert", "server-key"]);
}

#[test]
fn certificate_files_cannot_be_changed() {
    let directory = TestDirectory::new();
    for (name, data) in [("bundle.pem", test_support::BUNDLE_PEM)] {
        let path = directory.path().join(name);
        fs::write(&path, data).unwrap();
        let mut app = App::default();
        app.open_file(path.clone());
        assert!(!app.entries.is_empty(), "{name}");
        assert!(!screen(&mut app, 120, 24).contains("d Delete |"), "{name}");
        for key in ['d', 'w', 'W'] {
            press(&mut app, KeyCode::Char(key));
            assert!(app.confirm.is_none() && app.save_as.is_none(), "{name}");
            assert!(red_text(&mut app).contains(NOT_EDITABLE), "{name} {key}");
        }
        assert_eq!(fs::read(&path).unwrap(), data, "{name}");
    }
    // Without a loaded file the keys do nothing.
    let mut app = App::default();
    for key in ['d', 'w', 'W'] {
        press(&mut app, KeyCode::Char(key));
        assert!(app.message.is_none());
    }
}

fn type_alias(app: &mut App, alias: &str) {
    app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    type_password(app, alias);
    press(app, KeyCode::Enter);
}

#[test]
fn renaming_an_entry_keeps_alias_order_and_is_written_on_save() {
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    assert!(screen(&mut app, 120, 24).contains("i Import | r Rename | d Delete"));
    press(&mut app, KeyCode::Char('r'));
    assert!(screen(&mut app, 120, 24).contains("New alias for 'root-cert': root-cert_"));
    // Letters are typed into the alias instead of quitting.
    assert!(!press(&mut app, KeyCode::Char('q')));
    assert!(screen(&mut app, 120, 24).contains("root-certq_"));
    press(&mut app, KeyCode::Backspace);
    // Confirming the unchanged alias changes nothing.
    press(&mut app, KeyCode::Enter);
    assert!(app.alias_prompt.is_none() && !app.modified);

    press(&mut app, KeyCode::Char('r'));
    for (alias, error) in [
        ("", "Type an alias"),
        ("SERVER-key", "An entry named 'server-key' already exists."),
    ] {
        type_alias(&mut app, alias);
        assert!(red_text(&mut app).contains(error), "{alias}");
        assert!(app.alias_prompt.is_some() && !app.modified);
    }
    // Aliases are stored in lower case, as Java does.
    type_alias(&mut app, "Zulu-Ü");
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("Renamed entry 'root-cert' to 'zulu-ü'."));
    assert!(rendered.contains("[modified]"));
    assert_eq!(app.entries[1].alias, "zulu-ü");
    // The renamed entry stays selected in its new row.
    assert_eq!(app.selected_entry(), Some(1));
    assert_eq!(aliases(&path), ["root-cert", "server-key"]);
    press(&mut app, KeyCode::Char('w'));
    assert!(screen(&mut app, 200, 24).contains("Saved '"));
    assert_eq!(aliases(&path), ["server-key", "zulu-ü"]);

    // Esc cancels.
    press(&mut app, KeyCode::Char('r'));
    press(&mut app, KeyCode::Esc);
    assert!(app.alias_prompt.is_none() && !app.modified);
}

#[test]
fn importing_a_certificate_adds_a_trusted_entry() {
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    fs::write(
        directory.path().join("ca.pem"),
        test_support::TRUSTED_CERT_PEM,
    )
    .unwrap();
    fs::write(
        directory.path().join("bundle.pem"),
        test_support::BUNDLE_PEM,
    )
    .unwrap();
    fs::write(
        directory.path().join("request.csr"),
        test_support::KEYTOOL_REQUEST,
    )
    .unwrap();

    // Files without exactly one certificate are refused.
    for (name, error) in [
        ("bundle", "holds 2 certificates"),
        ("request", "holds no certificate"),
        ("store", "is not a certificate file"),
    ] {
        press(&mut app, KeyCode::Char('i'));
        assert!(screen(&mut app, 120, 24).contains(" Import certificate or key pair from file "));
        type_password(&mut app, name);
        press(&mut app, KeyCode::Enter);
        assert!(red_text(&mut app).contains(error), "{name}");
        assert!(
            app.file_picker.is_none() && app.alias_prompt.is_none(),
            "{name}"
        );
        assert!(!app.modified && !app.importing, "{name}");
    }
    // Cancelling the browser leaves the import.
    press(&mut app, KeyCode::Char('i'));
    press(&mut app, KeyCode::Esc);
    assert!(!app.importing);
    assert_eq!(app.keystore_path.as_deref(), Some(path.as_path()));

    press(&mut app, KeyCode::Char('i'));
    type_password(&mut app, "ca");
    press(&mut app, KeyCode::Enter);
    // The subject's common name, in lower case, is suggested.
    assert!(
        screen(&mut app, 120, 24)
            .contains("Alias for the imported certificate: jks tui test fixture_")
    );
    type_alias(&mut app, "root-cert");
    assert!(red_text(&mut app).contains("already exists"));
    type_alias(&mut app, "New-CA");
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("Imported certificate as 'new-ca'."));
    assert!(rendered.contains("[modified]"));
    assert_eq!(app.selected_entry(), Some(0));
    assert_eq!(
        app.entries[0],
        KeystoreEntry {
            alias: "new-ca".into(),
            certificate: Some(fixture_summary()),
            content: Content::Certificates {
                kind: Kind::TrustedCertificate,
                certificates: vec![test_support::fixture_certificate_der().to_vec()],
            },
            chain_warning: None,
        }
    );
    // The imported entry opens in the details like any other.
    press(&mut app, KeyCode::Enter);
    assert!(app.entry_details.is_some());
    press(&mut app, KeyCode::Esc);

    press(&mut app, KeyCode::Char('w'));
    assert_eq!(aliases(&path), ["new-ca", "root-cert", "server-key"]);
    let saved = keystore::load_entries(&fs::read(&path).unwrap(), "changeit").unwrap();
    assert_eq!(saved, app.entries);
}

#[test]
fn rename_and_import_need_an_editable_keystore() {
    let directory = TestDirectory::new();
    let path = directory.path().join("bundle.pem");
    fs::write(&path, test_support::BUNDLE_PEM).unwrap();
    let mut app = App::default();
    app.open_file(path);
    for key in ['r', 'i'] {
        press(&mut app, KeyCode::Char(key));
        assert!(app.alias_prompt.is_none() && app.file_picker.is_none());
        assert!(red_text(&mut app).contains(NOT_EDITABLE), "{key}");
    }
    let mut app = App::default();
    for key in ['r', 'i'] {
        press(&mut app, KeyCode::Char(key));
        assert!(app.message.is_none() && app.file_picker.is_none());
    }
}

/// Chooses the file starting with `name` in the import file browser.
fn import(app: &mut App, name: &str) {
    press(app, KeyCode::Char('i'));
    type_password(app, name);
    press(app, KeyCode::Enter);
}

/// PEM text of the synthetic Ed25519 key `key` and of `certificates`.
fn key_pem(label: &str, key: &[u8], certificates: &[&[u8]]) -> String {
    use crown::asn1::pem;
    let mut text = pem::encode(label, key);
    for certificate in certificates {
        text.push_str(&pem::encode("CERTIFICATE", certificate));
    }
    text
}

#[test]
fn importing_a_key_pair_adds_a_private_key_entry() {
    use test_support::{TestRng, ed25519_certificate, ed25519_pkcs8};
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
fn key_pairs_are_imported_from_and_into_pkcs12_keystores() {
    use test_support::{TestRng, ed25519_certificate, ed25519_pkcs8};
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
    // PKCS12 files without exactly one key are refused.
    for name in ["none", "two"] {
        import(&mut app, name);
        type_password(&mut app, "srcpass");
        press(&mut app, KeyCode::Enter);
        assert!(
            red_text(&mut app).contains("it must hold exactly one private key"),
            "{name}"
        );
        assert!(app.key_import.is_none());
    }
    assert_eq!(app.entries.len(), 1);

    // A passwordless truststore has no password to protect a key with. The
    // certificate request in the key's file is passed over.
    let mut text = key_pem("PRIVATE KEY", &key, &[&leaf]).into_bytes();
    text.extend_from_slice(test_support::KEYTOOL_REQUEST);
    write("request.pem", &text);
    let path = directory.path().join("open.p12");
    fs::write(&path, include_bytes!("../tests/fixtures/passwordless.p12")).unwrap();
    let mut app = App::default();
    app.open_file(path);
    assert!(app.document.is_some());
    import(&mut app, "request");
    press(&mut app, KeyCode::Enter);
    assert!(red_text(&mut app).contains("a key needs a keystore password that is not empty"));
    assert!(!app.modified);
}

fn type_new_password(app: &mut App, first: &str, second: &str) {
    type_password(app, first);
    press(app, KeyCode::Enter);
    type_password(app, second);
    press(app, KeyCode::Enter);
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
fn creating_a_keystore_writes_an_empty_file_and_opens_it() {
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    fs::write(directory.path().join("keystore.jks"), b"existing").unwrap();
    press(&mut app, KeyCode::Char('n'));
    let suggested = directory.path().join("keystore-2.jks");
    assert!(screen(&mut app, 200, 24).contains(&format!(
        "New keystore file (.jks, .jceks, or .p12): {}_",
        suggested.display()
    )));
    type_alias(&mut app, "store.jks");
    assert!(red_text(&mut app).contains("already exists"));
    assert!(app.save_as.is_some() && app.new_password.is_none());
    type_alias(&mut app, "new.JCEKS");
    assert!(screen(&mut app, 120, 24).contains("Password for the new keystore: _"));
    let created = directory.path().join("new.JCEKS");
    // Nothing is created before the password is confirmed.
    assert!(!created.exists());
    type_new_password(&mut app, "secret", "secret");

    let created = canonical_path::canonicalize(&created).unwrap();
    let rendered = screen(&mut app, 200, 24);
    assert!(rendered.contains("Created the JCEKS keystore"));
    assert!(rendered.contains("This keystore contains no entries."));
    assert_eq!(app.keystore_path.as_deref(), Some(created.as_path()));
    assert!(!app.modified && app.document.is_some());
    let data = fs::read(&created).unwrap();
    assert!(keystore::is_jceks(&data));
    assert!(keystore::load_entries(&data, "secret").unwrap().is_empty());
    assert_eq!(aliases(&path), ["root-cert", "server-key"]);

    // The new keystore can be filled and saved with its password.
    fs::write(
        directory.path().join("ca.pem"),
        test_support::TRUSTED_CERT_PEM,
    )
    .unwrap();
    press(&mut app, KeyCode::Char('i'));
    type_password(&mut app, "ca");
    press(&mut app, KeyCode::Enter);
    type_alias(&mut app, "ca");
    press(&mut app, KeyCode::Char('w'));
    let data = fs::read(&created).unwrap();
    assert_eq!(
        keystore::load_entries(&data, "secret").unwrap(),
        app.entries
    );
    assert_eq!(app.entries.len(), 1);
}

#[test]
fn a_keystore_can_be_created_before_any_file_is_open() {
    let directory = TestDirectory::in_working_directory();
    let mut app = App::default();
    assert!(
        screen(&mut app, 120, 24).contains("Press n to create a JKS, JCEKS, or PKCS12 keystore.")
    );
    press(&mut app, KeyCode::Char('n'));
    assert!(app.save_as.as_ref().is_some_and(|prompt| prompt.creating));
    press(&mut app, KeyCode::Esc);
    assert!(app.save_as.is_none() && app.keystore_path.is_none());

    press(&mut app, KeyCode::Char('n'));
    let path = directory.path().join("first.jks");
    type_alias(&mut app, &path.to_string_lossy());
    // Keys that are not text are ignored.
    press(&mut app, KeyCode::Tab);
    // An empty password is allowed, as for the stores the app opens.
    type_new_password(&mut app, "", "");
    let data = fs::read(&path).unwrap();
    assert!(!keystore::is_jceks(&data));
    assert_eq!(data, empty_keystore());
    assert!(app.document.is_some());

    // A file that cannot be created is reported, and the loaded file stays.
    press(&mut app, KeyCode::Char('n'));
    let missing = directory.path().join("missing").join("new.jks");
    type_alias(&mut app, &missing.to_string_lossy());
    type_new_password(&mut app, "secret", "secret");
    assert!(red_text(&mut app).contains("Cannot create"));
    assert!(app.new_password.is_none());
    assert_eq!(
        app.keystore_path.as_deref().map(fs::read).unwrap().unwrap(),
        data
    );
}

#[test]
fn creating_a_keystore_asks_before_discarding_changes() {
    let directory = TestDirectory::new();
    let (mut app, _) = editing(&directory);
    press(&mut app, KeyCode::Char('d'));
    press(&mut app, KeyCode::Char('y'));
    press(&mut app, KeyCode::Char('n'));
    assert!(
        screen(&mut app, 120, 24).contains("Creating a keystore discards the unsaved changes.")
    );
    press(&mut app, KeyCode::Char('x'));
    assert!(app.save_as.is_none());
    press(&mut app, KeyCode::Char('n'));
    press(&mut app, KeyCode::Char('y'));
    assert!(app.save_as.is_some());
    // The changes are kept until the keystore is created.
    press(&mut app, KeyCode::Esc);
    assert!(app.modified);

    // A passwordless PKCS12 truststore has no password to change.
    let path = directory.path().join("store.p12");
    let data = include_bytes!("../tests/fixtures/passwordless.p12");
    fs::write(&path, data).unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    press(&mut app, KeyCode::Char('p'));
    type_new_password(&mut app, "secret", "secret");
    assert!(red_text(&mut app).contains("not protected by a password"));
    assert!(!app.modified);
    assert_eq!(fs::read(&path).unwrap(), data);
}

/// The entries of the PKCS12 keystore at `path`, read completely.
fn pkcs12_entries(path: &Path, password: &str) -> Vec<KeystoreEntry> {
    let verified = pkcs12::parse(&fs::read(path).unwrap())
        .unwrap()
        .verify(password)
        .unwrap();
    assert!(!verified.incomplete);
    verified.entries
}

#[test]
fn pkcs12_keystores_are_edited_and_saved_like_the_others() {
    let directory = TestDirectory::new();
    let path = directory.path().join("store.p12");
    let original = include_bytes!("../tests/fixtures/trusted-cert.p12");
    fs::write(&path, original).unwrap();
    let ca = test_support::metadata_certificate("New CA", "New CA", &[1], &[]);
    fs::write(directory.path().join("ca.der"), &ca).unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 24).contains("i Import | r Rename"));

    press(&mut app, KeyCode::Char('r'));
    type_alias(&mut app, "Renamed");
    assert!(screen(&mut app, 120, 24).contains("Renamed entry 'root-cert' to 'renamed'."));
    press(&mut app, KeyCode::Char('i'));
    type_password(&mut app, "ca");
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 24).contains("Alias for the imported certificate: new ca_"));
    type_alias(&mut app, "renamed");
    assert!(red_text(&mut app).contains("already exists"));
    type_alias(&mut app, "added");
    assert_eq!(app.selected_entry(), Some(0));
    assert_eq!(app.entries[0].kind(), "Trusted certificate");
    press(&mut app, KeyCode::Char('p'));
    type_new_password(&mut app, "new-secret", "new-secret");
    assert!(screen(&mut app, 120, 24).contains("Password changed"));
    // Nothing reached the file yet.
    assert_eq!(fs::read(&path).unwrap(), original);

    press(&mut app, KeyCode::Char('w'));
    assert!(screen(&mut app, 200, 24).contains("Saved '"));
    assert!(!app.modified);
    let saved = pkcs12_entries(&path, "new-secret");
    assert_eq!(saved, app.entries);
    assert_eq!(saved.len(), 2);
    assert!(matches!(
        pkcs12::parse(&fs::read(&path).unwrap())
            .unwrap()
            .verify("changeit"),
        Err(pkcs12::VerifyError::Password)
    ));

    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Char('d'));
    assert!(screen(&mut app, 120, 24).contains("Delete entry 'renamed'?"));
    press(&mut app, KeyCode::Char('y'));
    press(&mut app, KeyCode::Char('W'));
    type_alias(&mut app, "copy.p12");
    let copy = directory.path().join("copy.p12");
    assert_eq!(pkcs12_entries(&copy, "new-secret"), app.entries);
    assert_eq!(app.entries.len(), 1);
    assert_eq!(pkcs12_entries(&path, "new-secret").len(), 2);

    // The saved store opens again in the app with the new password.
    let mut reopened = App::default();
    reopened.open_file(copy);
    type_password(&mut reopened, "new-secret");
    press(&mut reopened, KeyCode::Enter);
    assert_eq!(reopened.entries, app.entries);
}

#[test]
fn a_pkcs12_keystore_is_created_from_a_p12_or_pfx_name() {
    let directory = TestDirectory::in_working_directory();
    let mut app = App::default();
    press(&mut app, KeyCode::Char('n'));
    let path = directory.path().join("new.PFX");
    type_alias(&mut app, &path.to_string_lossy());
    // PKCS12 needs a password; nothing is created without one.
    type_new_password(&mut app, "", "");
    assert!(red_text(&mut app).contains("needs a password that is not empty"));
    assert!(!path.exists() && app.keystore_path.is_none());

    press(&mut app, KeyCode::Char('n'));
    type_alias(&mut app, &path.to_string_lossy());
    type_new_password(&mut app, "secret", "secret");
    assert!(screen(&mut app, 200, 24).contains("Created the PKCS12 keystore"));
    assert!(pkcs12_entries(&path, "secret").is_empty());
    assert!(app.document.is_some() && !app.modified);
}

#[test]
fn an_incompletely_read_pkcs12_keystore_cannot_be_changed() {
    let directory = TestDirectory::new();
    let path = directory.path().join("partial.p12");
    let data = include_bytes!("../tests/fixtures/invalid-ciphertext-no-mac.p12");
    fs::write(&path, data).unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    assert_eq!(app.warning, Some(INCOMPLETE_WARNING));
    for key in ['i', 'p', 'w', 'W'] {
        press(&mut app, KeyCode::Char(key));
        assert!(
            red_text(&mut app).contains(INCOMPLETE_NOT_EDITABLE),
            "{key}"
        );
    }
    assert_eq!(fs::read(&path).unwrap(), data);
}

/// A keystore saved as `name` with a trusted certificate and two private
/// keys holding synthetic bytes: `own`, protected by `keypass`, and `shared`,
/// protected by the keystore's password, `changeit`.
fn keystore_with_keys(directory: &TestDirectory, name: &str) -> (App, PathBuf, Vec<u8>) {
    use keystore::{PRIVATE_KEY_TAG, TRUSTED_CERT_TAG, VERSION_02};
    use test_support::{Builder, TestRng, synthetic_pkcs8};
    let jceks = name.ends_with(".jceks");
    let key = synthetic_pkcs8(b"synthetic, not a private key");
    let mut builder = if jceks {
        Builder::jceks(VERSION_02, 3)
    } else {
        Builder::new(VERSION_02, 3)
    };
    builder.entry(TRUSTED_CERT_TAG, b"cert", VERSION_02, 1);
    for (alias, password) in [(&b"own"[..], "keypass"), (b"shared", "changeit")] {
        builder.entry_header(PRIVATE_KEY_TAG, alias);
        builder.payload(&key_protection::protect(&key, password, jceks, &mut TestRng(0)).unwrap());
        builder.u32_field(1);
        builder.certificate(VERSION_02);
    }
    let path = directory.path().join(name);
    fs::write(&path, builder.finish("changeit")).unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.entries.len(), 3);
    (app, path, key)
}

/// The key that `password` recovers from the entry listed at `index` of the
/// keystore saved at `path`.
fn saved_key(path: &Path, index: usize, password: &str) -> Result<Vec<u8>, key_protection::Error> {
    let (_, writable) = keystore::parse(fs::read(path).unwrap())
        .unwrap()
        .open("changeit")
        .ok()
        .unwrap();
    key_protection::recover(writable.protected_key(index).unwrap(), password)
        .map(|key| key.to_vec())
}

#[test]
fn a_key_password_is_changed_after_unlocking_the_key() {
    let directory = TestDirectory::new();
    for name in ["store.jks", "store.jceks"] {
        let (mut app, path, key) = keystore_with_keys(&directory, name);
        let original = fs::read(&path).unwrap();
        assert!(
            screen(&mut app, 120, 24).contains("p Password | P Key password"),
            "{name}"
        );

        // A certificate has no password of its own.
        press(&mut app, KeyCode::Char('P'));
        assert!(red_text(&mut app).contains("Only private keys"), "{name}");
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
    fs::write(&path, include_bytes!("../tests/fixtures/trusted-cert.p12")).unwrap();
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
    use keystore::{SECRET_KEY_TAG, VERSION_02};
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
        error.contains("the secret key 'aes' cannot be converted yet"),
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
