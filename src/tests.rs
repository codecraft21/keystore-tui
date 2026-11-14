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
    assert!(screen(&mut app, 120, 24).contains("w Save | W Save as | p Password"));

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
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains(
        "Keystore: n New | g Generate | G Secret key | i Import | w Save | W Save as | p Password"
    ));
    assert!(rendered.contains(
        "Entry: e Export | c Request | R CA reply | C Chain | S Sign | r Rename | d Delete | P Key password"
    ));
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

    fs::write(directory.path().join("junk.der"), b"\x30\x03\x02\x01\x00").unwrap();
    // Files without exactly one certificate are refused.
    for (name, error) in [
        ("bundle", "holds 2 certificates"),
        ("request", "holds no certificate"),
        ("junk", "is not a certificate file"),
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
    for key in ['r', 'i', 'g', 'c', 'R', 'C', 'S', 'G'] {
        press(&mut app, KeyCode::Char(key));
        assert!(app.alias_prompt.is_none() && app.file_picker.is_none());
        assert!(app.secret_choice.is_none());
        assert!(app.generating.is_none() && app.requesting.is_none());
        assert!(app.reply.is_none() && app.chain_menu.is_none());
        assert!(app.sign_menu.is_none());
        assert!(red_text(&mut app).contains(NOT_EDITABLE), "{key}");
    }
    let mut app = App::default();
    for key in ['r', 'i', 'g', 'c', 'R', 'C', 'S', 'G'] {
        press(&mut app, KeyCode::Char(key));
        assert!(app.message.is_none() && app.file_picker.is_none());
        assert!(app.secret_choice.is_none());
        assert!(app.generating.is_none() && app.requesting.is_none());
        assert!(app.sign_menu.is_none());
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
    assert!(rendered.contains("[-] own | Private key (its key has a password of its own)"));
    assert!(rendered.contains("[ ] shared | Private key"));
    assert!(rendered.contains("Space Choose | a All | Up/Down j/k Move | Enter Import"));

    // An entry that cannot be copied is neither chosen nor imported.
    assert!(!press(&mut app, KeyCode::Char('q')));
    press(&mut app, KeyCode::Char('j'));
    press(&mut app, KeyCode::Char(' '));
    assert!(screen(&mut app, 120, 24).contains("> [-] own"));
    press(&mut app, KeyCode::Enter);
    assert!(red_text(&mut app).contains("'own' is not copied: its key has a password of its own."));
    assert!(app.copying.is_some() && app.alias_prompt.is_none());
    // The selection wraps; `a` chooses all that can be copied, or none.
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Up);
    press(&mut app, KeyCode::Char('k'));
    assert!(screen(&mut app, 120, 24).contains("> [-] own"));
    press(&mut app, KeyCode::Char('a'));
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("[x] cert") && rendered.contains("[x] shared"));
    press(&mut app, KeyCode::Char('a'));
    assert!(screen(&mut app, 120, 24).contains("[ ] cert"));
    press(&mut app, KeyCode::Char('a'));
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.message,
        Some(("Imported 2 entries from 'source.jks'.".into(), false))
    );
    assert!(app.modified && app.copying.is_none());
    assert_eq!(app.entries.len(), 4);
    press(&mut app, KeyCode::Char('w'));
    assert!(!app.modified, "{:?}", app.message);
    assert_eq!(
        aliases(&path),
        ["cert", "root-cert", "server-key", "shared"]
    );
    assert_eq!(saved_key(&path, 3, "changeit"), Ok(key.clone()));
    assert_eq!(
        app.entries,
        keystore::load_entries(&fs::read(&path).unwrap(), "changeit").unwrap()
    );

    // Aliases that exist are marked, and skipped when several are copied.
    import(&mut app, "source");
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 24).contains("[ ] cert | Trusted certificate (alias exists)"));
    press(&mut app, KeyCode::Char('a'));
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.message,
        Some((
            "Imported 0 entries from 'source.jks'. Skipped, alias exists: cert, shared.".into(),
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
    assert_eq!(app.entries.len(), 5);

    // An entry that fails stops the copy; those before it stay.
    let path = directory.path().join("open.p12");
    fs::write(&path, include_bytes!("../tests/fixtures/passwordless.p12")).unwrap();
    let mut app = App::default();
    app.open_file(path);
    import(&mut app, "source");
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('a'));
    press(&mut app, KeyCode::Enter);
    let (message, failed) = app.message.clone().unwrap();
    assert!(failed && app.modified);
    assert!(
        message.starts_with("Imported 1 entry from 'source.jks'. 'shared' failed: Not imported"),
        "{message}"
    );
    // Without a list, its keys do nothing.
    let mut app = App::default();
    app.handle_selection(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.message.is_none());
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
    assert!(rendered.contains("Export key to: ") && rendered.contains("shared.p12_"));
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
    assert!(screen(&mut app, 200, 24).contains("shared-2.p12_"));
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
    app.export_key(&file("none.key"), 0, "");
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
    assert!(
        screen(&mut app, 120, 24)
            .contains("Entry: e Export | c Request | R CA reply | C Chain | S Sign | r Rename")
    );

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
            screen(&mut app, 120, 24).contains("d Delete | P Key password"),
            "{name}"
        );

        // A certificate has no password of its own.
        press(&mut app, KeyCode::Char('P'));
        assert!(
            red_text(&mut app).contains("Only private and secret keys"),
            "{name}"
        );
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
        error.contains(
            "the secret key 'aes' stops it, because a JKS keystore cannot hold secret keys"
        ),
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
        "Save certificate request as: {}_",
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

/// Chooses the file starting with `name` as the CA reply of the selected key.
fn reply(app: &mut App, name: &str) {
    press(app, KeyCode::Char('R'));
    type_password(app, name);
    press(app, KeyCode::Enter);
}

/// Selects the entry named `alias`.
fn select(app: &mut App, alias: &str) {
    let row = app
        .visible
        .iter()
        .position(|&index| app.entries[index].alias == alias)
        .unwrap();
    app.entries_state.select(Some(row));
}

#[test]
fn a_ca_reply_replaces_the_chain_of_its_private_key() {
    use test_support::{ed25519_certificate, ed25519_pkcs8};
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
    use test_support::{TestRng, ed25519_certificate, ed25519_pkcs8};
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
    use test_support::{ed25519_certificate, ed25519_pkcs8};
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
    use test_support::{TestRng, ed25519_certificate, ed25519_pkcs8};
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
    assert!(rendered.contains(&format!("Save certificate as: {}_", expected.display())));
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
    assert!(rendered.contains(&format!("Save revocation list as: {}_", expected.display())));
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
        "Export secret key to: {}_",
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
    // It stops a conversion, and comes back with its current password.
    press(&mut app, KeyCode::Char('W'));
    type_alias(&mut app, "late.p12");
    assert!(red_text(&mut app).contains("Not converted: the secret key 'mac' has a password"));
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
    use keystore::{SECRET_KEY_TAG, VERSION_02};
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

    // A JKS keystore takes no secret key.
    let (mut jks, _) = editing(&directory);
    import(&mut jks, "source");
    type_password(&mut jks, "sourcepw");
    press(&mut jks, KeyCode::Enter);
    press(&mut jks, KeyCode::Enter);
    assert!(
        red_text(&mut jks).contains("a JKS keystore cannot hold secret keys"),
        "{:?}",
        jks.message
    );
}

/// A key pair generated on a background thread, which waits until the test
/// lets it finish with `result`.
fn slow_generation(
    app: &mut App,
    alias: &str,
) -> std::sync::mpsc::Sender<Result<generate::Generated, String>> {
    let (release, wait) = std::sync::mpsc::channel();
    app.generation = Some(generate::Job::start(
        alias.into(),
        generate::Algorithm::Rsa(4096),
        None,
        // Dropping the sender ends the thread without a result.
        move || wait.recv().unwrap(),
    ));
    release
}

fn generated_key_pair() -> generate::Generated {
    let mut rng = test_support::TestRng(3);
    let key = generate::key_pair(generate::Algorithm::Ed25519, &mut rng).unwrap();
    let request = signing::Request {
        subject: signing::Subject {
            common_name: "slow.test",
            ..signing::Subject::default()
        }
        .name(),
        days: 1,
        names: Vec::new(),
        purpose: signing::Purpose::None,
    };
    let certificate = signing::self_signed(&key, &request, 0, &mut rng).unwrap();
    (key, vec![certificate])
}

#[test]
fn the_keystore_is_read_only_while_a_key_pair_is_generated() {
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    let stored = fs::read(&path).unwrap();
    let release = slow_generation(&mut app, "slow");
    assert!(!app.poll_generation());

    // The status bar names the task, and the hints say editing is off.
    let rendered = screen(&mut app, 120, 30);
    assert!(
        rendered.contains("Generating RSA 4096 key pair 'slow'..."),
        "{rendered}"
    );
    assert!(rendered.contains("Read-only until the key pair is generated"));
    assert!(!rendered.contains("g Generate"));
    assert!(screen(&mut app, 60, 12).contains("Generating RSA 4096"));

    // Browsing still works.
    press(&mut app, KeyCode::Down);
    assert_eq!(selected_alias(&app), "server-key");
    press(&mut app, KeyCode::Char('s'));
    press(&mut app, KeyCode::Char('/'));
    assert!(app.editing_filter);
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Enter);
    assert!(app.entry_details.is_some());
    press(&mut app, KeyCode::Esc);
    assert!(app.entry_details.is_none());

    // Every edit is refused, and nothing is queued.
    for key in ['g', 'G', 'i', 'd', 'r', 'p', 'P', 'C', 'R', 'w', 'W'] {
        press(&mut app, KeyCode::Char(key));
        assert_eq!(app.message, Some((BUSY.into(), true)), "{key}");
        assert!(
            app.generating.is_none()
                && app.alias_prompt.is_none()
                && app.confirm.is_none()
                && app.new_password.is_none()
                && app.file_picker.is_none()
                && app.save_as.is_none()
                && app.chain_menu.is_none()
                && app.secret_choice.is_none(),
            "{key}"
        );
    }
    press(&mut app, KeyCode::Delete);
    assert!(app.confirm.is_none());
    // Quitting asks first, since the key pair would be lost.
    press(&mut app, KeyCode::Char('q'));
    assert!(matches!(app.confirm, Some(Confirm::Quit)));
    press(&mut app, KeyCode::Char('n'));
    assert!(!app.modified);

    // Success adds the entry on the UI thread, without saving it.
    release.send(Ok(generated_key_pair())).unwrap();
    assert!(app.finish_generation());
    assert_eq!(
        app.message,
        Some(("Generated RSA 4096 key pair 'slow'.".into(), false))
    );
    assert!(app.generation.is_none() && app.modified);
    assert_eq!(selected_alias(&app), "slow");
    assert_eq!(fs::read(&path).unwrap(), stored);
    assert!(!screen(&mut app, 120, 30).contains("Read-only"));
    press(&mut app, KeyCode::Char('w'));
    assert!(!app.modified, "{:?}", app.message);
    assert_eq!(aliases(&path), ["root-cert", "server-key", "slow"]);

    // A failure adds nothing and restores editing.
    let release = slow_generation(&mut app, "failed");
    release.send(Err("no luck".into())).unwrap();
    assert!(app.finish_generation());
    assert_eq!(app.message, Some(("no luck".into(), true)));
    assert!(!app.modified && app.entries.len() == 3);
    press(&mut app, KeyCode::Char('r'));
    assert!(app.alias_prompt.is_some());
    press(&mut app, KeyCode::Esc);

    // A thread that ends without a result is reported.
    let release = slow_generation(&mut app, "lost");
    drop(release);
    assert!(app.finish_generation());
    assert!(red_text(&mut app).contains("could not be generated"));

    // Opening another keystore drops a late result.
    let release = slow_generation(&mut app, "late");
    app.open_file(path.clone());
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    assert!(app.document.is_some() && app.generation.is_none());
    let _ = release.send(Ok(generated_key_pair()));
    assert!(!app.poll_generation());
}
