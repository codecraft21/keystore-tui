use super::*;

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
