use super::*;

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
fn read_bounded_with_exact_size_hint_does_not_reallocate_on_eof() {
    let payload: Vec<u8> = (0..128).collect();
    let data = read_bounded(&payload[..], payload.len() as u64, 1000).unwrap();
    assert_eq!(data, payload);
    assert_eq!(data.capacity(), payload.len() + 1);

    let directory = TestDirectory::new();
    let path = directory.path().join("key.bin");
    fs::write(&path, &payload).unwrap();
    let file_data = read_limited(&path, 1000).unwrap();
    assert_eq!(file_data, payload);
    assert_eq!(file_data.capacity(), payload.len() + 1);
    let exact_limit = read_limited(&path, payload.len() as u64).unwrap();
    assert_eq!(exact_limit, payload);
    assert_eq!(exact_limit.capacity(), payload.len() + 1);
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
