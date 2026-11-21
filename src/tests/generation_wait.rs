use super::*;

/// A key pair generated on a worker thread, which waits until the test
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
fn a_modal_waits_for_the_key_pair_and_ignores_other_keys() {
    let directory = TestDirectory::new();
    let (mut app, path) = editing(&directory);
    let stored = fs::read(&path).unwrap();
    let release = slow_generation(&mut app, "slow");
    assert!(!app.poll_generation());

    // The modal names the task and its keys, in a small terminal too.
    let rendered = screen(&mut app, 120, 30);
    assert!(rendered.contains(" Generate key pair "), "{rendered}");
    assert!(
        rendered.contains("Generating RSA 4096 key pair 'slow'... 0s"),
        "{rendered}"
    );
    assert!(rendered.contains(generate::SHORTCUTS));
    assert!(!rendered.contains("g Generate"));
    assert!(screen(&mut app, 60, 12).contains("Generating RSA 4096"));
    screen(&mut app, 10, 3);

    // Every other key is ignored, including the quit and navigation keys.
    let selected = selected_alias(&app).to_owned();
    for code in [
        KeyCode::Char('q'),
        KeyCode::Char('g'),
        KeyCode::Char('S'),
        KeyCode::Char('e'),
        KeyCode::Char('c'),
        KeyCode::Char('w'),
        KeyCode::Char('o'),
        KeyCode::Char('n'),
        KeyCode::Char('/'),
        KeyCode::Down,
        KeyCode::Enter,
        KeyCode::Delete,
    ] {
        assert!(!press(&mut app, code), "{code:?}");
        assert!(
            app.generation.is_some()
                && app.message.is_none()
                && app.confirm.is_none()
                && app.entry_details.is_none()
                && app.file_picker.is_none()
                && app.generating.is_none()
                && app.sign_menu.is_none()
                && !app.editing_filter,
            "{code:?}"
        );
    }
    assert_eq!(selected_alias(&app), selected);
    // Ctrl+C still quits at once.
    assert!(app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));

    // Completion closes the modal, then adds and selects the entry, unsaved.
    release.send(Ok(generated_key_pair())).unwrap();
    assert!(app.finish_generation());
    assert_eq!(
        app.message,
        Some(("Generated RSA 4096 key pair 'slow'.".into(), false))
    );
    assert!(app.generation.is_none() && app.modified);
    assert_eq!(selected_alias(&app), "slow");
    assert_eq!(fs::read(&path).unwrap(), stored);
    let rendered = screen(&mut app, 120, 30);
    assert!(!rendered.contains("Generating"), "{rendered}");
    assert!(rendered.contains("g Generate"));
    press(&mut app, KeyCode::Char('w'));
    assert!(!app.modified, "{:?}", app.message);
    assert_eq!(aliases(&path), ["root-cert", "server-key", "slow"]);

    // A failure adds nothing.
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
}

#[test]
fn esc_cancels_the_generation_without_adding_an_entry() {
    let directory = TestDirectory::new();
    let (mut app, _) = editing(&directory);
    let release = slow_generation(&mut app, "slow");

    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.generation.is_none());
    assert_eq!(
        app.message,
        Some((
            "Generating RSA 4096 key pair 'slow' was cancelled.".into(),
            false
        ))
    );
    assert!(screen(&mut app, 120, 30).contains("was cancelled."));
    // The late result finds nobody waiting and is never added.
    let _ = release.send(Ok(generated_key_pair()));
    assert!(!app.poll_generation());
    assert!(!app.modified && app.entries.len() == 2);
    // The next key clears the message, and the app is usable again.
    press(&mut app, KeyCode::Char('g'));
    assert!(app.message.is_none() && app.generating.is_some());
    // Nothing is left to cancel.
    app.cancel_generation();
    assert!(app.message.is_none());
}
