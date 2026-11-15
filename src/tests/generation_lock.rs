use super::*;

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
