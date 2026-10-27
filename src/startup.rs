use std::{
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
};

use ratatui::crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal,
};

use crate::{App, Loaded, Password, load};

pub(crate) const USAGE: &str = "Usage: keystore-tui [path]";

pub(crate) fn help() -> String {
    format!(
        "keystore-tui {}\n\
         Inspect JKS, JCEKS, and PKCS12 keystores, certificate files, and certificate requests.\n\
         \n\
         {USAGE}\n\
         \n\
         Options:\n  \
         -h, --help     Print this help and exit\n  \
         -V, --version  Print the version and exit",
        env!("CARGO_PKG_VERSION")
    )
}

#[derive(Debug, PartialEq)]
pub(crate) enum Command {
    Open(Option<PathBuf>),
    Help,
    Version,
}

pub(crate) fn argument(mut args: impl Iterator<Item = OsString>) -> Result<Command, ()> {
    let first = args.next();
    if args.next().is_some() {
        return Err(());
    }
    Ok(match first {
        Some(flag) if flag == "-h" || flag == "--help" => Command::Help,
        Some(flag) if flag == "-V" || flag == "--version" => Command::Version,
        path => Command::Open(path.map(PathBuf::from)),
    })
}

pub(crate) fn prepare(
    path: Option<PathBuf>,
    prompt: impl FnOnce() -> io::Result<Password>,
) -> Result<App, String> {
    let mut app = App::default();
    let Some(path) = path else {
        return Ok(app);
    };
    if !path.is_file() {
        app.startup_warning = Some(format!(
            "Cannot open {}: path is not a readable regular file",
            path.display()
        ));
        return Ok(app);
    }
    let store = match load(&path) {
        Ok(Loaded::Store(store)) => store,
        Ok(Loaded::Certificates(file)) => {
            app.show_entries(path, file.entries);
            app.warning = file.skipped.then_some(crate::SKIPPED_WARNING);
            app.show_selected_details();
            return Ok(app);
        }
        Err(error) => {
            app.startup_warning = Some(error);
            return Ok(app);
        }
    };
    let result = match store.verify("") {
        Ok(verified) => {
            app.show_verified(path, verified);
            return Ok(app);
        }
        Err(failure) if failure.1.is_some() => Err(failure),
        Err(failure) => {
            let mut password = prompt().map_err(|error| error.to_string())?;
            let result = failure.0.verify(&password.0);
            password.clear();
            result
        }
    };
    match result {
        Ok(verified) => app.show_verified(path, verified),
        Err(failure) => match failure.1 {
            Some(message) => app.startup_warning = Some(message.into()),
            None => return Err("Incorrect password or keystore integrity check failed.".into()),
        },
    }
    Ok(app)
}

struct RawMode;
impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

pub(crate) fn password() -> io::Result<Password> {
    terminal::enable_raw_mode()?;
    let guard = RawMode;
    let result = (|| {
        eprint!("Keystore password: ");
        io::stderr().flush()?;
        let mut password = Password::default();
        loop {
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Enter => return Ok(password),
                KeyCode::Esc => return Err(io::Error::other("Password input cancelled")),
                KeyCode::Char('c' | 'd') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Err(io::Error::other("Password input cancelled"));
                }
                KeyCode::Backspace => password.pop(),
                KeyCode::Char(ch) if crate::is_text_input(key.modifiers) => password.push(ch),
                _ => {}
            }
        }
    })();
    drop(guard);
    eprintln!();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments() {
        assert_eq!(argument([].into_iter()), Ok(Command::Open(None)));
        assert_eq!(
            argument([OsString::from("a b.jks")].into_iter()),
            Ok(Command::Open(Some("a b.jks".into())))
        );
        assert!(argument(["a".into(), "b".into()].into_iter()).is_err());
        for (flag, command) in [
            ("-h", Command::Help),
            ("--help", Command::Help),
            ("-V", Command::Version),
            ("--version", Command::Version),
        ] {
            assert_eq!(argument([OsString::from(flag)].into_iter()), Ok(command));
            assert!(argument([flag.into(), "a.jks".into()].into_iter()).is_err());
        }
        assert_eq!(
            argument([OsString::from("./--help")].into_iter()),
            Ok(Command::Open(Some("./--help".into())))
        );
        assert!(help().starts_with(&format!("keystore-tui {}\n", env!("CARGO_PKG_VERSION"))));
        assert!(help().contains(USAGE));
    }

    #[test]
    fn certificates_open_directly_in_details() {
        use crate::test_support::{TestDirectory, fixture_certificate_der};
        use crown::asn1::pem;

        let directory = TestDirectory::new();
        let der = fixture_certificate_der();
        let certificate = pem::encode("CERTIFICATE", der);
        for (name, data, count, skipped) in [
            (
                "certificate with spaces.pem",
                certificate.as_bytes(),
                1,
                false,
            ),
            ("certificate.der", der, 1, false),
            (
                "bundle.pem",
                [
                    certificate.as_str(),
                    certificate.as_str(),
                    &pem::encode("PRIVATE KEY", b"synthetic, not a key"),
                ]
                .concat()
                .as_bytes(),
                2,
                true,
            ),
            (
                "request.csr",
                crate::test_support::KEYTOOL_REQUEST,
                1,
                false,
            ),
            (
                "request.der",
                crate::test_support::OPENSSL_REQUEST_DER,
                1,
                false,
            ),
        ] {
            let path = directory.path().join(name);
            std::fs::write(&path, data).unwrap();
            let mut app = prepare(Some(path.clone()), || panic!("unexpected prompt")).unwrap();
            assert_eq!(app.keystore_path, Some(path));
            assert!(app.startup_warning.is_none());
            assert_eq!(app.entries.len(), count);
            assert_eq!(app.warning.is_some(), skipped);
            assert!(app.entry_details.is_some());
            assert!(!app.handle_key(ratatui::crossterm::event::KeyEvent::new(
                KeyCode::Esc,
                KeyModifiers::NONE,
            )));
            assert!(app.entry_details.is_none());
            assert_eq!(app.visible.len(), count);
        }
    }

    #[test]
    fn startup_outcomes() {
        assert!(
            prepare(None, || panic!("unexpected prompt"))
                .unwrap()
                .keystore_path
                .is_none()
        );
        for name in ["missing.jks", "README.md", "tests"] {
            let app = prepare(Some(name.into()), || panic!("unexpected prompt")).unwrap();
            assert!(app.startup_warning.is_some());
            assert!(app.keystore_path.is_none());
        }
        let app = prepare(Some("tests/fixtures/empty-password.p12".into()), || {
            panic!("unexpected prompt")
        })
        .unwrap();
        assert!(app.keystore_path.is_some());
        for ext in ["jks", "jceks", "p12"] {
            for (password, success) in [("changeit", true), ("wrong", false)] {
                let result = prepare(
                    Some(format!("tests/fixtures/trusted-cert.{ext}").into()),
                    || {
                        let mut value = Password::default();
                        for ch in password.chars() {
                            value.push(ch);
                        }
                        Ok(value)
                    },
                );
                assert_eq!(result.is_ok(), success);
                if let Ok(app) = result {
                    assert!(app.keystore_path.is_some());
                }
            }
        }
    }
}
