//! Typing a new keystore password twice, to create a keystore or to change
//! the open keystore's password, and the creation of a new keystore file.
use std::path::{Path, PathBuf};

use ratatui::crossterm::event::{KeyCode, KeyEvent};

use crate::{App, Confirm, Password, canonical_path, keystore, path_bar, save};

/// What the new password is for.
pub enum Purpose {
    /// Create an empty keystore at this path, which does not exist yet.
    Create(PathBuf),
    /// Change the open keystore's password.
    Change,
}

/// A new password being typed, then typed again to rule out a typing error.
pub struct NewPasswordPrompt {
    pub purpose: Purpose,
    /// The first entry, once confirmed with `Enter`.
    first: Option<Password>,
    pub current: Password,
}

impl NewPasswordPrompt {
    fn new(purpose: Purpose) -> Self {
        Self {
            purpose,
            first: None,
            current: Password::default(),
        }
    }

    /// Whether the password is being typed for the second time.
    pub fn repeating(&self) -> bool {
        self.first.is_some()
    }
}

/// Whether `path` names a PKCS12 keystore, which cannot be created yet.
fn is_pkcs12_name(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("p12") || ext.eq_ignore_ascii_case("pfx"))
}

impl App {
    /// Asks for the new keystore's file name, after asking about unsaved
    /// changes.
    pub(crate) fn ask_new_keystore(&mut self) {
        if self.modified {
            self.confirm = Some(Confirm::New);
        } else {
            self.name_new_keystore();
        }
    }

    pub(crate) fn name_new_keystore(&mut self) {
        let directory = self
            .keystore_path
            .as_deref()
            .map_or_else(std::env::current_dir, |path| Ok(path_bar::directory(path)));
        match directory {
            Ok(directory) => self.save_as = Some(save::SaveAsPrompt::for_new(directory)),
            Err(error) => {
                self.message = Some((format!("Cannot find the working directory: {error}"), true));
            }
        }
    }

    /// Checks the typed name, then asks for the new keystore's password.
    pub(crate) fn password_new_keystore(&mut self, path: PathBuf) {
        if is_pkcs12_name(&path) {
            self.message = Some((
                "Only JKS and JCEKS keystores can be created for now; use a .jks or .jceks name."
                    .into(),
                true,
            ));
        } else if path.exists() {
            self.message = Some((
                format!("'{}' already exists; choose another name.", path.display()),
                true,
            ));
        } else {
            self.save_as = None;
            self.new_password = Some(NewPasswordPrompt::new(Purpose::Create(path)));
        }
    }

    /// Asks for the open keystore's new password.
    pub(crate) fn ask_password_change(&mut self) {
        if self.editable() {
            self.new_password = Some(NewPasswordPrompt::new(Purpose::Change));
        }
    }

    pub(crate) fn handle_new_password(&mut self, key: KeyEvent) {
        let Some(prompt) = &mut self.new_password else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.new_password = None,
            KeyCode::Char(ch) if crate::is_text_input(key.modifiers) => prompt.current.push(ch),
            KeyCode::Backspace => prompt.current.pop(),
            KeyCode::Enter => {
                let typed = std::mem::take(&mut prompt.current);
                match prompt.first.take() {
                    None => prompt.first = Some(typed),
                    Some(first) if *first.0 != *typed.0 => {
                        self.message = Some((
                            "The passwords do not match; type the new password again.".into(),
                            true,
                        ));
                    }
                    Some(_) => {
                        // Dropping the prompt and `typed` wipes the passwords.
                        let prompt = self.new_password.take().unwrap();
                        match prompt.purpose {
                            Purpose::Create(path) => self.create_keystore(path, &typed.0),
                            Purpose::Change => self.change_password(&typed.0),
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Writes an empty keystore to the new file `path` and opens it. A
    /// `.jceks` name creates a JCEKS keystore, any other name a JKS one.
    fn create_keystore(&mut self, path: PathBuf, password: &str) {
        let jceks = path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("jceks"));
        let document = save::Document::new(keystore::Writable::empty(jceks), password);
        match document.save_new(&path, &[]) {
            Ok(()) => {
                let path = canonical_path::canonicalize(&path).unwrap_or(path);
                let format = if jceks { "JCEKS" } else { "JKS" };
                let message = format!("Created the {format} keystore '{}'.", path.display());
                self.show_entries(path, vec![]);
                self.document = Some(document);
                self.message = Some((message, false));
            }
            Err(error) => self.message = Some((error, true)),
        }
    }

    fn change_password(&mut self, password: &str) {
        if let Some(document) = &mut self.document {
            document.set_password(password);
            self.modified = true;
            self.message = Some((
                "Password changed; it is written when the keystore is saved.".into(),
                false,
            ));
        }
    }
}
