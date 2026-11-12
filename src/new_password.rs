//! Typing a new keystore password twice, to create a keystore or to change
//! the open keystore's password, and the creation of a new keystore file.
use std::path::{Path, PathBuf};

use ratatui::crossterm::event::{KeyCode, KeyEvent};

use crate::{
    App, Confirm, Password, canonical_path,
    keystore::{self, Kind},
    path_bar, pkcs12, save,
};

/// What the new password is for.
pub enum Purpose {
    /// Create an empty keystore at this path, which does not exist yet.
    Create(PathBuf),
    /// Change the open keystore's password.
    Change,
    /// Type the current password of the private key at this index of the
    /// app's entries, which the keystore's password does not unlock. It is
    /// typed once.
    KeyCurrent(usize),
    /// Change the password of the private key at this index, unlocked with
    /// the password given, or with the keystore's when there is none.
    KeyChange(usize, Option<Password>),
    /// Protect the private key at this index in the new file it is exported
    /// to. An empty password leaves the key unencrypted.
    Export(PathBuf, usize),
}

/// A new password being typed, then typed again to rule out a typing error.
pub struct NewPasswordPrompt {
    pub purpose: Purpose,
    /// The first entry, once confirmed with `Enter`.
    first: Option<Password>,
    pub current: Password,
}

impl NewPasswordPrompt {
    pub(crate) fn new(purpose: Purpose) -> Self {
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

/// Whether `path` names a PKCS12 keystore.
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
        // Without an opened file, a bare name stands for the working directory.
        let current = self
            .keystore_path
            .as_deref()
            .unwrap_or(Path::new("keystore.jks"));
        self.save_as = Some(save::SaveAsPrompt::for_new(path_bar::directory(current)));
    }

    /// Checks the typed name, then asks for the new keystore's password.
    pub(crate) fn password_new_keystore(&mut self, path: PathBuf) {
        if path.exists() {
            self.message = Some((
                format!("'{}' already exists; choose another name.", path.display()),
                true,
            ));
        } else {
            self.save_as = None;
            self.new_password = Some(NewPasswordPrompt::new(Purpose::Create(path)));
        }
    }

    /// Asks for the selected private key's new password, after its current
    /// one unless the keystore's password unlocks it.
    pub(crate) fn ask_key_password(&mut self) {
        if !self.editable() {
            return;
        }
        let (Some(index), Some(document)) = (self.selected_entry(), &self.document) else {
            return;
        };
        let purpose = if !document.has_key_passwords() {
            Err("PKCS12 keys share the keystore's password; press p to change it.".into())
        } else if self.entries[index].kind() != Kind::PrivateKey.label() {
            Err("Only private keys have a password of their own that can be changed.".into())
        } else {
            document.unlocks_key(index, None).map(|unlocked| {
                if unlocked {
                    Purpose::KeyChange(index, None)
                } else {
                    Purpose::KeyCurrent(index)
                }
            })
        };
        match purpose {
            Ok(purpose) => self.new_password = Some(NewPasswordPrompt::new(purpose)),
            Err(error) => self.message = Some((error, true)),
        }
    }

    /// Checks the typed current key password, then asks for the new one.
    fn unlock_key(&mut self, index: usize, typed: Password) {
        // The key's protection was read when the prompt opened, so any
        // failure here is the password.
        let unlocked = self
            .document
            .as_ref()
            .is_some_and(|document| document.unlocks_key(index, Some(&typed.0)) == Ok(true));
        if unlocked {
            self.new_password = Some(NewPasswordPrompt::new(Purpose::KeyChange(
                index,
                Some(typed),
            )));
        } else {
            // The prompt stays open for another attempt.
            self.message = Some(("Incorrect key password.".into(), true));
        }
    }

    fn change_key_password(&mut self, index: usize, current: Option<Password>, new: &str) {
        let Some(document) = &mut self.document else {
            return;
        };
        let current = current.as_ref().map(|password| password.0.as_str());
        self.message = Some(match document.set_key_password(index, current, new) {
            Ok(()) => {
                self.modified = true;
                (
                    format!(
                        "Password of key '{}' changed; it is written when the keystore is saved.",
                        self.entries[index].alias
                    ),
                    false,
                )
            }
            Err(error) => (error, true),
        });
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
                if let Purpose::KeyCurrent(index) = prompt.purpose {
                    return self.unlock_key(index, typed);
                }
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
                            Purpose::KeyChange(index, current) => {
                                self.change_key_password(index, current, &typed.0);
                            }
                            Purpose::Export(path, index) => {
                                self.export_key_with(path, index, &typed.0);
                            }
                            Purpose::KeyCurrent(_) => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Writes an empty keystore to the new file `path` and opens it. A
    /// `.jceks` name creates a JCEKS keystore, a `.p12` or `.pfx` name a
    /// PKCS12 one, and any other name a JKS one.
    fn create_keystore(&mut self, path: PathBuf, password: &str) {
        let jceks = path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("jceks"));
        let (format, document) = if is_pkcs12_name(&path) {
            if password.is_empty() {
                self.message = Some((
                    "A PKCS12 keystore needs a password that is not empty; nothing was created."
                        .into(),
                    true,
                ));
                return;
            }
            let writable = pkcs12::Writable::empty(password);
            ("PKCS12", save::Document::Pkcs12(writable))
        } else {
            let writable = keystore::Writable::empty(jceks);
            let format = if jceks { "JCEKS" } else { "JKS" };
            (format, save::Document::jks(writable, password))
        };
        match document.save_new(&path, &[]) {
            Ok(()) => {
                let path = canonical_path::canonicalize(&path).unwrap_or(path);
                let message = format!("Created the {format} keystore '{}'.", path.display());
                self.show_entries(path, vec![]);
                self.document = Some(document);
                self.message = Some((message, false));
            }
            Err(error) => self.message = Some((error, true)),
        }
    }

    fn change_password(&mut self, password: &str) {
        let Some(document) = &mut self.document else {
            return;
        };
        self.message = Some(match document.set_password(password) {
            Ok(()) => {
                self.modified = true;
                (
                    "Password changed; it is written when the keystore is saved.".into(),
                    false,
                )
            }
            Err(error) => (error, true),
        });
    }
}
