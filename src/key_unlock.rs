//! Prompting for separate key passwords when copying entries from another
//! keystore or converting a keystore to another format.
use std::{collections::VecDeque, path::PathBuf};

use ratatui::crossterm::event::{KeyCode, KeyEvent};
use zeroize::Zeroizing;

use crate::{
    App, Password, copy_entries, is_text_input,
    keystore::{KeystoreEntry, Kind},
    save::{self, Document, KeyAccessError},
    secret_key,
};

/// Which operation is waiting for separate key passwords.
enum UnlockPurpose {
    /// Converting the open keystore into a new file of `target` format.
    Convert { path: PathBuf, target: save::Format },
    /// Copying `picked` entries from another keystore (`selection`).
    Copy {
        selection: Box<copy_entries::Selection>,
        picked: Vec<usize>,
    },
}

/// Prompts for one or more keys whose own password differs from the source
/// keystore's password. Passwords typed in this operation are tried
/// automatically on remaining locked keys, and all buffers are wiped on drop.
pub(crate) struct KeyUnlock {
    purpose: UnlockPurpose,
    /// Entry indices still waiting to be unlocked; the front is prompted next.
    pending: VecDeque<usize>,
    /// Passwords entered so far in this operation, tried on later keys.
    tried: Vec<Password>,
    /// Unlocked entry indices paired with the password that opened each one.
    unlocked: Vec<(usize, Password)>,
    /// The password currently being typed.
    pub(crate) current: Password,
}

impl KeyUnlock {
    pub(crate) fn for_convert(path: PathBuf, target: save::Format, pending: Vec<usize>) -> Self {
        Self {
            purpose: UnlockPurpose::Convert { path, target },
            pending: pending.into(),
            tried: Vec::new(),
            unlocked: Vec::new(),
            current: Password::default(),
        }
    }

    pub(crate) fn for_copy(
        selection: copy_entries::Selection,
        picked: Vec<usize>,
        pending: Vec<usize>,
    ) -> Self {
        Self {
            purpose: UnlockPurpose::Copy {
                selection: Box::new(selection),
                picked,
            },
            pending: pending.into(),
            tried: Vec::new(),
            unlocked: Vec::new(),
            current: Password::default(),
        }
    }

    /// The alias of the key whose password is being asked for.
    pub(crate) fn current_alias<'a>(&'a self, entries: &'a [KeystoreEntry]) -> &'a str {
        let index = *self.pending.front().expect("pending keys are non-empty");
        match &self.purpose {
            UnlockPurpose::Convert { .. } => &entries[index].alias,
            UnlockPurpose::Copy { selection, .. } => &selection.entries()[index].alias,
        }
    }
}

enum VerifyError {
    Password,
    Failed(String),
}

/// Checks whether `password` unlocks the private or secret key at `index`,
/// and that the unlocked key is usable for the operation. The decrypted key
/// is wiped as soon as it is checked.
fn verify_key(
    document: &Document,
    entry: &KeystoreEntry,
    index: usize,
    password: &str,
    convert_target: Option<save::Format>,
) -> Result<(), VerifyError> {
    if entry.kind() == Kind::SecretKey.label() {
        match document.secret_key_with(index, Some(password)) {
            Ok(secret) => {
                if convert_target == Some(save::Format::Pkcs12)
                    && secret_key::to_pkcs8(&secret).is_none()
                {
                    return Err(VerifyError::Failed(format!(
                        "Not converted: PKCS12 has no name for the algorithm '{}' of the secret key '{}'.",
                        secret.algorithm, entry.alias
                    )));
                }
                Ok(())
            }
            Err(KeyAccessError::Password) => Err(VerifyError::Password),
            Err(KeyAccessError::Other(error)) => {
                Err(VerifyError::Failed(if convert_target.is_some() {
                    format!("Not converted: the secret key '{}' {error}.", entry.alias)
                } else {
                    format!("'{}' is not copied: {error}.", entry.alias)
                }))
            }
        }
    } else {
        match document.private_key_with(index, Some(password)) {
            Ok(_) => Ok(()),
            Err(KeyAccessError::Password) => Err(VerifyError::Password),
            Err(KeyAccessError::Other(error)) => {
                Err(VerifyError::Failed(if convert_target.is_some() {
                    format!("Not converted: the key '{}' {error}.", entry.alias)
                } else {
                    format!("'{}' is not copied: {error}.", entry.alias)
                }))
            }
        }
    }
}

fn clone_password(password: &Password) -> Password {
    Password(Zeroizing::new(password.0.as_str().to_owned()))
}

impl App {
    pub(crate) fn handle_key_unlock(&mut self, key: KeyEvent) {
        let Some(mut unlock) = self.key_unlock.take() else {
            return;
        };
        match key.code {
            KeyCode::Esc => {
                // Cancel atomically: drop all collected passwords and return
                // to the previous prompt (Selection list or Save As).
                if let UnlockPurpose::Copy { selection, .. } = unlock.purpose
                    && selection.entries().len() > 1
                {
                    self.copying = Some(*selection);
                }
            }
            KeyCode::Backspace => {
                unlock.current.pop();
                self.key_unlock = Some(unlock);
            }
            KeyCode::Char(character) if is_text_input(key.modifiers) => {
                unlock.current.push(character);
                self.key_unlock = Some(unlock);
            }
            KeyCode::Enter => self.submit_key_unlock(unlock),
            _ => {
                self.key_unlock = Some(unlock);
            }
        }
    }

    fn submit_key_unlock(&mut self, mut unlock: KeyUnlock) {
        let candidate = std::mem::take(&mut unlock.current);
        let Some(&index) = unlock.pending.front() else {
            return;
        };
        let verified = self.check_unlock(&unlock, index, &candidate.0);
        match verified {
            Err(VerifyError::Password) => {
                self.message = Some(("Incorrect password.".into(), true));
                self.key_unlock = Some(unlock);
                return;
            }
            Err(VerifyError::Failed(message)) => {
                self.message = Some((message, true));
                if let UnlockPurpose::Copy { selection, .. } = unlock.purpose
                    && selection.entries().len() > 1
                {
                    self.copying = Some(*selection);
                }
                return;
            }
            Ok(()) => {
                unlock.pending.pop_front();
                unlock.unlocked.push((index, clone_password(&candidate)));
                if !unlock
                    .tried
                    .iter()
                    .any(|existing| existing.0.as_str() == candidate.0.as_str())
                {
                    unlock.tried.push(candidate);
                }
            }
        }

        // Try already-entered passwords on any remaining locked keys before
        // prompting again.
        while let Some(&next_index) = unlock.pending.front() {
            let mut matched = None;
            for password in &unlock.tried {
                match self.check_unlock(&unlock, next_index, &password.0) {
                    Ok(()) => {
                        matched = Some(clone_password(password));
                        break;
                    }
                    Err(VerifyError::Password) => {}
                    Err(VerifyError::Failed(message)) => {
                        self.message = Some((message, true));
                        if let UnlockPurpose::Copy { selection, .. } = unlock.purpose
                            && selection.entries().len() > 1
                        {
                            self.copying = Some(*selection);
                        }
                        return;
                    }
                }
            }
            if let Some(password) = matched {
                unlock.pending.pop_front();
                unlock.unlocked.push((next_index, password));
            } else {
                self.key_unlock = Some(unlock);
                return;
            }
        }

        let KeyUnlock {
            purpose, unlocked, ..
        } = unlock;
        let passwords: Vec<(usize, &str)> = unlocked
            .iter()
            .map(|(index, password)| (*index, password.0.as_str()))
            .collect();
        match purpose {
            UnlockPurpose::Convert { path, target } => {
                self.finish_converted(path, target, &passwords);
            }
            UnlockPurpose::Copy { selection, picked } => {
                self.finish_copy(*selection, picked, &passwords);
            }
        }
    }

    fn check_unlock(
        &self,
        unlock: &KeyUnlock,
        index: usize,
        password: &str,
    ) -> Result<(), VerifyError> {
        match &unlock.purpose {
            UnlockPurpose::Convert { target, .. } => {
                let Some(document) = &self.document else {
                    return Err(VerifyError::Failed("No keystore is open.".into()));
                };
                verify_key(
                    document,
                    &self.entries[index],
                    index,
                    password,
                    Some(*target),
                )
            }
            UnlockPurpose::Copy { selection, .. } => verify_key(
                selection.source(),
                &selection.entries()[index],
                index,
                password,
                None,
            ),
        }
    }
}
