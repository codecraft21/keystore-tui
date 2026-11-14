//! Secret-key entries in the open keystore: choosing the algorithm of a new
//! key, reading a key from a file, and exporting a key to a new file.
use std::path::Path;

use ratatui::crossterm::event::{KeyCode, KeyEvent};
use zeroize::Zeroizing;

use crate::{
    App, Confirm, MAX_KEYSTORE_SIZE,
    editing::{Action, AliasPrompt},
    export::{ExportPrompt, Outcome, Scope},
    key_import,
    keystore::Kind,
    path_bar, read_limited, save,
    secret_key::{self, Choice, SecretKey},
};

/// The algorithm being chosen for a secret key: a new one, or the one read
/// from a file.
pub struct Chooser {
    /// The file's name and the key it holds, for an imported key.
    imported: Option<(String, Zeroizing<Vec<u8>>)>,
    choices: Vec<Choice>,
    selected: usize,
}

impl Chooser {
    /// What the choice is about, and the chosen algorithm.
    pub fn labels(&self) -> (String, String) {
        let subject = match &self.imported {
            Some((file, _)) => format!("Secret key from '{file}': "),
            None => "New secret key: ".into(),
        };
        (
            subject,
            format!("< {} >", self.choices[self.selected].label()),
        )
    }

    /// Whether a key can still be read from a file instead.
    pub fn generating(&self) -> bool {
        self.imported.is_none()
    }
}

/// The file name being typed for the export of the secret key at `index` of
/// the app's entries.
pub struct SecretExport {
    index: usize,
    pub prompt: ExportPrompt,
}

/// Whether the file `path` holds a key as hex digits, by its name.
fn is_hex_name(path: &Path) -> bool {
    path.extension().is_some_and(|extension| {
        extension.eq_ignore_ascii_case("hex") || extension.eq_ignore_ascii_case("txt")
    })
}

impl App {
    /// Asks for the algorithm of a new secret key.
    pub(crate) fn ask_secret_key(&mut self) {
        if !self.editable() {
            return;
        }
        let jks = |document: &save::Document| document.format() == save::Format::Jks;
        if self.document.as_ref().is_some_and(jks) {
            self.message = Some((
                "A JKS keystore cannot hold secret keys; save it as JCEKS or PKCS12 first (W)."
                    .into(),
                true,
            ));
            return;
        }
        self.secret_choice = Some(Chooser {
            imported: None,
            choices: secret_key::generated(),
            // AES with 256 bits.
            selected: 2,
        });
    }

    /// `Left` and `Right` change the algorithm, `Enter` asks for the alias,
    /// `i` reads a key from a file instead, and `Esc` adds nothing.
    pub(crate) fn handle_secret_choice(&mut self, key: KeyEvent) {
        let Some(chooser) = &mut self.secret_choice else {
            return;
        };
        let count = chooser.choices.len();
        match key.code {
            KeyCode::Esc => self.secret_choice = None,
            KeyCode::Left => chooser.selected = (chooser.selected + count - 1) % count,
            KeyCode::Right => chooser.selected = (chooser.selected + 1) % count,
            KeyCode::Char('i') if chooser.generating() && crate::is_text_input(key.modifiers) => {
                self.secret_choice = None;
                self.open_picker();
                // A key file can have any name.
                self.file_picker = self
                    .file_picker
                    .take()
                    .and_then(|picker| picker.with_all_files().ok());
                self.importing_secret = self.file_picker.is_some();
            }
            KeyCode::Enter => {
                let choice = chooser.choices[chooser.selected];
                let imported = self
                    .secret_choice
                    .take()
                    .and_then(|chooser| chooser.imported);
                self.alias_prompt = Some(match imported {
                    Some((file, key)) => AliasPrompt {
                        // Named after the file, without its extension.
                        alias: Path::new(&file)
                            .file_stem()
                            .map(|stem| stem.to_string_lossy().to_lowercase())
                            .unwrap_or_default(),
                        action: Action::ImportSecret(SecretKey {
                            algorithm: choice.algorithm.into(),
                            key,
                        }),
                    },
                    None => AliasPrompt {
                        alias: choice.algorithm.to_lowercase(),
                        action: Action::GenerateSecret(choice),
                    },
                });
            }
            _ => {}
        }
    }

    /// Reads the secret key in the file at `path` and asks for its
    /// algorithm.
    pub(crate) fn import_secret_file(&mut self, path: &Path) {
        let file = key_import::name(path);
        let key = read_limited(path, MAX_KEYSTORE_SIZE)
            .map(Zeroizing::new)
            .map_err(|error| format!("Cannot read {}: {error}", path.display()))
            .and_then(|data| {
                secret_key::from_file(&data).ok_or_else(|| {
                    format!(
                        "'{file}' holds no secret key: a key is 1 to {} bytes, as they are or in hex digits.",
                        secret_key::MAX_KEY_SIZE
                    )
                })
            });
        match key {
            Ok(key) => {
                self.secret_choice = Some(Chooser {
                    choices: secret_key::fitting(key.len()),
                    imported: Some((file, key)),
                    selected: 0,
                });
            }
            Err(error) => self.message = Some((error, true)),
        }
    }

    /// A new key of the chosen algorithm, from the system's random numbers.
    pub(crate) fn generate_secret(choice: Choice) -> Result<SecretKey, String> {
        save::OsRng::default().check()?;
        let mut rng = save::OsRng::default();
        let key = choice.generate(&mut rng);
        rng.check()?;
        Ok(key)
    }

    /// Asks for the file to export the secret key at `index` to.
    pub(crate) fn ask_secret_export(&mut self, index: usize) {
        let (Some(document), Some(path)) = (&self.document, &self.keystore_path) else {
            return;
        };
        let entry = &self.entries[index];
        match document.secret_key(index) {
            Ok(_) => {
                let directory = path_bar::directory(path);
                self.secret_export = Some(SecretExport {
                    index,
                    prompt: ExportPrompt::new(Scope::SecretKey, &directory, &entry.alias),
                });
            }
            Err(error) => {
                let message = format!("Not exported: the secret key '{}' {error}.", entry.alias);
                self.message = Some((message, true));
            }
        }
    }

    /// Types the export's file name, then asks before the key is written
    /// unencrypted.
    pub(crate) fn handle_secret_export(&mut self, key: KeyEvent) {
        let Some(export) = &mut self.secret_export else {
            return;
        };
        match export.prompt.handle_key(key) {
            Outcome::Editing => {}
            Outcome::Cancelled => self.secret_export = None,
            Outcome::Save(path) if path.exists() => {
                self.message = Some((
                    format!("'{}' already exists; choose another name.", path.display()),
                    true,
                ));
            }
            Outcome::Save(path) => {
                let index = export.index;
                self.secret_export = None;
                self.confirm = Some(Confirm::ExportSecret(path, index));
            }
        }
    }

    /// Writes the secret key at `index` to the new file `path`: hex digits
    /// for a `.hex` or `.txt` name, and the key's bytes otherwise.
    pub(crate) fn export_secret(&mut self, path: &Path, index: usize) {
        let Some(document) = &self.document else {
            return;
        };
        let alias = &self.entries[index].alias;
        let result = document
            .secret_key(index)
            .map_err(|error| format!("Not exported: the secret key '{alias}' {error}."))
            .and_then(|secret| {
                if is_hex_name(path) {
                    save::create_private(path, secret_key::hex(&secret.key).as_bytes())
                } else {
                    save::create_private(path, &secret.key)
                }
                .map(|()| {
                    format!(
                        "Exported the {} secret key '{alias}' ({} bits) to '{}'.",
                        secret.algorithm,
                        secret.key.len() * 8,
                        path.display()
                    )
                })
            });
        self.message = Some(match result {
            Ok(message) => (message, false),
            Err(error) => (error, true),
        });
    }

    /// Whether the entry at `index` is a secret key.
    pub(crate) fn is_secret_key(&self, index: usize) -> bool {
        self.entries[index].kind() == Kind::SecretKey.label()
    }
}
