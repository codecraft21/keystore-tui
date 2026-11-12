//! Changing the open keystore's entries: the alias prompt, renaming an
//! entry, and importing a trusted certificate or a key pair under an alias.
use std::path::Path;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::{App, certificate_file, key_import::Key, keystore::Content};

/// What the alias being typed is for.
pub enum Action {
    /// Rename the entry at this index of the app's entries.
    Rename(usize),
    /// Add this certificate's DER as a trusted certificate.
    Import(Vec<u8>),
    /// Add this private key with its certificate chain.
    ImportKey(Key, Vec<Vec<u8>>),
}

/// The alias being typed for a renamed or imported entry.
pub struct AliasPrompt {
    pub action: Action,
    pub alias: String,
}

impl App {
    /// Asks for the selected entry's new alias, starting from its current one.
    pub(crate) fn ask_rename(&mut self) {
        if let Some(index) = self.selected_entry()
            && self.editable()
        {
            self.alias_prompt = Some(AliasPrompt {
                action: Action::Rename(index),
                alias: self.entries[index].alias.clone(),
            });
        }
    }

    /// Opens the file browser to choose a certificate or key file to import.
    pub(crate) fn ask_import(&mut self) {
        if self.editable() {
            self.open_picker();
            self.importing = self.file_picker.is_some();
        }
    }

    /// Asks for the alias of the single certificate in the file content
    /// `data`, suggesting the certificate's subject name.
    pub(crate) fn import_certificate(&mut self, path: &Path, data: &[u8]) -> Result<(), String> {
        let certificate = read_certificate(path, data)?;
        let alias = certificate_file::subject_name(&certificate)
            .unwrap_or_default()
            .to_lowercase();
        self.alias_prompt = Some(AliasPrompt {
            action: Action::Import(certificate),
            alias,
        });
        Ok(())
    }

    pub(crate) fn handle_alias(&mut self, key: KeyEvent) {
        let Some(prompt) = &mut self.alias_prompt else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.alias_prompt = None,
            KeyCode::Enter => {
                let prompt = self.alias_prompt.take().unwrap();
                if let Err(error) = self.apply(&prompt) {
                    self.message = Some((error, true));
                    self.alias_prompt = Some(prompt);
                }
            }
            KeyCode::Backspace => {
                prompt.alias.pop();
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                prompt.alias.clear();
            }
            KeyCode::Char(ch) if crate::is_text_input(key.modifiers) => prompt.alias.push(ch),
            _ => {}
        }
    }

    /// Renames or imports under the typed alias, in lower case as Java
    /// looks aliases up.
    fn apply(&mut self, prompt: &AliasPrompt) -> Result<(), String> {
        let alias = prompt.alias.to_lowercase();
        let renamed = match prompt.action {
            Action::Rename(index) => Some(index),
            Action::Import(_) | Action::ImportKey(..) => None,
        };
        if alias.is_empty() {
            return Err("Type an alias, or press Esc to cancel.".into());
        }
        if renamed.is_some_and(|index| self.entries[index].alias == alias) {
            return Ok(());
        }
        // Java finds entries by lower-case alias, so two aliases differing
        // only in case would hide one another.
        if self
            .entries
            .iter()
            .enumerate()
            .any(|(index, entry)| Some(index) != renamed && entry.alias.to_lowercase() == alias)
        {
            return Err(format!("An entry named '{alias}' already exists."));
        }
        let Some(document) = &mut self.document else {
            return Ok(());
        };
        let (result, message) = match &prompt.action {
            Action::Rename(index) => {
                let message = format!(
                    "Renamed entry '{}' to '{alias}'.",
                    self.entries[*index].alias
                );
                (document.rename(&mut self.entries, *index, alias), message)
            }
            Action::Import(certificate) => {
                let message = format!("Imported certificate as '{alias}'.");
                (
                    document.import_certificate(&mut self.entries, alias, certificate),
                    message,
                )
            }
            Action::ImportKey(key, chain) => {
                let message = format!("Imported key pair as '{alias}'.");
                (
                    document.import_key_pair(&mut self.entries, alias, key, chain),
                    message,
                )
            }
        };
        let to = result?;
        self.modified = true;
        self.message = Some((message, false));
        // Select the changed entry when the filter still shows it.
        self.visible = crate::entry_list::visible_entries(&self.entries, &self.filter, self.sort);
        let selected = self
            .visible
            .iter()
            .position(|&index| index == to)
            .or((!self.visible.is_empty()).then_some(0));
        self.entries_state.select(selected);
        Ok(())
    }
}

/// The DER of the single certificate in the content `data` of the file at
/// `path`.
fn read_certificate(path: &Path, data: &[u8]) -> Result<Vec<u8>, String> {
    let file = certificate_file::parse(data)
        .map_err(|error| format!("{} is not a certificate file: {error}", path.display()))?;
    let mut certificates: Vec<_> = file
        .entries
        .into_iter()
        .filter_map(|entry| match entry.content {
            Content::Certificates { certificates, .. } => certificates.into_iter().next(),
            Content::Request(_) => None,
        })
        .collect();
    match certificates.len() {
        1 => Ok(certificates.remove(0)),
        0 => Err(format!("{} holds no certificate.", path.display())),
        count => Err(format!(
            "{} holds {count} certificates; import a file with a single certificate.",
            path.display()
        )),
    }
}
