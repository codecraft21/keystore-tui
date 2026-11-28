//! Copying entries from another keystore: the list in which they are chosen,
//! and adding the chosen ones to the open keystore.
use ratatui::{
    Frame,
    crossterm::event::{KeyCode, KeyEvent},
    layout::{Constraint, Layout, Margin},
    style::{Color, Modifier, Style},
    widgets::{Block, Clear, List, ListItem, ListState, Paragraph, Wrap},
};

use crate::{
    App,
    editing::{Action, AliasPrompt},
    key_import::Key,
    key_unlock,
    keystore::{Content, KeystoreEntry, Kind},
    save::{Document, Format, KeyAccessError},
    secret_key::SecretKey,
};

/// What is copied for an entry.
enum Item {
    Certificate(Vec<u8>),
    Key(Key, Vec<Vec<u8>>),
    Secret(SecretKey),
}

/// Whether an entry in the source keystore can be copied directly, needs a
/// separate key password first, or cannot be copied at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Availability {
    Ready,
    NeedsPassword,
    Blocked(&'static str),
}

impl Availability {
    fn is_blocked(self) -> bool {
        matches!(self, Self::Blocked(_))
    }
}

/// Classifies a private or secret key after attempting recovery with the
/// source keystore's password.
fn key_availability<T>(recovered: Result<T, KeyAccessError>) -> Availability {
    match recovered {
        Ok(_) => Availability::Ready,
        Err(KeyAccessError::Password) => Availability::NeedsPassword,
        Err(KeyAccessError::Other(_)) => Availability::Blocked("its key cannot be read"),
    }
}

/// The entries of another keystore, some of them chosen to be copied.
pub struct Selection {
    /// The keystore's file name, as shown in messages.
    file: String,
    /// The opened keystore, which unlocks its private keys.
    source: Document,
    entries: Vec<KeystoreEntry>,
    /// Whether each entry can be copied, needs a key password, or is blocked.
    availability: Vec<Availability>,
    chosen: Vec<bool>,
    cursor: ListState,
}

impl Selection {
    pub fn new(
        file: String,
        source: Document,
        entries: Vec<KeystoreEntry>,
        allows_secret_keys: bool,
    ) -> Self {
        let availability = entries
            .iter()
            .enumerate()
            .map(|(index, entry)| match &entry.content {
                Content::Certificates {
                    kind: Kind::PrivateKey,
                    ..
                } => key_availability(source.private_key_with(index, None)),
                Content::Certificates {
                    kind: Kind::SecretKey,
                    ..
                } if !allows_secret_keys => {
                    Availability::Blocked("a JKS keystore cannot hold secret keys")
                }
                Content::Certificates {
                    kind: Kind::SecretKey,
                    ..
                } => key_availability(source.secret_key_with(index, None)),
                Content::Certificates {
                    kind: Kind::TrustedCertificate | Kind::Certificate,
                    certificates,
                } if !certificates.is_empty() => Availability::Ready,
                _ => Availability::Blocked("it holds no certificate"),
            })
            .collect();
        Self {
            file,
            source,
            chosen: vec![false; entries.len()],
            cursor: ListState::default().with_selected((!entries.is_empty()).then_some(0)),
            entries,
            availability,
        }
    }

    pub(crate) fn source(&self) -> &Document {
        &self.source
    }

    pub(crate) fn entries(&self) -> &[KeystoreEntry] {
        &self.entries
    }

    /// What copying the entry at `index` adds, using `password` when given
    /// and the source keystore's password otherwise.
    fn item(&self, index: usize, password: Option<&str>) -> Result<Item, String> {
        let entry = &self.entries[index];
        if let Availability::Blocked(reason) = self.availability[index] {
            return Err(reason.into());
        }
        let map_key_error = |error: KeyAccessError| match error {
            KeyAccessError::Password => "its key has a password of its own".into(),
            KeyAccessError::Other(reason) => reason,
        };
        if entry.kind() == Kind::PrivateKey.label() {
            let key = self
                .source
                .private_key_with(index, password)
                .map_err(map_key_error)?;
            Ok(Item::Key(key, entry.certificates().to_vec()))
        } else if entry.kind() == Kind::SecretKey.label() {
            Ok(Item::Secret(
                self.source
                    .secret_key_with(index, password)
                    .map_err(map_key_error)?,
            ))
        } else {
            Ok(Item::Certificate(entry.certificates()[0].clone()))
        }
    }

    /// The chosen entries, or the highlighted one when none is chosen.
    fn picked(&self) -> Vec<usize> {
        let chosen: Vec<usize> = (0..self.entries.len())
            .filter(|&index| self.chosen[index])
            .collect();
        if chosen.is_empty() {
            self.cursor.selected().into_iter().collect()
        } else {
            chosen
        }
    }

    fn step(&mut self, forward: bool) {
        let count = self.entries.len();
        if let Some(at) = self.cursor.selected() {
            let next = if forward { at + 1 } else { at + count - 1 } % count;
            self.cursor.select(Some(next));
        }
    }

    /// Chooses every entry that can be copied, or none if they all are.
    fn toggle_all(&mut self) {
        let all = (0..self.entries.len())
            .all(|index| self.chosen[index] || self.availability[index].is_blocked());
        for index in 0..self.entries.len() {
            self.chosen[index] = !all && !self.availability[index].is_blocked();
        }
    }

    /// Draws the list over the main view. `existing` are the open
    /// keystore's entries, whose aliases cannot be used again, and `error`
    /// is shown in red below the list.
    pub fn draw(&mut self, frame: &mut Frame, existing: &[KeystoreEntry], error: Option<&str>) {
        let area = frame.area().inner(Margin {
            horizontal: 2,
            vertical: 1,
        });
        let block = Block::bordered().title(format!(" Import entries from '{}' ", self.file));
        let inner = block.inner(area);
        frame.render_widget(Clear, area);
        frame.render_widget(block, area);
        let [list, status, help] = Layout::vertical([
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(2),
        ])
        .areas(inner);
        frame.render_widget(
            Paragraph::new(error.unwrap_or_default()).style(Style::default().fg(Color::Red)),
            status,
        );
        let items = self.entries.iter().enumerate().map(|(index, entry)| {
            let taken = existing
                .iter()
                .any(|other| other.alias.to_lowercase() == entry.alias.to_lowercase());
            let (mark, note) = match self.availability[index] {
                Availability::Blocked(reason) => ("[-]", format!(" ({reason})")),
                Availability::Ready if taken => (self.mark(index), " (alias exists)".into()),
                Availability::Ready => (self.mark(index), String::new()),
                Availability::NeedsPassword if taken => (
                    self.mark(index),
                    " (alias exists, key password needed)".into(),
                ),
                Availability::NeedsPassword => (self.mark(index), " (key password needed)".into()),
            };
            let item = ListItem::new(format!("{mark} {} | {}{note}", entry.alias, entry.kind()));
            if self.availability[index].is_blocked() {
                item.style(Style::default().fg(Color::DarkGray))
            } else {
                item
            }
        });
        frame.render_stateful_widget(
            List::new(items).highlight_symbol("> ").highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            list,
            &mut self.cursor,
        );
        frame.render_widget(
            Paragraph::new(
                "Space Choose | a All | Up/Down j/k Move | Enter Import\nEsc Cancel | Ctrl+C Quit",
            )
            .wrap(Wrap { trim: false }),
            help,
        );
    }

    fn mark(&self, index: usize) -> &'static str {
        if self.chosen[index] { "[x]" } else { "[ ]" }
    }
}

impl App {
    /// Lists the entries of the opened keystore file `file` to choose from.
    /// A keystore with a single entry skips the list.
    pub(crate) fn choose_entries(
        &mut self,
        file: String,
        source: Document,
        entries: Vec<KeystoreEntry>,
    ) -> Result<(), String> {
        if entries.is_empty() {
            return Err(format!("'{file}' holds no entries."));
        }
        let single = entries.len() == 1;
        let allows_secret_keys = self
            .document
            .as_ref()
            .is_none_or(|document| document.format() != Format::Jks);
        self.copying = Some(Selection::new(file, source, entries, allows_secret_keys));
        if single {
            self.copy_chosen();
        }
        Ok(())
    }

    pub(crate) fn handle_selection(&mut self, key: KeyEvent) {
        let Some(selection) = &mut self.copying else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.copying = None,
            KeyCode::Down | KeyCode::Char('j') => selection.step(true),
            KeyCode::Up | KeyCode::Char('k') => selection.step(false),
            KeyCode::Char('a') => selection.toggle_all(),
            KeyCode::Char(' ') => {
                if let Some(at) = selection.cursor.selected()
                    && !selection.availability[at].is_blocked()
                {
                    selection.chosen[at] = !selection.chosen[at];
                }
            }
            KeyCode::Enter => self.copy_chosen(),
            _ => {}
        }
    }

    /// Copies the chosen entries. If any chosen entry that will be imported
    /// has a password of its own, prompts for it first.
    fn copy_chosen(&mut self) {
        let Some(selection) = self.copying.take() else {
            return;
        };
        let picked = selection.picked();
        if let [index] = picked[..] {
            if selection.availability[index] == Availability::NeedsPassword {
                self.key_unlock = Some(key_unlock::KeyUnlock::for_copy(
                    selection,
                    vec![index],
                    vec![index],
                ));
                return;
            }
            self.finish_copy(selection, vec![index], &[]);
            return;
        }
        // Entries skipped because their alias exists, in the open keystore or
        // earlier in this copy, are not asked for.
        let mut aliases: Vec<String> = self
            .entries
            .iter()
            .map(|entry| entry.alias.to_lowercase())
            .collect();
        let pending: Vec<usize> = picked
            .iter()
            .copied()
            .filter(|&index| {
                let alias = selection.entries[index].alias.to_lowercase();
                if aliases.contains(&alias) {
                    return false;
                }
                aliases.push(alias);
                selection.availability[index] == Availability::NeedsPassword
            })
            .collect();
        if !pending.is_empty() {
            self.key_unlock = Some(key_unlock::KeyUnlock::for_copy(selection, picked, pending));
            return;
        }
        self.finish_copy(selection, picked, &[]);
    }

    /// Completes copying `picked` entries using any unlocked `key_passwords`.
    /// A single entry goes through the alias prompt; several keep their aliases.
    pub(crate) fn finish_copy(
        &mut self,
        selection: Selection,
        picked: Vec<usize>,
        key_passwords: &[(usize, &str)],
    ) {
        let password_for = |index: usize| {
            key_passwords
                .iter()
                .find_map(|&(at, password)| (at == index).then_some(password))
        };
        if let [index] = picked[..] {
            let entry = &selection.entries[index];
            match selection.item(index, password_for(index)) {
                Ok(item) => {
                    self.alias_prompt = Some(AliasPrompt {
                        action: match item {
                            Item::Certificate(certificate) => Action::Import(certificate),
                            Item::Key(key, chain) => Action::ImportKey(key, chain),
                            Item::Secret(key) => Action::ImportSecret(key),
                        },
                        alias: entry.alias.to_lowercase(),
                    });
                }
                Err(reason) => {
                    let message = format!("'{}' is not copied: {reason}.", entry.alias);
                    self.message = Some((message, true));
                    // The list stays open, unless this was its only entry.
                    if selection.entries.len() > 1 {
                        self.copying = Some(selection);
                    }
                }
            }
            return;
        }
        let Some(document) = &mut self.document else {
            return;
        };
        let (mut copied, mut skipped, mut failed) = (0, Vec::new(), None);
        for index in picked {
            // Aliases are stored in lower case, as Java looks them up.
            let alias = selection.entries[index].alias.to_lowercase();
            if self
                .entries
                .iter()
                .any(|entry| entry.alias.to_lowercase() == alias)
            {
                skipped.push(alias);
                continue;
            }
            let result = selection
                .item(index, password_for(index))
                .and_then(|item| match item {
                    Item::Certificate(certificate) => {
                        document.import_certificate(&mut self.entries, alias.clone(), &certificate)
                    }
                    Item::Key(key, chain) => {
                        document.import_key_pair(&mut self.entries, alias.clone(), &key, &chain)
                    }
                    Item::Secret(key) => {
                        document.import_secret_key(&mut self.entries, alias.clone(), &key)
                    }
                });
            match result {
                Ok(_) => copied += 1,
                Err(error) => {
                    failed = Some(format!(" '{alias}' failed: {error}"));
                    break;
                }
            }
        }
        let entries = if copied == 1 { "entry" } else { "entries" };
        let mut message = format!("Imported {copied} {entries} from '{}'.", selection.file);
        if !skipped.is_empty() {
            message += &format!(" Skipped, alias exists: {}.", skipped.join(", "));
        }
        let is_error = failed.is_some() || copied == 0;
        message += failed.as_deref().unwrap_or_default();
        self.modified |= copied > 0;
        self.message = Some((message, is_error));
        self.refresh_visible();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::Writable;

    #[test]
    fn secret_keys_are_not_copied() {
        let entry = KeystoreEntry {
            alias: "aes".into(),
            certificate: None,
            content: Content::Certificates {
                kind: Kind::SecretKey,
                certificates: vec![],
            },
            chain_warning: None,
        };
        let source = Document::jks(Writable::empty(true), "");
        let mut selection = Selection::new("source.jceks".into(), source, vec![entry], true);
        let reason = "its key cannot be read";
        assert_eq!(selection.availability, [Availability::Blocked(reason)]);
        // It is not chosen with the others.
        selection.toggle_all();
        assert_eq!(selection.chosen, [false]);
        assert_eq!(selection.item(0, None).err().as_deref(), Some(reason));

        // Copying into JKS blocks secret keys up front.
        let entry = KeystoreEntry {
            alias: "aes".into(),
            certificate: None,
            content: Content::Certificates {
                kind: Kind::SecretKey,
                certificates: vec![],
            },
            chain_warning: None,
        };
        let source = Document::jks(Writable::empty(true), "");
        let mut selection = Selection::new("source.jceks".into(), source, vec![entry], false);
        let jks_reason = "a JKS keystore cannot hold secret keys";
        assert_eq!(selection.availability, [Availability::Blocked(jks_reason)]);
        selection.toggle_all();
        assert_eq!(selection.chosen, [false]);
        assert_eq!(selection.item(0, None).err().as_deref(), Some(jks_reason));
    }
}
