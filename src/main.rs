mod asn1_dump;
mod canonical_path;
mod certificate;
mod certificate_file;
mod certificate_request;
mod editing;
mod entry_details;
mod entry_list;
mod export;
mod file_picker;
mod java_serialization;
mod key_import;
mod key_protection;
mod keystore;
mod new_password;
mod path_bar;
mod pkcs12;
mod save;
mod startup;

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout},
    style::{Color, Style, Stylize},
    text::Line,
    widgets::{Block, Cell, Paragraph, Row, Table, TableState, Wrap},
};

use entry_list::{ExpiryStatus, SortOrder};
use file_picker::FilePicker;
use keystore::KeystoreEntry;
use zeroize::{Zeroize, Zeroizing};

/// Real keystores are far smaller; refuse to read arbitrarily large files.
const MAX_KEYSTORE_SIZE: u64 = 64 * 1024 * 1024;

/// Grows its buffer manually so no reallocation leaves a stale copy behind.
struct Password(Zeroizing<String>);

impl Default for Password {
    fn default() -> Self {
        Self(Zeroizing::new(String::with_capacity(64)))
    }
}

impl Password {
    fn push(&mut self, ch: char) {
        if self.0.len() + ch.len_utf8() > self.0.capacity() {
            let mut grown = String::with_capacity(self.0.capacity() * 2 + ch.len_utf8());
            grown.push_str(&self.0);
            // Dropping the old buffer wipes it.
            self.0 = Zeroizing::new(grown);
        }
        self.0.push(ch);
    }

    fn pop(&mut self) {
        let Some((index, _)) = self.0.char_indices().next_back() else {
            return;
        };
        // Wipe the removed character's bytes before shortening the buffer.
        let mut bytes = std::mem::take(&mut *self.0).into_bytes();
        bytes[index..].zeroize();
        bytes.truncate(index);
        *self.0 = String::from_utf8(bytes).expect("truncated at a char boundary");
    }

    fn clear(&mut self) {
        // Zeroes the whole allocation, including spare capacity.
        self.0.zeroize();
    }
}

struct PasswordPrompt {
    path: PathBuf,
    keystore: Store,
    password: Password,
}

#[derive(Default)]
struct App {
    keystore_path: Option<PathBuf>,
    file_picker: Option<FilePicker>,
    password_prompt: Option<PasswordPrompt>,
    entries: Vec<KeystoreEntry>,
    /// Indices into `entries` shown by the table, after filtering and sorting.
    /// `entries_state` selects a position in this list.
    visible: Vec<usize>,
    entries_state: TableState,
    filter: String,
    /// Whether keys are typed into the filter instead of acting as shortcuts.
    editing_filter: bool,
    sort: SortOrder,
    entry_details: Option<entry_details::EntryDetails>,
    error: Option<String>,
    startup_warning: Option<String>,
    /// Shown in yellow while the loaded file is displayed.
    warning: Option<&'static str>,
    /// The loaded keystore's writable form, when it can be edited and saved.
    document: Option<save::Document>,
    /// Whether the entries differ from the file they were loaded from.
    modified: bool,
    /// A question waiting for `y`; any other key cancels it.
    confirm: Option<Confirm>,
    save_as: Option<save::SaveAsPrompt>,
    alias_prompt: Option<editing::AliasPrompt>,
    new_password: Option<new_password::NewPasswordPrompt>,
    /// Whether the file browser is choosing a file to import from.
    importing: bool,
    /// A key pair import waiting for a password or a certificate file.
    key_import: Option<key_import::KeyImport>,
    /// The result of the last edit or save, and whether it failed. Cleared
    /// on the next key.
    message: Option<(String, bool)>,
}

enum Confirm {
    /// Delete the entry at this index of `entries`.
    Delete(usize),
    Quit,
    /// Open the file browser, to replace the modified keystore.
    Open,
    /// Create a keystore, which replaces the modified one.
    New,
}

const NOT_EDITABLE: &str = "Only keystores can be changed, not certificate files.";
const INCOMPLETE_NOT_EDITABLE: &str =
    "This PKCS12 keystore was not read completely, so it cannot be changed.";

const INCOMPLETE_WARNING: &str = "Warning: this PKCS12 entry list is incomplete.";
const SKIPPED_WARNING: &str = "Warning: PEM blocks other than certificates and certificate requests, such as private keys, were not read.";

enum Loaded {
    Store(Store),
    Certificates(certificate_file::CertificateFile),
}

enum Store {
    Jks(keystore::Keystore),
    Pkcs12(pkcs12::Store),
}

/// A keystore whose password was verified.
struct Opened {
    verified: pkcs12::Verified,
    document: Option<save::Document>,
}

impl Store {
    fn verify(self, password: &str) -> Result<Opened, Box<(Self, Option<&'static str>)>> {
        match self {
            Self::Jks(store) => store
                .open(password)
                .map(|(entries, writable)| Opened {
                    verified: pkcs12::Verified {
                        entries,
                        incomplete: false,
                    },
                    document: Some(save::Document::jks(writable, password)),
                })
                .map_err(|store| Box::new((Self::Jks(store), None))),
            Self::Pkcs12(store) => match store.open(password) {
                Ok((verified, writable)) => Ok(Opened {
                    verified,
                    document: writable.map(save::Document::Pkcs12),
                }),
                Err(pkcs12::VerifyError::Password) => Err(Box::new((Self::Pkcs12(store), None))),
                Err(pkcs12::VerifyError::Invalid(message)) => {
                    Err(Box::new((Self::Pkcs12(store), Some(message))))
                }
            },
        }
    }
}

/// A move through the entry table, by one row up or down.
#[derive(Clone, Copy)]
enum Step {
    Previous,
    Next,
}

impl App {
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }

        self.message = None;
        // Ctrl+C quits at once, even with unsaved changes.
        if key.code == KeyCode::Char('c')
            && key.modifiers.contains(KeyModifiers::CONTROL)
            && !key.modifiers.contains(KeyModifiers::ALT)
        {
            return true;
        }
        if let Some(confirm) = self.confirm.take() {
            return key.code == KeyCode::Char('y') && self.confirmed(confirm);
        }
        if key.code == KeyCode::Char('q') && !self.typing() {
            return self.quit();
        }

        if self.password_prompt.is_some() {
            self.handle_password(key);
        } else if let Some(picker) = &mut self.file_picker {
            if key.code == KeyCode::Esc {
                if !picker.clear_filter() {
                    self.file_picker = None;
                    self.importing = false;
                    self.cancel_key_import();
                }
            } else if let Some(path) = picker.handle_key(key) {
                self.file_picker = None;
                if std::mem::take(&mut self.importing) {
                    self.import_file(&path);
                } else {
                    self.open_file(path);
                }
            }
        } else if let Some(details) = &mut self.entry_details {
            if details.handle_event(key) {
                self.entry_details = None;
            }
        } else if self.unlocking_import() {
            self.handle_import_password(key);
        } else if self.alias_prompt.is_some() {
            self.handle_alias(key);
        } else if self.new_password.is_some() {
            self.handle_new_password(key);
        } else if let Some(prompt) = &mut self.save_as {
            let creating = prompt.creating;
            match prompt.handle_key(key) {
                save::Outcome::Editing => {}
                save::Outcome::Cancelled => self.save_as = None,
                save::Outcome::Save(path) if creating => self.password_new_keystore(path),
                save::Outcome::Save(path) => self.save_new(path),
            }
        } else if self.editing_filter {
            self.handle_filter(key);
        } else {
            match key.code {
                KeyCode::Enter => self.show_selected_details(),
                KeyCode::Char('o') if self.modified => self.confirm = Some(Confirm::Open),
                KeyCode::Char('o') => self.open_picker(),
                KeyCode::Delete => self.ask_delete(),
                KeyCode::Char('d') if is_text_input(key.modifiers) => self.ask_delete(),
                KeyCode::Char('n') if is_text_input(key.modifiers) => self.ask_new_keystore(),
                KeyCode::Char('p') if is_text_input(key.modifiers) => self.ask_password_change(),
                KeyCode::Char('P') if is_text_input(key.modifiers) => self.ask_key_password(),
                KeyCode::Char('r') if is_text_input(key.modifiers) => self.ask_rename(),
                KeyCode::Char('i') if is_text_input(key.modifiers) => self.ask_import(),
                KeyCode::Char('w') if is_text_input(key.modifiers) => self.save(),
                KeyCode::Char('W') if is_text_input(key.modifiers) => {
                    if self.editable()
                        && let Some(path) = &self.keystore_path
                    {
                        self.save_as = Some(save::SaveAsPrompt::new(path));
                    }
                }
                KeyCode::Char('/') if !self.entries.is_empty() => self.editing_filter = true,
                KeyCode::Char('s') if !self.entries.is_empty() => {
                    self.sort = self.sort.next();
                    self.refresh_visible();
                }
                KeyCode::Esc => return self.quit(),
                KeyCode::Down | KeyCode::Char('j') => self.move_entry_selection(Step::Next),
                KeyCode::Up | KeyCode::Char('k') => self.move_entry_selection(Step::Previous),
                _ => {}
            }
        }

        false
    }

    /// Asks whether to delete the selected entry.
    fn ask_delete(&mut self) {
        if let Some(index) = self.selected_entry()
            && self.editable()
        {
            self.confirm = Some(Confirm::Delete(index));
        }
    }

    /// Quits, or asks first when there are unsaved changes.
    fn quit(&mut self) -> bool {
        if self.modified {
            self.confirm = Some(Confirm::Quit);
        }
        !self.modified
    }

    /// Carries out a confirmed question. Returns whether to quit.
    fn confirmed(&mut self, confirm: Confirm) -> bool {
        match confirm {
            Confirm::Quit => return true,
            Confirm::Open => self.open_picker(),
            Confirm::New => self.name_new_keystore(),
            Confirm::Delete(index) => {
                let Some(document) = &mut self.document else {
                    return false;
                };
                let message = format!("Deleted entry '{}'.", self.entries[index].alias);
                document.remove(&mut self.entries, index);
                self.modified = true;
                self.message = Some((message, false));
                // Indices after the deleted entry shifted, so keep the
                // selection at the same row instead of following an entry.
                let position = self.entries_state.selected();
                self.visible = entry_list::visible_entries(&self.entries, &self.filter, self.sort);
                self.entries_state.select(
                    self.visible
                        .len()
                        .checked_sub(1)
                        .map(|last| position.unwrap_or(0).min(last)),
                );
            }
        }
        false
    }

    /// Whether the loaded file can be changed and saved; explains when a
    /// loaded file cannot.
    fn editable(&mut self) -> bool {
        if self.document.is_none() && self.keystore_path.is_some() {
            let reason = if self.warning == Some(INCOMPLETE_WARNING) {
                INCOMPLETE_NOT_EDITABLE
            } else {
                NOT_EDITABLE
            };
            self.message = Some((reason.into(), true));
        }
        self.document.is_some()
    }

    /// Replaces the opened file with the modified keystore.
    fn save(&mut self) {
        if !self.editable() {
            return;
        }
        let (Some(document), Some(path)) = (&self.document, &self.keystore_path) else {
            return;
        };
        self.message = Some(if !self.modified {
            ("No changes to save.".into(), false)
        } else {
            match document.save(path, &self.entries) {
                Ok(()) => {
                    self.modified = false;
                    (format!("Saved '{}'.", path.display()), false)
                }
                Err(error) => (error, true),
            }
        });
    }

    /// Writes the keystore to a new file, which becomes the opened file.
    fn save_new(&mut self, path: PathBuf) {
        let Some(document) = &self.document else {
            return;
        };
        // A name asking for another format converts the keystore.
        let target = save::Format::from_name(&path).filter(|&format| format != document.format());
        let saved = match target {
            Some(format) => self.save_converted(&path, format),
            None => document
                .save_new(&path, &self.entries)
                .map(|()| String::new()),
        };
        self.message = Some(match saved {
            Ok(format) => {
                let path = canonical_path::canonicalize(&path).unwrap_or(path);
                let message = format!("Saved '{}'{format}.", path.display());
                self.keystore_path = Some(path);
                self.modified = false;
                self.save_as = None;
                (message, false)
            }
            Err(error) => (error, true),
        });
    }

    /// Writes the keystore to the new file `path` in another format and
    /// opens that file in its place. Returns what to add to the message.
    fn save_converted(&mut self, path: &Path, format: save::Format) -> Result<String, String> {
        let document = self.document.as_ref().ok_or("No keystore is open.")?;
        let data = document.convert(&self.entries, format)?;
        let password = Zeroizing::new(document.password().to_owned());
        save::create(path, &data)?;
        // The converted keystore was read back before it was written.
        let opened = match load(path)? {
            Loaded::Store(store) => store.verify(&password).ok(),
            Loaded::Certificates(_) => None,
        }
        .ok_or("The converted keystore could not be opened again.")?;
        self.show_verified(path.to_path_buf(), opened);
        Ok(format!(" as {}", format.label()))
    }

    /// Whether letter keys are typed as text rather than used as shortcuts.
    fn typing(&self) -> bool {
        self.password_prompt.is_some()
            || self.file_picker.is_some()
            || self.editing_filter
            || self.save_as.is_some()
            || self.alias_prompt.is_some()
            || self.new_password.is_some()
            || self.unlocking_import()
            || self
                .entry_details
                .as_ref()
                .is_some_and(entry_details::EntryDetails::exporting)
    }

    fn handle_filter(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.editing_filter = false;
                self.filter.clear();
            }
            KeyCode::Enter => {
                self.editing_filter = false;
                return;
            }
            KeyCode::Backspace => {
                self.filter.pop();
            }
            KeyCode::Char(ch) if is_text_input(key.modifiers) => self.filter.push(ch),
            KeyCode::Down => return self.move_entry_selection(Step::Next),
            KeyCode::Up => return self.move_entry_selection(Step::Previous),
            _ => return,
        }
        self.refresh_visible();
    }

    /// Moves one row, wrapping at either end; selects the first row when
    /// none is selected. A selection past the end counts as the last row,
    /// as in `selected_entry`.
    fn move_entry_selection(&mut self, step: Step) {
        let Some(last) = self.visible.len().checked_sub(1) else {
            self.entries_state.select(None);
            return;
        };
        let selected = self.entries_state.selected().map(|index| index.min(last));
        let next = match (selected, step) {
            (Some(index), Step::Previous) => index.checked_sub(1).unwrap_or(last),
            (Some(index), Step::Next) if index < last => index + 1,
            _ => 0,
        };
        self.entries_state.select(Some(next));
    }

    /// The `entries` index of the selected row, if any row is shown.
    fn selected_entry(&self) -> Option<usize> {
        let last = self.visible.len().checked_sub(1)?;
        let position = self.entries_state.selected()?.min(last);
        Some(self.visible[position])
    }

    /// Re-applies the filter and sort, keeping the selected entry selected
    /// when it is still shown, or else selecting the first shown entry.
    fn refresh_visible(&mut self) {
        let selected = self.selected_entry();
        self.visible = entry_list::visible_entries(&self.entries, &self.filter, self.sort);
        let position = selected
            .and_then(|entry| self.visible.iter().position(|&index| index == entry))
            .or((!self.visible.is_empty()).then_some(0));
        self.entries_state.select(position);
    }

    fn handle_password(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Esc {
            self.password_prompt = None;
            self.error = None;
            return;
        }
        let Some(prompt) = &mut self.password_prompt else {
            return;
        };
        match key.code {
            KeyCode::Char(ch) if is_text_input(key.modifiers) => prompt.password.push(ch),
            KeyCode::Backspace => prompt.password.pop(),
            KeyCode::Enter => {
                let PasswordPrompt {
                    path,
                    keystore,
                    mut password,
                } = self.password_prompt.take().unwrap();
                let result = keystore.verify(&password.0);
                password.clear();
                match result {
                    Ok(verified) => self.show_verified(path, verified),
                    Err(failure) if failure.1.is_some() => {
                        self.error = Some(failure.1.unwrap().into());
                    }
                    Err(failure) => {
                        let (keystore, _) = *failure;
                        self.password_prompt = Some(PasswordPrompt {
                            path,
                            keystore,
                            password,
                        });
                        self.error = Some(
                            "Incorrect password or keystore integrity check failed. Try again or press Esc."
                                .into(),
                        );
                    }
                }
            }
            _ => {}
        }
    }

    fn show_selected_details(&mut self) {
        if let Some(index) = self.selected_entry() {
            let path = self.keystore_path.as_deref().unwrap_or(Path::new(""));
            self.entry_details = Some(entry_details::EntryDetails::new(&self.entries[index], path));
        }
    }

    fn open_file(&mut self, path: PathBuf) {
        self.startup_warning = None;
        self.error = None;
        // Parse the entire structure once, before prompting. Empty-password
        // stores are verified immediately; others require their password.
        let keystore = match load(&path) {
            Ok(Loaded::Store(keystore)) => keystore,
            Ok(Loaded::Certificates(file)) => {
                self.show_certificate_file(path, file);
                return;
            }
            Err(error) => {
                self.error = Some(error);
                return;
            }
        };
        match keystore.verify("") {
            Ok(verified) => self.show_verified(path, verified),
            Err(failure) if failure.1.is_some() => {
                self.error = Some(failure.1.unwrap().into());
            }
            Err(failure) => {
                let (keystore, _) = *failure;
                self.password_prompt = Some(PasswordPrompt {
                    path,
                    keystore,
                    password: Password::default(),
                });
            }
        }
    }

    fn show_entries(&mut self, path: PathBuf, entries: Vec<KeystoreEntry>) {
        self.keystore_path = Some(path);
        self.entries = entries;
        self.filter.clear();
        self.editing_filter = false;
        // The sort order is kept across keystores; the filter is not.
        self.visible = entry_list::visible_entries(&self.entries, "", self.sort);
        self.entries_state =
            TableState::default().with_selected((!self.visible.is_empty()).then_some(0));
        self.entry_details = None;
        self.error = None;
        self.warning = None;
        // Dropping the previous document wipes its password.
        self.document = None;
        self.modified = false;
        self.confirm = None;
        self.save_as = None;
        self.alias_prompt = None;
        self.new_password = None;
        self.importing = false;
        self.key_import = None;
        self.message = None;
    }

    /// Lists a standalone certificate file. A file with a single certificate
    /// or request opens straight into its details; `Esc` returns to the list.
    fn show_certificate_file(&mut self, path: PathBuf, file: certificate_file::CertificateFile) {
        self.show_entries(path, file.entries);
        self.warning = file.skipped.then_some(SKIPPED_WARNING);
        if self.entries.len() == 1 {
            self.show_selected_details();
        }
    }

    fn show_verified(&mut self, path: PathBuf, opened: Opened) {
        self.show_entries(path, opened.verified.entries);
        self.warning = opened.verified.incomplete.then_some(INCOMPLETE_WARNING);
        self.document = opened.document;
    }

    fn open_picker(&mut self) {
        let directory = self
            .keystore_path
            .as_deref()
            .map_or_else(std::env::current_dir, |path| Ok(path_bar::directory(path)));

        match directory.and_then(|path| FilePicker::new(&path)) {
            Ok(picker) => {
                self.file_picker = Some(picker);
                self.error = None;
            }
            Err(error) => self.error = Some(format!("Could not open file browser: {error}")),
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        // A question is asked on the main view, even from the details.
        if self.password_prompt.is_none()
            && self.file_picker.is_none()
            && self.confirm.is_none()
            && let Some(details) = &mut self.entry_details
        {
            details.draw(frame);
            return;
        }
        let shortcuts = self.shortcuts();
        let [content, status, path_area, help] = Layout::vertical([
            Constraint::Min(3),
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(shortcuts.len() as u16),
        ])
        .areas(frame.area());

        if let Some(prompt) = &self.password_prompt {
            let masked = "*".repeat(prompt.password.0.chars().count());
            frame.render_widget(
                Paragraph::new(format!(
                    "Enter the keystore password to verify and list its entries.\n\nPassword: {masked}"
                ))
                .block(Block::bordered().title(format!(" {} ", prompt.path.display())))
                .wrap(Wrap { trim: false }),
                content,
            );
        } else if self.keystore_path.is_some() {
            let mut title = vec![" keystore-tui ".blue()];
            if self.modified {
                title.push("[modified] ".yellow());
            }
            let mut block = Block::bordered().title(Line::from(title));
            if !self.entries.is_empty() {
                block = block.title_bottom(Line::from(self.list_title()).right_aligned());
            }
            if self.entries.is_empty() {
                frame.render_widget(
                    Paragraph::new("This keystore contains no entries.").block(block),
                    content,
                );
            } else if self.visible.is_empty() {
                let hint = if self.editing_filter {
                    "Edit the filter with Backspace, or press Esc to clear it."
                } else {
                    "Press / to edit the filter, then Esc to clear it."
                };
                frame.render_widget(
                    Paragraph::new(format!("No matching entries.\n\n{hint}"))
                        .block(block)
                        .wrap(Wrap { trim: false }),
                    content,
                );
            } else {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.as_secs() as i64);
                let selected = self
                    .entries_state
                    .selected()
                    .map(|position| position.min(self.visible.len() - 1));
                let rows = self.visible.iter().enumerate().map(|(position, &index)| {
                    let entry = &self.entries[index];
                    let is_selected = selected == Some(position);
                    let mut cells =
                        vec![Cell::from(entry.alias.as_str()), Cell::from(entry.kind())];
                    match &entry.certificate {
                        Some(summary) => {
                            let expiry = Cell::from(summary.expiry_text());
                            cells.extend([
                                Cell::from(summary.algorithm.as_str()),
                                Cell::from(summary.key_size_text()),
                                match (entry_list::expiry_status(summary, now), is_selected) {
                                    (ExpiryStatus::Expired, true) => expiry
                                        .fg(Color::Rgb(255, 255, 255))
                                        .bg(Color::Rgb(128, 0, 0)),
                                    (ExpiryStatus::Expired, false) => expiry.fg(Color::Red),
                                    (ExpiryStatus::ExpiringSoon, true) => {
                                        expiry.fg(Color::Rgb(0, 0, 0)).bg(Color::Rgb(255, 175, 0))
                                    }
                                    (ExpiryStatus::ExpiringSoon, false) => expiry.fg(Color::Yellow),
                                    (ExpiryStatus::Valid, _) => expiry,
                                },
                                match (summary.weaknesses.is_empty(), is_selected) {
                                    (true, _) => Cell::from(""),
                                    (false, true) => Cell::from("Weak")
                                        .fg(Color::Rgb(0, 0, 0))
                                        .bg(Color::Rgb(255, 175, 0)),
                                    (false, false) => Cell::from("Weak").fg(Color::Yellow),
                                },
                            ]);
                        }
                        None => cells.extend(["-", "-", "-", "-"].map(Cell::from)),
                    }
                    let row = Row::new(cells);
                    if is_selected {
                        row.style(
                            Style::default()
                                .fg(Color::Rgb(0, 0, 0))
                                .bg(Color::Rgb(175, 255, 255))
                                .bold(),
                        )
                    } else {
                        row
                    }
                });
                let table = Table::new(
                    rows,
                    [
                        Constraint::Fill(1),
                        Constraint::Length(19),
                        Constraint::Length(10),
                        Constraint::Length(9),
                        Constraint::Length(10),
                        Constraint::Length(6),
                    ],
                )
                .header(
                    Row::new([
                        "Alias",
                        "Type",
                        "Algorithm",
                        "Key size",
                        "Expires",
                        "Crypto",
                    ])
                    .bold(),
                )
                .block(block)
                .highlight_symbol("> ");
                frame.render_stateful_widget(table, content, &mut self.entries_state);
            }
        } else {
            frame.render_widget(
                Paragraph::new(
                    "No keystore selected.\n\nPress n to create a JKS, JCEKS, or PKCS12 keystore.\n\nPress o to open a keystore (.jks, .jceks, .p12, .pfx, cacerts, jssecacerts) or a certificate or request file (.pem, .crt, .cer, .der, .p7b, .p7c, .csr, .p10).",
                )
                .block(Block::bordered().title(" keystore-tui ".blue()))
                .wrap(Wrap { trim: false }),
                content,
            );
        }
        if let Some(question) = self.question() {
            frame.render_widget(
                Paragraph::new(question)
                    .style(Style::default().fg(Color::Yellow))
                    .wrap(Wrap { trim: false }),
                status,
            );
        } else if let Some((message, failed)) = &self.message {
            let color = if *failed { Color::Red } else { Color::Green };
            frame.render_widget(
                Paragraph::new(message.as_str())
                    .style(Style::default().fg(color))
                    .wrap(Wrap { trim: false }),
                status,
            );
        } else if let Some(error) = &self.error {
            frame.render_widget(
                Paragraph::new(error.as_str())
                    .style(Style::default().fg(Color::Red))
                    .wrap(Wrap { trim: false }),
                status,
            );
        } else if let Some(warning) = self.startup_warning.as_deref().or(self.warning)
            && self.file_picker.is_none()
        {
            frame.render_widget(
                Paragraph::new(warning)
                    .style(Style::default().fg(Color::Yellow))
                    .wrap(Wrap { trim: false }),
                status,
            );
        }
        // The password prompt shows the file being opened, not the one already open.
        let path = match &self.password_prompt {
            Some(prompt) => Some(&prompt.path),
            None => self.keystore_path.as_ref(),
        };
        if let Some(path) = path {
            frame.render_widget(path_bar::line(path), path_area);
        }
        if let Some(picker) = &mut self.file_picker {
            if self.key_import.is_some() {
                picker.draw_titled(frame, " Certificate file of the imported key ");
            } else if self.importing {
                picker.draw_titled(frame, " Import certificate or key pair from file ");
            } else {
                picker.draw(frame);
            }
        } else {
            frame.render_widget(Paragraph::new(shortcuts), help);
        }
    }

    /// The bottom lines: the shortcuts, or the "save as" name being typed.
    fn shortcuts(&self) -> Vec<Line<'static>> {
        const LIST: &str = "o Open file | Enter Details | Up/Down j/k Scroll | / Filter | s Sort | q / Esc / Ctrl+C Quit";
        if self.password_prompt.is_some() {
            vec!["Enter Verify | Backspace Delete | Esc Cancel | Ctrl+C Quit".into()]
        } else if let Some(prompt) = &self.save_as {
            vec![
                Line::from(vec![
                    if prompt.creating {
                        "New keystore file (.jks, .jceks, or .p12): ".bold()
                    } else {
                        "Save keystore as: ".bold()
                    },
                    format!("{}_", prompt.path).into(),
                ]),
                if prompt.creating {
                    "Enter Save | Ctrl+U Clear | Esc Cancel | Ctrl+C Quit".into()
                } else {
                    "A .jks, .jceks, or .p12 name converts | Enter Save | Ctrl+U Clear | Esc Cancel | Ctrl+C Quit".into()
                },
            ]
        } else if let Some(prompt) = &self.new_password {
            use new_password::Purpose;
            let alias = |index: &usize| self.entries[*index].alias.as_str();
            let label = match (&prompt.purpose, prompt.repeating()) {
                (_, true) => "Type the password again: ".into(),
                (Purpose::Create(_), false) => "Password for the new keystore: ".into(),
                (Purpose::Change, false) => "New keystore password: ".into(),
                (Purpose::KeyCurrent(index), false) => {
                    format!("Current password of key '{}': ", alias(index))
                }
                (Purpose::KeyChange(index, _), false) => {
                    format!("New password for key '{}': ", alias(index))
                }
            };
            vec![
                Line::from(vec![
                    label.bold(),
                    format!("{}_", "*".repeat(prompt.current.0.chars().count())).into(),
                ]),
                "Enter Confirm | Backspace Delete | Esc Cancel | Ctrl+C Quit".into(),
            ]
        } else if let Some((file, password)) = self
            .key_import
            .as_ref()
            .and_then(|import| import.password())
        {
            vec![
                Line::from(vec![
                    format!("Password of '{file}': ").bold(),
                    format!("{}_", "*".repeat(password.chars().count())).into(),
                ]),
                "Enter Confirm | Backspace Delete | Esc Cancel | Ctrl+C Quit".into(),
            ]
        } else if let Some(prompt) = &self.alias_prompt {
            let label = match prompt.action {
                editing::Action::Rename(index) => {
                    format!("New alias for '{}': ", self.entries[index].alias)
                }
                editing::Action::Import(_) => "Alias for the imported certificate: ".into(),
                editing::Action::ImportKey(..) => "Alias for the imported key pair: ".into(),
            };
            vec![
                Line::from(vec![label.bold(), format!("{}_", prompt.alias).into()]),
                "Enter Confirm | Ctrl+U Clear | Esc Cancel | Ctrl+C Quit".into(),
            ]
        } else if self.editing_filter {
            vec!["Type to filter | Enter Apply | Esc Clear | Up/Down Scroll | Ctrl+C Quit".into()]
        } else if self.document.is_some() && self.file_picker.is_none() {
            vec![
                "n New | i Import | r Rename | d Delete | w Save | W Save as | p Password | P Key password".into(),
                LIST.into(),
            ]
        } else {
            vec![LIST.into()]
        }
    }

    /// The question waiting for `y`, if any.
    fn question(&self) -> Option<String> {
        Some(match self.confirm.as_ref()? {
            Confirm::Delete(index) => format!(
                "Delete entry '{}'? Press y to delete, any other key to cancel.",
                self.entries[*index].alias
            ),
            Confirm::Quit => {
                "Quit without saving the changes? Press y to quit, any other key to cancel.".into()
            }
            Confirm::New => {
                "Creating a keystore discards the unsaved changes. Press y to continue, any other key to cancel.".into()
            }
            Confirm::Open => {
                "Opening another file discards the unsaved changes. Press y to continue, any other key to cancel.".into()
            }
        })
    }

    /// Describes the filter, shown entry count, and sort order.
    fn list_title(&self) -> String {
        let total = self.entries.len();
        let shown = self.visible.len();
        let filter = if self.editing_filter {
            format!("Filter: {}_ | {shown} of {total} entries | ", self.filter)
        } else if self.filter.is_empty() {
            format!("{total} entries | ")
        } else {
            format!("Filter: '{}' | {shown} of {total} entries | ", self.filter)
        };
        format!(" {filter}Sort: {} ", self.sort.label())
    }
}

/// Whether a character key with these modifiers is text rather than a
/// shortcut. Windows reports AltGr as Ctrl+Alt; elsewhere Ctrl+Alt is a chord.
fn is_text_input(modifiers: KeyModifiers) -> bool {
    let control = modifiers.contains(KeyModifiers::CONTROL);
    let alt = modifiers.contains(KeyModifiers::ALT);
    (cfg!(windows) && control && alt) || (!control && !alt)
}

/// Detects the format from the content first, then from the file name.
fn load(path: &Path) -> Result<Loaded, String> {
    let data = read_limited(path, MAX_KEYSTORE_SIZE)
        .map_err(|error| format!("Cannot read {}: {error}", path.display()))?;
    let is_pkcs12_name = path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("p12") || ext.eq_ignore_ascii_case("pfx"));
    let certificates = || {
        certificate_file::parse(&data)
            .map(Loaded::Certificates)
            .map_err(|error| {
                format!(
                    "{} is not a valid certificate file: {error}",
                    path.display()
                )
            })
    };
    let pkcs12 = || {
        pkcs12::parse(&data)
            .map(|store| Loaded::Store(Store::Pkcs12(store)))
            .map_err(|error| format!("{} is not a valid PKCS12 keystore: {error}", path.display()))
    };
    if keystore::has_magic(&data) {
        jks(data, path)
    } else if certificate_file::is_pem(&data) {
        certificates()
    } else if is_pkcs12_name {
        pkcs12()
    } else if certificate_file::has_extension(path) {
        certificates()
    } else if data.first() == Some(&0x30) {
        // A PFX never reads as a certificate or PKCS#7 bundle, so try those first.
        certificates().or_else(|_| pkcs12())
    } else {
        jks(data, path)
    }
}

fn jks(data: Vec<u8>, path: &Path) -> Result<Loaded, String> {
    let format = if keystore::is_jceks(&data) {
        "JCEKS"
    } else {
        "JKS"
    };
    keystore::parse(data)
        .map(|store| Loaded::Store(Store::Jks(store)))
        .map_err(|error| {
            format!(
                "{} is not a valid {format} keystore: {error}",
                path.display()
            )
        })
}

fn read_limited(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let size_hint = file.metadata()?.len();
    if size_hint > limit {
        return Err(too_large(limit));
    }
    read_bounded(file, size_hint, limit)
}

/// Reads at most `limit + 1` bytes, so an oversized input is detected without
/// reading all of it. `size_hint` pre-sizes the buffer to avoid regrowth.
fn read_bounded(reader: impl Read, size_hint: u64, limit: u64) -> io::Result<Vec<u8>> {
    let capacity = usize::try_from(size_hint.min(limit + 1)).unwrap_or(0);
    let mut data = Vec::with_capacity(capacity);
    reader.take(limit + 1).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        return Err(too_large(limit));
    }
    Ok(data)
}

fn too_large(limit: u64) -> io::Error {
    io::Error::other(format!(
        "file is larger than the {limit}-byte keystore limit"
    ))
}

fn main() -> ExitCode {
    let path = match startup::argument(std::env::args_os().skip(1)) {
        Ok(startup::Command::Open(path)) => path,
        Ok(startup::Command::Help) => {
            println!("{}", startup::help());
            return ExitCode::SUCCESS;
        }
        Ok(startup::Command::Version) => {
            println!("keystore-tui {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Err(()) => {
            eprintln!("{}", startup::USAGE);
            return ExitCode::from(2);
        }
    };
    let app = match startup::prepare(path, startup::password) {
        Ok(app) => app,
        Err(error) => {
            eprintln!("keystore-tui: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut terminal = match ratatui::try_init() {
        Ok(terminal) => terminal,
        Err(err) => {
            // Undo raw mode in case it was enabled before the failure.
            let _ = ratatui::try_restore();
            eprintln!("keystore-tui must be run in an interactive terminal: {err}");
            return ExitCode::FAILURE;
        }
    };
    let result = run(&mut terminal, app);
    ratatui::restore();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("keystore-tui: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(terminal: &mut DefaultTerminal, mut app: App) -> io::Result<()> {
    loop {
        terminal.draw(|frame| app.draw(frame))?;

        // Periodically redraw so a missed resize notification cannot leave
        // the layout stale until the next key press.
        if event::poll(std::time::Duration::from_millis(250))?
            && let Event::Key(key) = event::read()?
            && app.handle_key(key)
        {
            return Ok(());
        }
    }
}
