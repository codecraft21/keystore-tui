use std::{
    fs, io,
    path::{Path, PathBuf},
};

use ratatui::{
    Frame,
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers},
    layout::{Constraint, Layout, Margin},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, List, ListItem, ListState, Paragraph, Wrap},
};

struct Entry {
    path: PathBuf,
    is_directory: bool,
}

pub(crate) struct FilePicker {
    directory: PathBuf,
    entries: Vec<Entry>,
    /// Typed name prefix; entries not starting with it are hidden.
    filter: String,
    /// Indices into `entries` that are listed; `selection` indexes this.
    visible: Vec<usize>,
    selection: ListState,
    error: Option<String>,
}

impl FilePicker {
    pub(crate) fn new(directory: &Path) -> io::Result<Self> {
        let directory = directory.canonicalize()?;
        let mut entries = Vec::new();
        for entry in fs::read_dir(&directory)? {
            let path = entry?.path();
            let is_directory = path.is_dir();
            let is_supported = path.extension().is_some_and(|extension| {
                ["jks", "jceks", "p12", "pfx"]
                    .iter()
                    .any(|ext| extension.eq_ignore_ascii_case(ext))
            }) || path.file_name().is_some_and(|name| {
                ["cacerts", "jssecacerts"]
                    .iter()
                    .any(|supported| name.eq_ignore_ascii_case(supported))
            }) || crate::certificate_file::has_extension(&path);
            if is_directory || (is_supported && path.is_file()) {
                entries.push(Entry { path, is_directory });
            }
        }
        entries.sort_by(|a, b| {
            b.is_directory
                .cmp(&a.is_directory)
                .then_with(|| a.path.file_name().cmp(&b.path.file_name()))
        });
        // Select the first file or folder rather than `../`; with nothing
        // else listed, select `../` (or nothing at the filesystem root).
        let first = usize::from(directory.parent().is_some() && !entries.is_empty());
        if let Some(parent) = directory.parent() {
            entries.insert(
                0,
                Entry {
                    path: parent.to_path_buf(),
                    is_directory: true,
                },
            );
        }

        let selection = ListState::default().with_selected((!entries.is_empty()).then_some(first));
        Ok(Self {
            directory,
            visible: (0..entries.len()).collect(),
            entries,
            filter: String::new(),
            selection,
            error: None,
        })
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> Option<PathBuf> {
        let result = match key.code {
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.filter.push(c);
                self.refilter();
                return None;
            }
            KeyCode::Backspace => {
                if self.filter.pop().is_some() {
                    self.refilter();
                }
                return None;
            }
            KeyCode::Up => {
                self.move_selection(-1);
                return None;
            }
            KeyCode::Down => {
                self.move_selection(1);
                return None;
            }
            KeyCode::Home => {
                self.selection
                    .select((!self.visible.is_empty()).then_some(0));
                return None;
            }
            KeyCode::End => {
                self.selection.select(self.visible.len().checked_sub(1));
                return None;
            }
            KeyCode::Enter | KeyCode::Right => self.open_selected(key.code == KeyCode::Enter),
            KeyCode::Left => self.open_parent(),
            _ => return None,
        };

        match result {
            Ok(path) => {
                self.error = None;
                path
            }
            Err(error) => {
                self.error = Some(format!("Could not open selection: {error}"));
                None
            }
        }
    }

    /// Clears the name filter, returning `false` if it was already empty.
    pub(crate) fn clear_filter(&mut self) -> bool {
        if self.filter.is_empty() {
            return false;
        }
        self.filter.clear();
        self.refilter();
        true
    }

    /// Lists the entries whose name starts with the filter, ignoring case.
    /// `../` is listed only while the filter is empty. The selected entry
    /// stays selected if still listed; otherwise the first entry other than
    /// `../` is, as when a directory opens.
    fn refilter(&mut self) {
        let previous = self
            .selection
            .selected()
            .and_then(|i| self.visible.get(i))
            .copied();
        let prefix = self.filter.to_lowercase();
        let parent = self.directory.parent();
        self.visible = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                prefix.is_empty()
                    || (Some(entry.path.as_path()) != parent
                        && entry.path.file_name().is_some_and(|name| {
                            name.to_string_lossy().to_lowercase().starts_with(&prefix)
                        }))
            })
            .map(|(index, _)| index)
            .collect();
        let is_parent = |&index: &usize| Some(self.entries[index].path.as_path()) == parent;
        let kept = previous.and_then(|previous| self.visible.iter().position(|&i| i == previous));
        let first = self.visible.iter().position(|i| !is_parent(i));
        self.selection
            .select(kept.or(first).or((!self.visible.is_empty()).then_some(0)));
    }

    fn move_selection(&mut self, offset: isize) {
        if let Some(selected) = self.selection.selected() {
            let next = if offset < 0 {
                selected.checked_sub(1).unwrap_or(self.visible.len() - 1)
            } else {
                (selected + 1) % self.visible.len()
            };
            self.selection.select(Some(next));
        }
    }

    fn open_selected(&mut self, allow_file: bool) -> io::Result<Option<PathBuf>> {
        let Some(entry) = self
            .selection
            .selected()
            .and_then(|i| self.visible.get(i))
            .and_then(|&i| self.entries.get(i))
        else {
            return Ok(None);
        };

        if entry.is_directory {
            *self = Self::new(&entry.path)?;
        } else if allow_file {
            let path = entry.path.canonicalize()?;
            if !fs::metadata(&path)?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "The selected entry is no longer a file.",
                ));
            }
            return Ok(Some(path));
        }

        Ok(None)
    }

    fn open_parent(&mut self) -> io::Result<Option<PathBuf>> {
        if let Some(parent) = self.directory.parent() {
            *self = Self::new(parent)?;
        }
        Ok(None)
    }

    pub(crate) fn draw(&mut self, frame: &mut Frame) {
        let area = frame.area().inner(Margin {
            horizontal: 2,
            vertical: 1,
        });
        let block = Block::bordered().title(" Open keystore or certificate file ");
        let inner = block.inner(area);
        frame.render_widget(Clear, area);
        frame.render_widget(block, area);

        // The path takes up to two lines; the filter, when typed, one more.
        let heading_height = if self.filter.is_empty() { 2 } else { 3 };
        let [directory, entries, status, help] = Layout::vertical([
            Constraint::Length(heading_height),
            Constraint::Min(1),
            Constraint::Length(2),
            Constraint::Length(2),
        ])
        .areas(inner);
        let mut heading = vec![Line::from(self.directory.to_string_lossy())];
        if !self.filter.is_empty() {
            heading.push(Line::from(vec![
                Span::raw("Filter: "),
                Span::styled(self.filter.as_str(), Style::default().fg(Color::Yellow)),
            ]));
        }
        frame.render_widget(
            Paragraph::new(heading).wrap(Wrap { trim: false }),
            directory,
        );

        let items = self.visible.iter().map(|&index| {
            let entry = &self.entries[index];
            let name = if Some(entry.path.as_path()) == self.directory.parent() {
                "../".to_owned()
            } else {
                let name = entry.path.file_name().unwrap_or_default().to_string_lossy();
                format!("{name}{}", if entry.is_directory { "/" } else { "" })
            };
            ListItem::new(name)
        });
        frame.render_stateful_widget(
            List::new(items).highlight_symbol("> ").highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            entries,
            &mut self.selection,
        );

        let no_match;
        let (message, color) = if let Some(error) = &self.error {
            (error.as_str(), Color::Red)
        } else if !self.filter.is_empty() && self.visible.is_empty() {
            no_match = format!("No entries start with \"{}\".", self.filter);
            (no_match.as_str(), Color::Gray)
        } else if !self.entries.iter().any(|entry| !entry.is_directory) {
            (
                "No keystore (.jks, .jceks, .p12, .pfx, cacerts, jssecacerts) or certificate (.pem, .crt, .cer, .der, .p7b, .p7c, .csr, .p10) files in this directory.",
                Color::Gray,
            )
        } else {
            ("", Color::Reset)
        };
        frame.render_widget(
            Paragraph::new(message)
                .style(Style::default().fg(color))
                .wrap(Wrap { trim: false }),
            status,
        );
        frame.render_widget(
            Paragraph::new(
                "Type to filter | Up/Down Move | Enter Open | Left Parent\nBackspace Delete | Esc Clear filter / Cancel | Ctrl+C Quit",
            )
            .wrap(Wrap { trim: false }),
            help,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(picker: &mut FilePicker, code: KeyCode) -> Option<PathBuf> {
        picker.handle_key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn type_text(picker: &mut FilePicker, text: &str) {
        for c in text.chars() {
            assert_eq!(press(picker, KeyCode::Char(c)), None);
        }
    }

    /// A picker over `/base` listing `../` and the given names, unfiltered.
    fn picker(names: &[&str]) -> FilePicker {
        let directory = PathBuf::from("/base");
        let mut entries = vec![Entry {
            path: PathBuf::from("/"),
            is_directory: true,
        }];
        entries.extend(names.iter().map(|name| Entry {
            path: directory.join(name.trim_end_matches('/')),
            is_directory: name.ends_with('/'),
        }));
        FilePicker {
            directory,
            visible: (0..entries.len()).collect(),
            entries,
            filter: String::new(),
            selection: ListState::default().with_selected(Some(1)),
            error: None,
        }
    }

    fn listed(picker: &FilePicker) -> Vec<String> {
        picker
            .visible
            .iter()
            .map(|&i| picker.entries[i].path.to_string_lossy().into_owned())
            .collect()
    }

    fn selected(picker: &FilePicker) -> Option<String> {
        picker
            .selection
            .selected()
            .map(|i| listed(picker)[i].clone())
    }

    #[test]
    fn navigation_with_no_entries_keeps_selection_empty() {
        let mut picker = FilePicker {
            directory: PathBuf::new(),
            entries: Vec::new(),
            filter: String::new(),
            visible: Vec::new(),
            selection: ListState::default(),
            error: None,
        };
        for key in [KeyCode::Up, KeyCode::Down, KeyCode::Home, KeyCode::End] {
            assert_eq!(press(&mut picker, key), None);
            assert_eq!(picker.selection.selected(), None);
        }
    }

    #[test]
    fn typing_lists_case_insensitive_prefix_matches_without_the_parent() {
        let mut picker = picker(&["Keys/", "alpha.jks", "keystore.JKS", "my-key.p12"]);
        type_text(&mut picker, "kE");
        assert_eq!(listed(&picker), ["/base/Keys", "/base/keystore.JKS"]);
        assert_eq!(selected(&picker).as_deref(), Some("/base/Keys"));

        // Selection wraps within the matches only.
        press(&mut picker, KeyCode::Up);
        assert_eq!(selected(&picker).as_deref(), Some("/base/keystore.JKS"));
        press(&mut picker, KeyCode::Down);
        assert_eq!(selected(&picker).as_deref(), Some("/base/Keys"));
        press(&mut picker, KeyCode::End);
        assert_eq!(selected(&picker).as_deref(), Some("/base/keystore.JKS"));
    }

    #[test]
    fn shortcut_letters_are_typed_into_the_filter() {
        let mut picker = picker(&["jks/", "kq.pem", "q.pem"]);
        type_text(&mut picker, "q");
        assert_eq!(listed(&picker), ["/base/q.pem"]);
        assert!(picker.clear_filter());
        type_text(&mut picker, "kq");
        assert_eq!(listed(&picker), ["/base/kq.pem"]);
        assert!(picker.clear_filter());
        type_text(&mut picker, "j");
        assert_eq!(listed(&picker), ["/base/jks"]);
    }

    #[test]
    fn control_and_alt_characters_are_not_typed() {
        let mut picker = picker(&["a.pem"]);
        for modifiers in [KeyModifiers::CONTROL, KeyModifiers::ALT] {
            picker.handle_key(KeyEvent::new(KeyCode::Char('o'), modifiers));
            assert!(picker.filter.is_empty());
        }
        picker.handle_key(KeyEvent::new(KeyCode::Char('A'), KeyModifiers::SHIFT));
        assert_eq!(picker.filter, "A");
    }

    #[test]
    fn backspace_edits_the_filter_and_never_leaves_the_directory() {
        let mut picker = picker(&["ab.pem", "ac.pem", "b.pem"]);
        type_text(&mut picker, "ab");
        assert_eq!(listed(&picker), ["/base/ab.pem"]);
        press(&mut picker, KeyCode::Backspace);
        assert_eq!(listed(&picker), ["/base/ab.pem", "/base/ac.pem"]);
        press(&mut picker, KeyCode::Down);
        assert_eq!(selected(&picker).as_deref(), Some("/base/ac.pem"));
        press(&mut picker, KeyCode::Backspace);
        assert_eq!(listed(&picker).len(), 4);
        // The selected entry stays selected as the list widens.
        assert_eq!(selected(&picker).as_deref(), Some("/base/ac.pem"));
        press(&mut picker, KeyCode::Backspace);
        assert_eq!(picker.directory, PathBuf::from("/base"));
        assert_eq!(listed(&picker).len(), 4);
    }

    #[test]
    fn no_matches_clears_the_selection_and_enter_does_nothing() {
        let mut picker = picker(&["a.pem"]);
        type_text(&mut picker, "z");
        assert!(listed(&picker).is_empty());
        assert_eq!(picker.selection.selected(), None);
        for key in [KeyCode::Up, KeyCode::Down, KeyCode::Enter, KeyCode::Right] {
            assert_eq!(press(&mut picker, key), None);
        }
        assert_eq!(picker.directory, PathBuf::from("/base"));
        assert!(picker.error.is_none());
    }

    #[test]
    fn clear_filter_reports_whether_there_was_a_filter() {
        let mut picker = picker(&["a.pem", "b.pem"]);
        assert!(!picker.clear_filter());
        type_text(&mut picker, "b");
        assert!(picker.clear_filter());
        assert!(picker.filter.is_empty());
        assert_eq!(listed(&picker).len(), 3);
        assert_eq!(selected(&picker).as_deref(), Some("/base/b.pem"));
        type_text(&mut picker, "z");
        assert!(picker.clear_filter());
        // With nothing previously selected, the first entry after `../` is.
        assert_eq!(selected(&picker).as_deref(), Some("/base/a.pem"));
        assert!(!picker.clear_filter());
    }
}
