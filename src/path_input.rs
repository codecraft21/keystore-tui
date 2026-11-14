//! A one-line text input for file and path names, edited at a cursor.

use std::{ffi::OsStr, ops::Deref, path::Path};

use ratatui::{
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers},
    style::Stylize,
    text::{Line, Span},
};

/// The typed text and the cursor, a byte offset always on a character
/// boundary, so editing never splits a UTF-8 character.
#[derive(Clone, Default)]
pub struct PathInput {
    text: String,
    cursor: usize,
}

impl PathInput {
    /// The text with the cursor after its last character.
    pub fn new(text: String) -> Self {
        let cursor = text.len();
        Self { text, cursor }
    }

    /// Edits the text for Left/Right, Home/End, Backspace, Delete, Ctrl+U,
    /// and typed characters; returns `false` for any other key.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Left => self.cursor = self.previous(),
            KeyCode::Right => self.cursor = self.next(),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.text.len(),
            KeyCode::Backspace => {
                let start = self.previous();
                self.text.replace_range(start..self.cursor, "");
                self.cursor = start;
            }
            KeyCode::Delete => {
                let end = self.next();
                self.text.replace_range(self.cursor..end, "");
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.text.clear();
                self.cursor = 0;
            }
            KeyCode::Char(ch) if crate::is_text_input(key.modifiers) => {
                self.text.insert(self.cursor, ch);
                self.cursor += ch.len_utf8();
            }
            _ => return false,
        }
        true
    }

    fn previous(&self) -> usize {
        self.text[..self.cursor]
            .char_indices()
            .next_back()
            .map_or(0, |(index, _)| index)
    }

    fn next(&self) -> usize {
        self.text[self.cursor..]
            .chars()
            .next()
            .map_or(self.cursor, |ch| self.cursor + ch.len_utf8())
    }

    /// The text in at most `width` columns, scrolled to keep the cursor in
    /// view, with the character under the cursor (a space at the end) shown
    /// reversed.
    pub fn spans(&self, width: usize) -> Vec<Span<'static>> {
        let width = width.max(1);
        let columns = |text: &str| Span::raw(text).width();
        let under = self.text[self.cursor..].chars().next();
        let cursor_width = under.map_or(1, |ch| columns(ch.encode_utf8(&mut [0; 4])).max(1));
        // Start as far left as possible while the cursor still fits.
        let mut start = self.cursor;
        let mut used = cursor_width;
        for (index, ch) in self.text[..self.cursor].char_indices().rev() {
            let w = columns(ch.encode_utf8(&mut [0; 4]));
            if used + w > width {
                break;
            }
            used += w;
            start = index;
        }
        // Then fill the rest of the line after the cursor.
        let after_start = self.cursor + under.map_or(0, char::len_utf8);
        let mut end = after_start;
        for ch in self.text[after_start..].chars() {
            let w = columns(ch.encode_utf8(&mut [0; 4]));
            if used + w > width {
                break;
            }
            used += w;
            end += ch.len_utf8();
        }
        let under = under.map_or_else(|| " ".to_owned(), String::from);
        vec![
            Span::raw(self.text[start..self.cursor].to_owned()),
            Span::raw(under).reversed(),
            Span::raw(self.text[after_start..end].to_owned()),
        ]
    }
}

/// `label` followed by `input`, scrolled to fit in `width` columns.
pub fn line(label: Span<'static>, input: &PathInput, width: u16) -> Line<'static> {
    let rest = usize::from(width).saturating_sub(label.width());
    let mut spans = vec![label];
    spans.extend(input.spans(rest));
    Line::from(spans)
}

impl Deref for PathInput {
    type Target = str;

    fn deref(&self) -> &str {
        &self.text
    }
}

impl AsRef<Path> for PathInput {
    fn as_ref(&self) -> &Path {
        Path::new(&self.text)
    }
}

impl AsRef<OsStr> for PathInput {
    fn as_ref(&self) -> &OsStr {
        OsStr::new(&self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(input: &mut PathInput, code: KeyCode) {
        assert!(input.handle_key(KeyEvent::new(code, KeyModifiers::NONE)));
    }

    fn type_text(input: &mut PathInput, text: &str) {
        text.chars().for_each(|ch| press(input, KeyCode::Char(ch)));
    }

    fn shown(input: &PathInput, width: usize) -> (String, String, String) {
        let spans = input.spans(width);
        (
            spans[0].content.to_string(),
            spans[1].content.to_string(),
            spans[2].content.to_string(),
        )
    }

    #[test]
    fn edits_a_middle_component_and_keeps_the_suffix() {
        let mut input = PathInput::new("/home/chris/project/file.jks".into());
        for _ in 0.."/file.jks".len() {
            press(&mut input, KeyCode::Left);
        }
        for _ in 0.."project".len() {
            press(&mut input, KeyCode::Backspace);
        }
        type_text(&mut input, "work");
        assert_eq!(&*input, "/home/chris/work/file.jks");
    }

    #[test]
    fn edits_the_beginning_and_end() {
        let mut input = PathInput::new("b.jks".into());
        press(&mut input, KeyCode::Home);
        press(&mut input, KeyCode::Delete);
        type_text(&mut input, "a");
        press(&mut input, KeyCode::End);
        press(&mut input, KeyCode::Backspace);
        type_text(&mut input, "x");
        assert_eq!(&*input, "a.jkx");
    }

    #[test]
    fn boundaries_and_empty_input_are_no_ops() {
        let mut input = PathInput::default();
        for code in [
            KeyCode::Left,
            KeyCode::Right,
            KeyCode::Home,
            KeyCode::End,
            KeyCode::Backspace,
            KeyCode::Delete,
        ] {
            press(&mut input, code);
        }
        assert_eq!(&*input, "");
        type_text(&mut input, "ab");
        press(&mut input, KeyCode::Right);
        press(&mut input, KeyCode::Delete);
        press(&mut input, KeyCode::Home);
        press(&mut input, KeyCode::Left);
        press(&mut input, KeyCode::Backspace);
        assert_eq!(&*input, "ab");
        assert!(input.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL)));
        assert_eq!(&*input, "");
        assert!(!input.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
    }

    #[test]
    fn edits_unicode_without_splitting_characters() {
        let mut input = PathInput::new("/tmp/clé-日本.p12".into());
        for _ in 0..".p12".len() {
            press(&mut input, KeyCode::Left);
        }
        press(&mut input, KeyCode::Backspace);
        press(&mut input, KeyCode::Left);
        press(&mut input, KeyCode::Left);
        press(&mut input, KeyCode::Backspace);
        type_text(&mut input, "ф");
        assert_eq!(&*input, "/tmp/clф-日.p12");
        assert_eq!(
            shown(&input, 40),
            ("/tmp/clф".into(), "-".into(), "日.p12".into())
        );
    }

    #[test]
    fn line_fits_the_label_and_input_in_the_width() {
        let input = PathInput::new("abcdefghij".into());
        let line = line(Span::raw("To: "), &input, 8);
        assert_eq!(line.width(), 8);
        assert_eq!(line.to_string(), "To: hij ");
    }

    #[test]
    fn long_input_scrolls_to_keep_the_cursor_visible() {
        let mut input = PathInput::new("abcdefghij".into());
        assert_eq!(shown(&input, 4), ("hij".into(), " ".into(), String::new()));
        press(&mut input, KeyCode::Home);
        assert_eq!(shown(&input, 4), (String::new(), "a".into(), "bcd".into()));
        press(&mut input, KeyCode::Right);
        press(&mut input, KeyCode::Right);
        assert_eq!(shown(&input, 4), ("ab".into(), "c".into(), "d".into()));
        // Wide characters take two columns each.
        let input = PathInput::new("日本語".into());
        assert_eq!(shown(&input, 5), ("本語".into(), " ".into(), String::new()));
    }
}
