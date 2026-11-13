//! The form asking how a certificate request is signed: the validity, the
//! serial number, what the file holds, and which of the requested
//! extensions the certificate gets.
use crown::{asn1::oid, x509::extensions::Extension as Signed};
use ratatui::{
    Frame,
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers},
    layout::{Constraint, Layout},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Clear, Paragraph, Wrap},
};

use crate::{
    certificate::extensions::{self, Extension},
    signing::Terms,
};

const DAYS: usize = 0;
const SERIAL: usize = 1;
const SAVE: usize = 2;
/// The rows before the requested extensions.
const FIELDS: usize = 3;

/// The form's size, with its border.
const WIDTH: u16 = 72;
const HEIGHT: u16 = 16;
/// How many rows are shown at once; more are scrolled.
const ROWS: usize = 7;
/// Where the values start in a row.
const VALUE_COLUMN: usize = 22;

/// A form asking how the request of `subject` is signed.
pub struct SignForm {
    title: String,
    subject: String,
    public_key: String,
    days: String,
    serial: String,
    /// Whether the file also holds the signer's chain.
    with_chain: bool,
    /// The requested extensions, and whether the certificate gets each.
    extensions: Vec<(Extension, bool)>,
    selected: usize,
    error: Option<String>,
}

pub enum Outcome {
    Editing,
    Cancelled,
    /// The terms, and whether the file also holds the signer's chain.
    Submitted(Terms, bool),
}

impl SignForm {
    /// The form titled `title` for a request with this subject, public key
    /// and requested extensions. The key identifiers are the issuer's to
    /// set, an extension is taken once, and one that cannot be read is
    /// never copied.
    pub fn new(title: String, subject: String, public_key: String, asked: &[Extension]) -> Self {
        let mut extensions: Vec<(Extension, bool)> = Vec::new();
        for extension in asked {
            let Some(id) = &extension.oid else {
                continue;
            };
            let set_by_issuer = id.matches(oid::OID_SUBJECT_KEY_IDENTIFIER)
                || id.matches(oid::OID_AUTHORITY_KEY_IDENTIFIER);
            let repeated = extensions
                .iter()
                .any(|(listed, _)| listed.oid == extension.oid);
            if !set_by_issuer && !repeated {
                // Making a certificate authority is not left to its request.
                let authority = id.matches(oid::OID_BASIC_CONSTRAINTS)
                    && crown::x509::extensions::BasicConstraints::parse(&extension.value)
                        .map_or(true, |constraints| constraints.ca);
                extensions.push((extension.clone(), !authority));
            }
        }
        Self {
            title,
            subject,
            public_key,
            days: "365".into(),
            serial: String::new(),
            with_chain: true,
            extensions,
            selected: 0,
            error: None,
        }
    }

    fn rows(&self) -> usize {
        FIELDS + self.extensions.len()
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Outcome {
        self.error = None;
        let rows = self.rows();
        match key.code {
            KeyCode::Esc => return Outcome::Cancelled,
            KeyCode::Enter => match self.terms() {
                Ok(terms) => return Outcome::Submitted(terms, self.with_chain),
                Err((field, error)) => {
                    self.selected = field;
                    self.error = Some(error);
                }
            },
            KeyCode::Up | KeyCode::BackTab => self.selected = (self.selected + rows - 1) % rows,
            KeyCode::Down | KeyCode::Tab => self.selected = (self.selected + 1) % rows,
            _ => self.edit(key),
        }
        Outcome::Editing
    }

    /// Changes the selected row: a text by typing, a choice with the arrows
    /// or the space bar.
    fn edit(&mut self, key: KeyEvent) {
        let text = match self.selected {
            DAYS => &mut self.days,
            SERIAL => &mut self.serial,
            row => {
                if matches!(
                    key.code,
                    KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')
                ) {
                    match row.checked_sub(FIELDS) {
                        Some(index) => self.extensions[index].1 ^= true,
                        None => self.with_chain ^= true,
                    }
                }
                return;
            }
        };
        match key.code {
            KeyCode::Backspace => {
                text.pop();
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => text.clear(),
            KeyCode::Char(ch) if crate::is_text_input(key.modifiers) => text.push(ch),
            _ => {}
        }
    }

    /// What the form asks for, or the first field that is wrong and why.
    fn terms(&self) -> Result<Terms, (usize, String)> {
        let days = self
            .days
            .trim()
            .parse()
            .ok()
            .filter(|days| (1..=36500).contains(days))
            .ok_or((
                DAYS,
                "The validity is a number of days from 1 to 36500.".into(),
            ))?;
        let serial = serial(&self.serial).map_err(|error| (SERIAL, error.into()))?;
        Ok(Terms {
            days,
            serial,
            extensions: self
                .extensions
                .iter()
                .filter(|(_, copied)| *copied)
                .filter_map(|(extension, _)| {
                    let id = extension.oid.clone()?;
                    Some(Signed::new(id, extension.critical, extension.value.clone()))
                })
                .collect(),
        })
    }

    /// What the selected row is for.
    fn hint(&self) -> &'static str {
        match self.selected {
            DAYS => "How many days the certificate is valid, from now.",
            SERIAL => "Optional, in hex, such as 01:A4. Empty: 16 random bytes.",
            SAVE => "What the new file holds. A DER file holds the certificate alone.",
            _ => "Space: copy this requested extension into the certificate, or not.",
        }
    }

    /// Draws the form over the middle of the main view.
    pub fn draw(&self, frame: &mut Frame) {
        let screen = frame.area();
        if screen.width < WIDTH || screen.height < HEIGHT {
            frame.render_widget(Clear, screen);
            frame.render_widget(
                Paragraph::new("Resize terminal for the signing form. Esc Cancel | Ctrl+C Quit")
                    .wrap(Wrap { trim: false }),
                screen,
            );
            return;
        }
        let area = screen.centered(Constraint::Length(WIDTH), Constraint::Length(HEIGHT));
        let block = Block::bordered().title(self.title.as_str());
        let inner = block.inner(area);
        frame.render_widget(Clear, area);
        frame.render_widget(block, area);
        let [request, _, fields, _, hint, error] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(ROWS as u16),
            Constraint::Min(0),
            Constraint::Length(1),
            Constraint::Length(2),
        ])
        .areas(inner);
        let width = usize::from(inner.width);
        let clipped = |text: String| text.chars().take(width).collect::<String>();
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(clipped(format!(" {:<20} {}", "Subject", self.subject))),
                Line::from(clipped(format!(
                    " {:<20} {}",
                    "Public key", self.public_key
                ))),
            ]),
            request,
        );
        let rows = (0..self.rows()).map(|row| {
            let selected = row == self.selected;
            let cursor = if selected { "_" } else { "" };
            let text = match row {
                DAYS => format!(" {:<20} {}{cursor}", "Valid for (days)", self.days),
                SERIAL => {
                    // Show the end of a serial number too long for the row.
                    let room = width - VALUE_COLUMN - cursor.len();
                    let skipped = self.serial.chars().count().saturating_sub(room);
                    let shown: String = self.serial.chars().skip(skipped).collect();
                    format!(" {:<20} {shown}{cursor}", "Serial number (hex)")
                }
                SAVE => format!(
                    " {:<20} < {} >",
                    "Save",
                    if self.with_chain {
                        "Certificate and the signer's chain"
                    } else {
                        "Certificate only"
                    }
                ),
                _ => {
                    let (extension, copied) = &self.extensions[row - FIELDS];
                    let name = extension
                        .oid
                        .as_ref()
                        .and_then(extensions::name)
                        .map_or_else(
                            || extension.title(),
                            |name| {
                                if extension.critical {
                                    format!("{name} [critical]")
                                } else {
                                    name.into()
                                }
                            },
                        );
                    let mark = if *copied { 'x' } else { ' ' };
                    format!(" [{mark}] {name}: {}", extension.lines.join(", "))
                }
            };
            let text = clipped(text);
            if selected {
                Line::styled(
                    format!("{text:<width$}"),
                    Style::default()
                        .fg(Color::Rgb(0, 0, 0))
                        .bg(Color::Rgb(175, 255, 255))
                        .bold(),
                )
            } else {
                Line::from(text)
            }
        });
        // Keep the selected row in view.
        let skipped = (self.selected + 1).saturating_sub(ROWS);
        frame.render_widget(
            Paragraph::new(rows.collect::<Vec<_>>()).scroll((skipped as u16, 0)),
            fields,
        );
        frame.render_widget(Paragraph::new(format!(" {}", self.hint())), hint);
        frame.render_widget(
            Paragraph::new(format!(" {}", self.error.as_deref().unwrap_or_default()))
                .style(Style::default().fg(Color::Red))
                .wrap(Wrap { trim: false }),
            error,
        );
    }
}

/// The bytes of the serial number typed in hex, with or without `0x` and
/// colons; `None` for an empty one. A serial number is positive and at most
/// 20 bytes long as encoded.
fn serial(text: &str) -> Result<Option<Vec<u8>>, &'static str> {
    const WRONG: &str = "The serial number is 1 to 20 bytes in hex, such as 01:A4, and not zero.";
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let text = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    let mut digits = Vec::new();
    for ch in text.chars().filter(|ch| *ch != ':') {
        digits.push(ch.to_digit(16).ok_or(WRONG)? as u8);
    }
    if digits.len() % 2 == 1 {
        digits.insert(0, 0);
    }
    let bytes: Vec<u8> = digits
        .chunks(2)
        .map(|pair| pair[0] << 4 | pair[1])
        .skip_while(|byte| *byte == 0)
        .collect();
    // A leading zero byte is added to a number whose first bit is set.
    let encoded = bytes.len() + usize::from(bytes.first().is_some_and(|byte| byte & 0x80 != 0));
    if bytes.is_empty() || encoded > 20 {
        return Err(WRONG);
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use crown::asn1::{der, oid::ObjectIdentifier};
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;

    fn press(form: &mut SignForm, code: KeyCode) -> Outcome {
        form.handle_key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn type_text(form: &mut SignForm, text: &str) {
        for ch in text.chars() {
            press(form, KeyCode::Char(ch));
        }
    }

    fn screen(form: &SignForm, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| form.draw(frame)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        buffer
            .content
            .chunks(usize::from(width))
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// An extension as a request holds it.
    fn extension(arcs: &[u64], critical: bool, value: &[u8]) -> Extension {
        let mut content = der::oid(&ObjectIdentifier::new(arcs).unwrap());
        if critical {
            content.extend(der::boolean(true));
        }
        content.extend(der::octet_string(value));
        Extension::parse(&der::sequence(&content))
    }

    fn asked() -> Vec<Extension> {
        let name = der::sequence(&der::tlv(der::Tag::context(2), b"a.test"));
        let authority = der::sequence(&der::boolean(true));
        vec![
            extension(
                oid::OID_SUBJECT_KEY_IDENTIFIER,
                false,
                &der::octet_string(&[1]),
            ),
            extension(oid::OID_SUBJECT_ALT_NAME, false, &name),
            extension(oid::OID_BASIC_CONSTRAINTS, true, &authority),
            extension(oid::OID_SUBJECT_ALT_NAME, false, &name),
            Extension::parse(b"junk"),
            extension(&[1, 2, 3, 4], false, &[5]),
        ]
    }

    fn form() -> SignForm {
        SignForm::new(
            " Sign request with 'ca' ".into(),
            "CN=a.test".into(),
            "EC 256 bits".into(),
            &asked(),
        )
    }

    #[test]
    fn the_form_lists_the_request_and_what_the_issuer_decides() {
        let mut form = form();
        let shown = screen(&form, 80, 24);
        for expected in [
            " Sign request with 'ca' ",
            "Subject              CN=a.test",
            "Public key           EC 256 bits",
            "Valid for (days)     365_",
            "Serial number (hex)  ",
            "Save                 < Certificate and the signer's chain >",
            "[x] Subject Alternative Name: DNS: a.test",
            "[ ] Basic Constraints [critical]: CA: true",
            "[x] 1.2.3.4: Value: 05",
            "How many days the certificate is valid, from now.",
        ] {
            assert!(shown.contains(expected), "missing {expected:?} in\n{shown}");
        }
        // The key identifiers, a repeated extension, and an unreadable one
        // are not offered.
        assert_eq!(form.extensions.len(), 3);
        assert!(!shown.contains("Key Identifier") && !shown.contains("Malformed"));

        // The rows wrap at either end, and each says what it is for.
        press(&mut form, KeyCode::Up);
        assert_eq!(form.selected, 5);
        assert!(screen(&form, 80, 24).contains("Space: copy this requested extension"));
        press(&mut form, KeyCode::Tab);
        assert_eq!(form.selected, DAYS);
        press(&mut form, KeyCode::Down);
        assert!(screen(&form, 80, 24).contains("Empty: 16 random bytes."));
        press(&mut form, KeyCode::Down);
        assert!(screen(&form, 80, 24).contains("A DER file holds the certificate alone."));
        press(&mut form, KeyCode::BackTab);
        assert_eq!(form.selected, SERIAL);

        // A small terminal shows a hint instead.
        assert!(screen(&form, 60, 24).contains("Resize terminal for the signing form."));
        assert!(screen(&form, 80, 10).contains("Resize terminal for the signing form."));
    }

    #[test]
    fn choices_toggle_and_texts_are_typed() {
        let mut form = form();
        // Typing, including q, with Backspace and Ctrl+U.
        type_text(&mut form, "q");
        assert_eq!(form.days, "365q");
        press(&mut form, KeyCode::Backspace);
        form.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert_eq!(form.days, "");
        press(&mut form, KeyCode::Left);
        assert_eq!(form.days, "");
        type_text(&mut form, "30");

        press(&mut form, KeyCode::Down);
        press(&mut form, KeyCode::Down);
        // Typing does nothing to a choice; the arrows and the space bar do.
        type_text(&mut form, "x");
        assert!(form.with_chain);
        press(&mut form, KeyCode::Right);
        assert!(!form.with_chain);
        assert!(screen(&form, 80, 24).contains("< Certificate only >"));
        press(&mut form, KeyCode::Char(' '));
        assert!(form.with_chain);
        press(&mut form, KeyCode::Left);

        press(&mut form, KeyCode::Down);
        press(&mut form, KeyCode::Char(' '));
        press(&mut form, KeyCode::Down);
        press(&mut form, KeyCode::Right);
        let shown = screen(&form, 80, 24);
        assert!(shown.contains("[ ] Subject Alternative Name"));
        assert!(shown.contains("[x] Basic Constraints [critical]"));

        let Outcome::Submitted(terms, with_chain) = press(&mut form, KeyCode::Enter) else {
            panic!("the form is complete");
        };
        assert!(!with_chain);
        assert_eq!((terms.days, &terms.serial), (30, &None));
        let copied: Vec<_> = terms
            .extensions
            .iter()
            .map(|extension| (extension.oid.to_dotted_string(), extension.critical))
            .collect();
        assert_eq!(
            copied,
            [("2.5.29.19".into(), true), ("1.2.3.4".into(), false)]
        );
        assert_eq!(terms.extensions[1].value, [5]);
        assert!(matches!(press(&mut form, KeyCode::Esc), Outcome::Cancelled));
    }

    #[test]
    fn wrong_fields_are_selected_and_explained() {
        let mut form = form();
        form.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        press(&mut form, KeyCode::Down);
        type_text(&mut form, "xyz");
        assert!(matches!(press(&mut form, KeyCode::Enter), Outcome::Editing));
        assert_eq!(form.selected, DAYS);
        assert!(
            screen(&form, 80, 24).contains("The validity is a number of days from 1 to 36500.")
        );
        // The message clears on the next key.
        type_text(&mut form, "7");
        assert!(form.error.is_none());
        assert!(matches!(press(&mut form, KeyCode::Enter), Outcome::Editing));
        assert_eq!(form.selected, SERIAL);
        assert!(screen(&form, 80, 24).contains("The serial number is 1 to 20 bytes in hex"));
        // A long serial number shows its end.
        form.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        type_text(&mut form, &format!("{}ab", "01:".repeat(20)));
        assert!(screen(&form, 80, 24).contains(":01:ab_"));
    }

    #[test]
    fn many_extensions_scroll_with_the_selection() {
        let asked: Vec<_> = (1..=9)
            .map(|number| extension(&[1, 2, 3, number], false, &[number as u8]))
            .collect();
        let mut form = SignForm::new(" Sign ".into(), "CN=a".into(), "RSA".into(), &asked);
        let shown = screen(&form, 80, 24);
        assert!(shown.contains("1.2.3.4") && !shown.contains("1.2.3.5"));
        press(&mut form, KeyCode::Up);
        let shown = screen(&form, 80, 24);
        assert!(shown.contains("[x] 1.2.3.9") && !shown.contains("Valid for (days)"));
    }

    #[test]
    fn serial_numbers_are_positive_hex_of_at_most_twenty_bytes() {
        assert_eq!(serial("  "), Ok(None));
        assert_eq!(serial("01:a4"), Ok(Some(vec![1, 0xa4])));
        assert_eq!(serial("0x1A4"), Ok(Some(vec![1, 0xa4])));
        assert_eq!(serial("0X00ff"), Ok(Some(vec![0xff])));
        assert_eq!(serial(&"7f".repeat(20)).unwrap().unwrap().len(), 20);
        for wrong in [
            "0",
            "00:00",
            "xyz",
            "-1",
            &"ff".repeat(20),
            &"01".repeat(21),
        ] {
            assert!(serial(wrong).is_err(), "{wrong}");
        }
    }
}
