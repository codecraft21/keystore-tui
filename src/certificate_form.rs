//! The form asking what a certificate holds: the fields of a new key
//! pair's certificate, or of a certificate request for an existing key.
use std::net::IpAddr;

use crown::{
    asn1::oid,
    x509::{extensions::GeneralName, name::Name},
};
use ratatui::{
    Frame,
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers},
    layout::{Constraint, Layout},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Clear, Paragraph, Wrap},
};

use crate::{
    generate::Algorithm,
    signing::{self, Purpose, Subject},
};

const ALGORITHM: usize = 0;
const COMMON_NAME: usize = 1;
const ORGANIZATION: usize = 2;
const UNIT: usize = 3;
const LOCALITY: usize = 4;
const STATE: usize = 5;
const COUNTRY: usize = 6;
const DAYS: usize = 7;
const NAMES: usize = 8;
const PURPOSE: usize = 9;

const LABELS: [&str; 10] = [
    "Algorithm",
    "Common name (CN)",
    "Organization (O)",
    "Org. unit (OU)",
    "Locality (L)",
    "State (ST)",
    "Country (C)",
    "Valid for (days)",
    "Alternative names",
    "Purpose",
];

/// The form's size, with its border.
const WIDTH: u16 = 72;
const HEIGHT: u16 = 16;
/// Where the values start in a row.
const VALUE_COLUMN: usize = 22;

/// The fields of the form for a new key pair, and of the one for a
/// certificate request, which has no algorithm and no validity.
const KEY_PAIR_FIELDS: &[usize] = &[
    ALGORITHM,
    COMMON_NAME,
    ORGANIZATION,
    UNIT,
    LOCALITY,
    STATE,
    COUNTRY,
    DAYS,
    NAMES,
    PURPOSE,
];
const REQUEST_FIELDS: &[usize] = &[
    COMMON_NAME,
    ORGANIZATION,
    UNIT,
    LOCALITY,
    STATE,
    COUNTRY,
    NAMES,
    PURPOSE,
];
/// The subject name's fields, with the attribute each one holds.
const SUBJECT_FIELDS: [(usize, &[u64]); 6] = [
    (COMMON_NAME, oid::OID_AT_COMMON_NAME),
    (ORGANIZATION, oid::OID_AT_ORGANIZATION),
    (UNIT, oid::OID_AT_ORGANIZATIONAL_UNIT),
    (LOCALITY, oid::OID_AT_LOCALITY),
    (STATE, oid::OID_AT_STATE),
    (COUNTRY, oid::OID_AT_COUNTRY),
];

/// A form asking what a certificate or a certificate request holds.
pub struct Form {
    title: String,
    fields: &'static [usize],
    /// The position of the selected field in `fields`.
    selected: usize,
    /// The subject the form started from, used as it is while its fields
    /// are left as they were.
    kept: Option<(Name, [String; 6])>,
    /// An index into `Algorithm::ALL`.
    algorithm: usize,
    /// An index into `Purpose::ALL`.
    purpose: usize,
    /// What was typed, by field; the two choices have no text.
    text: [String; 10],
    error: Option<String>,
}

impl Default for Form {
    fn default() -> Self {
        let mut text: [String; 10] = Default::default();
        text[DAYS] = "365".into();
        Self {
            title: " Generate key pair ".into(),
            fields: KEY_PAIR_FIELDS,
            selected: 0,
            kept: None,
            algorithm: 3,
            purpose: 0,
            text,
            error: None,
        }
    }
}

pub enum Outcome {
    Editing,
    Cancelled,
    Submitted(Algorithm, signing::Request),
}

impl Form {
    /// The form for a request named `title`, starting from the `subject`
    /// and the alternative `names` of the key's certificate.
    pub fn for_request(title: String, subject: &Name, names: &[GeneralName]) -> Self {
        let mut form = Self {
            title,
            fields: REQUEST_FIELDS,
            ..Self::default()
        };
        for (field, arcs) in SUBJECT_FIELDS {
            form.text[field] = subject
                .get(arcs)
                .and_then(|attribute| attribute.text().ok())
                .unwrap_or_default();
        }
        form.text[NAMES] = names
            .iter()
            .filter_map(|name| match name {
                GeneralName::DnsName(name) | GeneralName::Rfc822Name(name) => Some(name.clone()),
                GeneralName::IpAddress(bytes) => <[u8; 4]>::try_from(&bytes[..])
                    .map(IpAddr::from)
                    .or_else(|_| <[u8; 16]>::try_from(&bytes[..]).map(IpAddr::from))
                    .ok()
                    .map(|address| address.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(", ");
        form.kept = Some((subject.clone(), form.subject_text()));
        form
    }

    /// The subject name's fields as typed, without the spaces around them.
    fn subject_text(&self) -> [String; 6] {
        SUBJECT_FIELDS.map(|(field, _)| self.text[field].trim().to_owned())
    }

    /// The common name as typed.
    pub fn common_name(&self) -> &str {
        self.text[COMMON_NAME].trim()
    }

    /// The field that is selected.
    fn field(&self) -> usize {
        self.fields[self.selected]
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Outcome {
        self.error = None;
        match key.code {
            KeyCode::Esc => return Outcome::Cancelled,
            KeyCode::Enter => match self.request() {
                Ok(request) => {
                    return Outcome::Submitted(Algorithm::ALL[self.algorithm], request);
                }
                Err((field, error)) => {
                    self.selected = self
                        .fields
                        .iter()
                        .position(|&listed| listed == field)
                        .unwrap_or(0);
                    self.error = Some(error);
                }
            },
            KeyCode::Up | KeyCode::BackTab => {
                self.selected = (self.selected + self.fields.len() - 1) % self.fields.len();
            }
            KeyCode::Down | KeyCode::Tab => self.selected = (self.selected + 1) % self.fields.len(),
            _ => self.edit(key),
        }
        Outcome::Editing
    }

    /// Changes the selected field: a choice with the arrows, a text by typing.
    fn edit(&mut self, key: KeyEvent) {
        let field = self.field();
        let choice = match field {
            ALGORITHM => Some((&mut self.algorithm, Algorithm::ALL.len())),
            PURPOSE => Some((&mut self.purpose, Purpose::ALL.len())),
            _ => None,
        };
        let text = &mut self.text[field];
        match (key.code, choice) {
            (KeyCode::Left, Some((value, count))) => *value = (*value + count - 1) % count,
            (KeyCode::Right, Some((value, count))) => *value = (*value + 1) % count,
            (KeyCode::Backspace, None) => {
                text.pop();
            }
            (KeyCode::Char('u'), None) if key.modifiers.contains(KeyModifiers::CONTROL) => {
                text.clear();
            }
            (KeyCode::Char(ch), None) if crate::is_text_input(key.modifiers) => text.push(ch),
            _ => {}
        }
    }

    /// What the form asks for, or the first field that is wrong and why.
    fn request(&self) -> Result<signing::Request, (usize, String)> {
        let field = |index: usize| self.text[index].trim();
        // A subject left as it was is kept, whatever it holds.
        let kept = self
            .kept
            .as_ref()
            .filter(|(_, text)| *text == self.subject_text())
            .map(|(name, _)| name.clone());
        if kept.is_none() && field(COMMON_NAME).is_empty() {
            return Err((COMMON_NAME, "A common name is required.".into()));
        }
        let country = field(COUNTRY).to_ascii_uppercase();
        if !country.is_empty()
            && (country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_uppercase()))
        {
            return Err((
                COUNTRY,
                "The country is a two-letter code, such as CH.".into(),
            ));
        }
        let days = field(DAYS)
            .parse()
            .ok()
            .filter(|days| (1..=36500).contains(days))
            .ok_or((
                DAYS,
                "The validity is a number of days from 1 to 36500.".into(),
            ))?;
        let names = signing::alternative_names(field(NAMES)).map_err(|error| (NAMES, error))?;
        Ok(signing::Request {
            subject: kept.unwrap_or_else(|| {
                Subject {
                    common_name: field(COMMON_NAME),
                    organization: field(ORGANIZATION),
                    unit: field(UNIT),
                    locality: field(LOCALITY),
                    state: field(STATE),
                    country: &country,
                }
                .name()
            }),
            days,
            names,
            purpose: Purpose::ALL[self.purpose],
        })
    }

    /// What the selected field is for.
    fn hint(&self) -> &'static str {
        match self.field() {
            ALGORITHM => "The key's algorithm and size. RSA 4096 takes a few seconds.",
            COMMON_NAME => "Required: who the certificate is for, such as a host name.",
            COUNTRY => "Optional: a two-letter country code, such as CH.",
            DAYS => "How many days the certificate is valid, from now.",
            NAMES => "Optional, separated by commas: DNS names, IP addresses, or emails.",
            PURPOSE => Purpose::ALL[self.purpose].summary(),
            _ => "Optional.",
        }
    }

    /// Draws the form over the middle of the main view.
    pub fn draw(&self, frame: &mut Frame) {
        let screen = frame.area();
        if screen.width < WIDTH || screen.height < HEIGHT {
            frame.render_widget(Clear, screen);
            frame.render_widget(
                Paragraph::new("Resize terminal for the key pair form. Esc Cancel | Ctrl+C Quit")
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
        let [fields, _, hint, error] = Layout::vertical([
            Constraint::Length(self.fields.len() as u16),
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(2),
        ])
        .areas(inner);
        let width = usize::from(inner.width);
        let rows = self.fields.iter().enumerate().map(|(position, &index)| {
            let label = LABELS[index];
            let selected = position == self.selected;
            let value = match index {
                ALGORITHM => format!("< {} >", Algorithm::ALL[self.algorithm].label()),
                PURPOSE => format!("< {} >", Purpose::ALL[self.purpose].label()),
                // Show the end of a text too long for the row.
                _ => {
                    let cursor = if selected { "_" } else { "" };
                    let room = width - VALUE_COLUMN - cursor.len();
                    let skipped = self.text[index].chars().count().saturating_sub(room);
                    let shown: String = self.text[index].chars().skip(skipped).collect();
                    format!("{shown}{cursor}")
                }
            };
            let row = format!(" {label:<20} {value}");
            if selected {
                Line::styled(
                    format!("{row:<width$}"),
                    Style::default()
                        .fg(Color::Rgb(0, 0, 0))
                        .bg(Color::Rgb(175, 255, 255))
                        .bold(),
                )
            } else {
                Line::from(row)
            }
        });
        frame.render_widget(Paragraph::new(rows.collect::<Vec<_>>()), fields);
        frame.render_widget(Paragraph::new(format!(" {}", self.hint())), hint);
        frame.render_widget(
            Paragraph::new(format!(" {}", self.error.as_deref().unwrap_or_default()))
                .style(Style::default().fg(Color::Red))
                .wrap(Wrap { trim: false }),
            error,
        );
    }
}

#[cfg(test)]
mod tests {
    use crown::ec::CurveId;
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;

    fn press(form: &mut Form, code: KeyCode) -> Outcome {
        form.handle_key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn type_text(form: &mut Form, text: &str) {
        for ch in text.chars() {
            press(form, KeyCode::Char(ch));
        }
    }

    fn screen(form: &Form, width: u16, height: u16) -> String {
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

    #[test]
    fn the_form_moves_between_fields_and_changes_choices() {
        let mut form = Form::default();
        let shown = screen(&form, 80, 24);
        assert!(shown.contains(" Generate key pair "));
        assert!(shown.contains("Algorithm            < EC P-256 >"));
        assert!(shown.contains("Valid for (days)     365"));
        assert!(shown.contains("Purpose              < None >"));
        assert!(shown.contains("RSA 4096 takes a few seconds."));

        press(&mut form, KeyCode::Right);
        press(&mut form, KeyCode::Right);
        assert!(screen(&form, 80, 24).contains("< EC P-521 >"));
        for _ in 0..3 {
            press(&mut form, KeyCode::Left);
        }
        assert!(screen(&form, 80, 24).contains("< RSA 4096 >"));
        // Typing does nothing to a choice.
        type_text(&mut form, "x");
        press(&mut form, KeyCode::Backspace);
        assert!(screen(&form, 80, 24).contains("< RSA 4096 >"));

        // Up from the first field wraps to the last, and Down back.
        press(&mut form, KeyCode::Up);
        assert!(screen(&form, 80, 24).contains("No key usage extensions."));
        press(&mut form, KeyCode::Left);
        assert!(screen(&form, 80, 24).contains("< Code signing >"));
        press(&mut form, KeyCode::Tab);
        press(&mut form, KeyCode::Down);
        type_text(&mut form, "q host");
        assert!(screen(&form, 80, 24).contains("Common name (CN)     q host_"));
        press(&mut form, KeyCode::Backspace);
        assert!(screen(&form, 80, 24).contains("q hos_"));
        form.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        // Arrows and chords do nothing to a text.
        press(&mut form, KeyCode::Left);
        form.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::ALT));
        assert!(screen(&form, 80, 24).contains("Common name (CN)     _ "));
        press(&mut form, KeyCode::BackTab);
        assert!(screen(&form, 80, 24).contains("RSA 4096 takes"));
        assert!(matches!(press(&mut form, KeyCode::Esc), Outcome::Cancelled));
    }

    #[test]
    fn the_form_names_the_first_wrong_field() {
        let mut form = Form::default();
        let rejected = |form: &mut Form| {
            assert!(matches!(press(form, KeyCode::Enter), Outcome::Editing));
            (form.selected, form.error.clone().unwrap())
        };
        assert_eq!(
            rejected(&mut form),
            (COMMON_NAME, "A common name is required.".into())
        );
        assert!(screen(&form, 80, 24).contains("A common name is required."));
        type_text(&mut form, " Host ");
        // The error clears on the next key.
        assert!(!screen(&form, 80, 24).contains("A common name is required."));

        form.selected = COUNTRY;
        for country in ["c", "c1", "che"] {
            form.text[COUNTRY] = country.into();
            assert!(rejected(&mut form).1.contains("two-letter"));
        }
        form.text[COUNTRY] = "ch".into();
        for days in ["", "0", "36501", "soon"] {
            form.text[DAYS] = days.into();
            assert_eq!(rejected(&mut form).0, DAYS);
        }
        form.text[DAYS] = "90".into();
        form.text[NAMES] = "host.test,,".into();
        assert_eq!(rejected(&mut form).0, NAMES);
        form.text[NAMES] = "host.test, 10.0.0.1".into();
        form.text[ORGANIZATION] = "Example".into();
        form.purpose = 1;

        let Outcome::Submitted(algorithm, request) = press(&mut form, KeyCode::Enter) else {
            panic!("the form is complete");
        };
        assert_eq!(algorithm, Algorithm::Ec(CurveId::P256));
        let subject: Vec<_> = request
            .subject
            .iter_attributes()
            .map(|attribute| attribute.text().unwrap())
            .collect();
        assert_eq!(subject, ["CH", "Example", "Host"]);
        assert_eq!((request.days, request.names.len()), (90, 2));
        assert_eq!(request.purpose, Purpose::TlsServer);
    }

    #[test]
    fn the_form_shows_the_end_of_long_text_and_needs_room() {
        let mut form = Form {
            selected: NAMES,
            ..Form::default()
        };
        form.text[NAMES] = format!("{}.test", "a".repeat(60));
        let shown = screen(&form, 72, 16);
        assert!(shown.contains(&format!("Alternative names    {}.test_", "a".repeat(42))));
        assert!(shown.contains("Optional, separated by commas"));
        form.selected = DAYS;
        assert!(screen(&form, 72, 16).contains(&format!(" {}.test│", "a".repeat(43))));
        assert!(screen(&form, 72, 16).contains("How many days"));
        form.selected = COUNTRY;
        assert!(screen(&form, 72, 16).contains("such as CH"));
        form.selected = STATE;
        assert!(screen(&form, 72, 16).contains(" Optional. "));
        for (width, height) in [(71, 16), (72, 15)] {
            let small = screen(&form, width, height);
            assert!(small.contains("Resize terminal for the key pair form."));
            assert!(!small.contains("Generate key pair"));
        }
    }

    #[test]
    fn a_request_form_starts_from_the_certificate_and_keeps_its_subject() {
        use crown::asn1::oid::ObjectIdentifier;
        use crown::x509::name::{AttributeTypeAndValue, Rdn};

        // A subject with an attribute the form has no field for.
        let mut subject = Subject {
            common_name: "host.test",
            organization: "Example",
            country: "CH",
            ..Subject::default()
        }
        .name();
        subject.rdns.push(Rdn {
            attributes: vec![AttributeTypeAndValue::from_utf8(
                ObjectIdentifier::new(oid::OID_AT_EMAIL_ADDRESS).unwrap(),
                "admin@host.test",
            )],
        });
        let names = [
            GeneralName::DnsName("host.test".into()),
            GeneralName::IpAddress(vec![10, 0, 0, 5]),
            GeneralName::IpAddress([&[0; 15][..], &[1]].concat()),
            GeneralName::IpAddress(vec![1, 2, 3]),
            GeneralName::Uri("https://host.test".into()),
            GeneralName::Rfc822Name("admin@host.test".into()),
        ];
        let mut form =
            Form::for_request(" Certificate request for 'host' ".into(), &subject, &names);
        let shown = screen(&form, 80, 24);
        assert!(shown.contains(" Certificate request for 'host' "));
        assert!(shown.contains("Common name (CN)     host.test_"));
        assert!(shown.contains("Organization (O)     Example"));
        assert!(shown.contains("Country (C)          CH"));
        assert!(shown.contains("Alternative names    host.test, 10.0.0.5, ::1, admin@host.test"));
        assert!(!shown.contains("Algorithm") && !shown.contains("Valid for"));
        assert_eq!(form.common_name(), "host.test");

        // Left as it was, the subject is kept whole.
        let Outcome::Submitted(_, request) = press(&mut form, KeyCode::Enter) else {
            panic!("the form is complete");
        };
        assert_eq!(request.subject, subject);
        assert_eq!(request.names.len(), 4);

        // Once a field changes, the subject is made of the fields alone.
        type_text(&mut form, "x");
        let Outcome::Submitted(_, request) = press(&mut form, KeyCode::Enter) else {
            panic!("the form is complete");
        };
        let text: Vec<_> = request
            .subject
            .iter_attributes()
            .map(|attribute| attribute.text().unwrap())
            .collect();
        assert_eq!(text, ["CH", "Example", "host.testx"]);

        // Up from the first field wraps to the purpose, the last one.
        press(&mut form, KeyCode::Up);
        assert!(screen(&form, 80, 24).contains("No key usage extensions."));

        // A subject without a common name is kept too, but not once changed.
        let bare = Subject {
            organization: "Example",
            ..Subject::default()
        }
        .name();
        let mut form = Form::for_request(String::new(), &bare, &[]);
        assert!(matches!(
            press(&mut form, KeyCode::Enter),
            Outcome::Submitted(..)
        ));
        press(&mut form, KeyCode::Down);
        type_text(&mut form, "s");
        assert!(matches!(press(&mut form, KeyCode::Enter), Outcome::Editing));
        assert!(screen(&form, 80, 24).contains("A common name is required."));
        assert!(screen(&form, 80, 24).contains("Common name (CN)     _"));
    }
}
