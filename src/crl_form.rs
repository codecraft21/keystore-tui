//! The form asking what a certificate revocation list holds: the revoked
//! serial numbers with their reasons, the two update times, and the list's
//! number.
use crown::{asn1::Asn1Time, x509::extensions::CrlReason};
use ratatui::{
    Frame,
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers},
    layout::{Constraint, Layout},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Clear, Paragraph, Wrap},
};

use crate::{
    sign_form,
    signing::{Revocations, Revoked},
};

const REVOKED: usize = 0;
const THIS_UPDATE: usize = 1;
const NEXT_UPDATE: usize = 2;
const NUMBER: usize = 3;

const LABELS: [&str; 4] = [
    "Revoked serials",
    "This update (UTC)",
    "Next update (UTC)",
    "CRL number",
];

/// The form's size, with its border.
const WIDTH: u16 = 72;
const HEIGHT: u16 = 12;
/// Where the values start in a row.
const VALUE_COLUMN: usize = 22;

/// How long a list is current, unless the form says otherwise.
const DAYS: i64 = 30;

/// A form asking what a revocation list holds.
pub struct CrlForm {
    title: String,
    selected: usize,
    text: [String; 4],
    error: Option<String>,
}

pub enum Outcome {
    Editing,
    Cancelled,
    Submitted(Revocations),
}

/// A time as the form shows and reads it, such as `2026-11-13 15:40:00`.
fn time_text(time: Asn1Time) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        time.year, time.month, time.day, time.hour, time.minute, time.second
    )
}

/// The time typed as `YYYY-MM-DD`, with `HH:MM` or `HH:MM:SS` after it if
/// not midnight, and `UTC` after that or not.
fn time(text: &str) -> Option<Asn1Time> {
    let text = text.trim();
    let text = text.strip_suffix("UTC").unwrap_or(text).trim();
    let (date, clock) = text.split_once(' ').unwrap_or((text, "00:00:00"));
    let numbers = |text: &str, separator: char| {
        text.split(separator)
            .map(|part| {
                // No signs or spaces: digits only.
                part.bytes()
                    .all(|byte| byte.is_ascii_digit())
                    .then(|| part.parse::<u16>().ok())
                    .flatten()
            })
            .collect::<Option<Vec<u16>>>()
    };
    let (date, clock) = (numbers(date, '-')?, numbers(clock.trim(), ':')?);
    let (&[year, month, day], &[hour, minute, ref second @ ..]) = (&date[..], &clock[..]) else {
        return None;
    };
    let second = match second {
        [] => 0,
        &[second] => second,
        _ => return None,
    };
    let byte = |number: u16| u8::try_from(number).ok();
    let time = Asn1Time::new(
        i32::from(year),
        byte(month)?,
        byte(day)?,
        byte(hour)?,
        byte(minute)?,
        byte(second)?,
        true,
    )
    .ok()
    .filter(|_| (1950..=9999).contains(&year))?;
    // A day its month does not have, such as February 30, changes when the
    // time is counted in seconds and back.
    (Asn1Time::from_unix(time.to_unix(), true) == time).then_some(time)
}

/// The reasons a list signed here gives, without the one that only a delta
/// list uses.
fn reasons() -> impl Iterator<Item = CrlReason> {
    (0..=10)
        .filter_map(|code| CrlReason::from_u8(code).ok())
        .filter(|reason| *reason != CrlReason::RemoveFromCrl)
}

/// The revoked serial numbers typed in hex and separated by commas, each
/// with `=` and a reason after it or not.
fn revoked(text: &str) -> Result<Vec<Revoked>, String> {
    let mut revoked: Vec<Revoked> = Vec::new();
    if text.trim().is_empty() {
        return Ok(revoked);
    }
    for entry in text.split(',') {
        let (number, reason) = match entry.split_once('=') {
            Some((number, reason)) => (number, Some(reason.trim())),
            None => (entry, None),
        };
        let number = number.trim();
        let serial = sign_form::serial(number).ok().flatten().ok_or_else(|| {
            format!("'{number}' is not a serial number: 1 to 20 bytes in hex, such as 01:A4.")
        })?;
        let reason = match reason {
            None => None,
            Some(name) => Some(
                reasons()
                    .find(|reason| reason.name().eq_ignore_ascii_case(name))
                    .ok_or_else(|| {
                        let known: Vec<_> = reasons().map(CrlReason::name).collect();
                        format!("'{name}' is not a reason. Reasons: {}.", known.join(", "))
                    })?,
            ),
        };
        if revoked.iter().any(|(listed, _)| *listed == serial) {
            return Err(format!("The serial number '{number}' is listed twice."));
        }
        revoked.push((serial, reason));
    }
    Ok(revoked)
}

impl CrlForm {
    /// The form titled `title`, for a list updated at `now`, in seconds
    /// since the Unix epoch, and current for 30 days.
    pub fn new(title: String, now: i64) -> Self {
        let shown = |seconds: i64| time_text(Asn1Time::from_unix(seconds, true));
        Self {
            title,
            selected: 0,
            text: [
                String::new(),
                shown(now),
                shown(now + DAYS * 86_400),
                "1".into(),
            ],
            error: None,
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Outcome {
        self.error = None;
        let rows = LABELS.len();
        let text = &mut self.text[self.selected];
        match key.code {
            KeyCode::Esc => return Outcome::Cancelled,
            KeyCode::Enter => match self.revocations() {
                Ok(revocations) => return Outcome::Submitted(revocations),
                Err((field, error)) => {
                    self.selected = field;
                    self.error = Some(error);
                }
            },
            KeyCode::Up | KeyCode::BackTab => self.selected = (self.selected + rows - 1) % rows,
            KeyCode::Down | KeyCode::Tab => self.selected = (self.selected + 1) % rows,
            KeyCode::Backspace => {
                text.pop();
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => text.clear(),
            KeyCode::Char(ch) if crate::is_text_input(key.modifiers) => text.push(ch),
            _ => {}
        }
        Outcome::Editing
    }

    /// What the form asks for, or the first field that is wrong and why.
    fn revocations(&self) -> Result<Revocations, (usize, String)> {
        const TIME: &str = "A time is written as 2026-11-13 15:40:00, or as a date alone.";
        let revoked = revoked(&self.text[REVOKED]).map_err(|error| (REVOKED, error))?;
        let this_update = time(&self.text[THIS_UPDATE]).ok_or((THIS_UPDATE, TIME.into()))?;
        let next_update = time(&self.text[NEXT_UPDATE]).ok_or((NEXT_UPDATE, TIME.into()))?;
        if next_update.to_unix() <= this_update.to_unix() {
            return Err((
                NEXT_UPDATE,
                "The next update comes after this update.".into(),
            ));
        }
        let number = self.text[NUMBER].trim().parse().map_err(|_| {
            (
                NUMBER,
                "The CRL number is a whole number, counted up with each list.".into(),
            )
        })?;
        Ok(Revocations {
            this_update,
            next_update,
            number,
            revoked,
        })
    }

    /// What the selected field is for.
    fn hint(&self) -> &'static str {
        match self.selected {
            REVOKED => "Optional: hex serials, separated by commas; 01A4=keyCompromise.",
            THIS_UPDATE => "When the list is issued; each serial is revoked at this time.",
            NEXT_UPDATE => "When the next list is due at the latest.",
            _ => "Higher than the number of the list before this one.",
        }
    }

    /// Draws the form over the middle of the main view.
    pub fn draw(&self, frame: &mut Frame) {
        let screen = frame.area();
        if screen.width < WIDTH || screen.height < HEIGHT {
            frame.render_widget(Clear, screen);
            frame.render_widget(
                Paragraph::new(
                    "Resize terminal for the revocation list form. Esc Cancel | Ctrl+C Quit",
                )
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
            Constraint::Length(LABELS.len() as u16),
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(4),
        ])
        .areas(inner);
        let width = usize::from(inner.width);
        let rows = LABELS.iter().enumerate().map(|(index, label)| {
            let selected = index == self.selected;
            // Show the end of a text too long for the row.
            let cursor = if selected { "_" } else { "" };
            let room = width - VALUE_COLUMN - cursor.len();
            let skipped = self.text[index].chars().count().saturating_sub(room);
            let shown: String = self.text[index].chars().skip(skipped).collect();
            let row = format!(" {label:<20} {shown}{cursor}");
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
            Paragraph::new(self.error.clone().unwrap_or_default())
                .style(Style::default().fg(Color::Red))
                .wrap(Wrap { trim: false }),
            error,
        );
    }
}

#[cfg(test)]
mod tests {
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;

    /// 2026-01-01 00:00:00 UTC.
    const NOW: i64 = 1_767_225_600;

    fn press(form: &mut CrlForm, code: KeyCode) -> Outcome {
        form.handle_key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn type_text(form: &mut CrlForm, text: &str) {
        for ch in text.chars() {
            press(form, KeyCode::Char(ch));
        }
    }

    fn clear(form: &mut CrlForm) {
        form.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    }

    fn screen(form: &CrlForm, width: u16, height: u16) -> String {
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

    fn form() -> CrlForm {
        CrlForm::new(" Revocation list signed by 'ca' ".into(), NOW)
    }

    #[test]
    fn the_form_starts_from_now_and_moves_between_its_fields() {
        let mut form = form();
        let shown = screen(&form, 80, 24);
        for expected in [
            " Revocation list signed by 'ca' ",
            "Revoked serials      _",
            "This update (UTC)    2026-01-01 00:00:00",
            "Next update (UTC)    2026-01-31 00:00:00",
            "CRL number           1",
            "Optional: hex serials, separated by commas; 01A4=keyCompromise.",
        ] {
            assert!(shown.contains(expected), "missing {expected:?} in\n{shown}");
        }
        press(&mut form, KeyCode::Up);
        assert!(screen(&form, 80, 24).contains("Higher than the number of the list before"));
        press(&mut form, KeyCode::Tab);
        press(&mut form, KeyCode::Down);
        assert!(screen(&form, 80, 24).contains("When the list is issued"));
        press(&mut form, KeyCode::Down);
        assert!(screen(&form, 80, 24).contains("When the next list is due at the latest."));
        press(&mut form, KeyCode::BackTab);
        assert_eq!(form.selected, THIS_UPDATE);
        // Keys that are not text do nothing.
        press(&mut form, KeyCode::Left);
        assert_eq!(form.text[THIS_UPDATE], "2026-01-01 00:00:00");

        // A small terminal shows a hint instead.
        assert!(screen(&form, 60, 24).contains("Resize terminal for the revocation list form."));
        assert!(screen(&form, 80, 10).contains("Resize terminal for the revocation list form."));
        assert!(matches!(press(&mut form, KeyCode::Esc), Outcome::Cancelled));
    }

    #[test]
    fn a_filled_in_form_gives_the_list() {
        let mut form = form();
        // Typing, including q, with Backspace; a long text shows its end.
        type_text(&mut form, "01a4=KeyCompromise, 0F ,7f=superseded,q");
        press(&mut form, KeyCode::Backspace);
        press(&mut form, KeyCode::Backspace);
        type_text(&mut form, &", 05".repeat(12));
        assert!(screen(&form, 80, 24).contains(", 05, 05_"));
        for _ in 0..48 {
            press(&mut form, KeyCode::Backspace);
        }
        press(&mut form, KeyCode::Down);
        clear(&mut form);
        type_text(&mut form, "2026-02-01");
        press(&mut form, KeyCode::Down);
        clear(&mut form);
        type_text(&mut form, "2026-03-01 12:30 UTC");
        press(&mut form, KeyCode::Down);
        type_text(&mut form, "7");
        let Outcome::Submitted(list) = press(&mut form, KeyCode::Enter) else {
            panic!("the form is complete: {:?}", form.error);
        };
        assert_eq!(
            list.revoked,
            [
                (vec![1, 0xa4], Some(CrlReason::KeyCompromise)),
                (vec![0x0f], None),
                (vec![0x7f], Some(CrlReason::Superseded)),
            ]
        );
        assert_eq!(time_text(list.this_update), "2026-02-01 00:00:00");
        assert_eq!(time_text(list.next_update), "2026-03-01 12:30:00");
        assert_eq!(list.number, 17);

        // An empty list is a list too.
        let Outcome::Submitted(list) = press(&mut super::tests::form(), KeyCode::Enter) else {
            panic!("the form is complete");
        };
        assert!(list.revoked.is_empty());
        assert_eq!(list.number, 1);
    }

    #[test]
    fn wrong_fields_are_selected_and_explained() {
        let wrong = |field: usize, text: &str| {
            let mut form = form();
            form.selected = field;
            clear(&mut form);
            type_text(&mut form, text);
            form.selected = (field + 1) % 4;
            assert!(matches!(press(&mut form, KeyCode::Enter), Outcome::Editing));
            assert_eq!(form.selected, field, "{text}");
            let shown = screen(&form, 80, 24);
            // The message clears on the next key.
            press(&mut form, KeyCode::Left);
            assert!(form.error.is_none());
            shown
        };
        assert!(wrong(REVOKED, "xyz").contains("'xyz' is not a serial number"));
        assert!(wrong(REVOKED, "01,").contains("'' is not a serial number"));
        assert!(wrong(REVOKED, "01, 0001=superseded").contains("'0001' is listed twice."));
        let shown = wrong(REVOKED, "01=stolen");
        assert!(shown.contains("'stolen' is not a reason. Reasons: unspecified, keyCompromise,"));
        assert!(shown.contains("aACompromise.") && !shown.contains("removeFromCRL"));
        for time in [
            "",
            "soon",
            "2026-02-30",
            "2026-13-01",
            "2026-01-01 25:00",
            "2026-01-01 10",
            "2026-01-01 10:00:00:00",
            "1949-01-01",
            "+2026-01-01",
            "2026-01-01 10:300",
        ] {
            assert!(wrong(THIS_UPDATE, time).contains("A time is written as"));
        }
        assert!(wrong(NEXT_UPDATE, "tomorrow").contains("A time is written as"));
        assert!(
            wrong(NEXT_UPDATE, "2026-01-01").contains("The next update comes after this update.")
        );
        assert!(wrong(NUMBER, "-1").contains("The CRL number is a whole number"));
    }
}
