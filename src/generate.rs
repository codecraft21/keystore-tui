//! Generating a key pair with a self-signed certificate: the key
//! algorithms, the form asking what the certificate holds, and adding the
//! result to the open keystore.
use std::time::{SystemTime, UNIX_EPOCH};

use crown::{
    asn1::{
        der,
        oid::{self, ObjectIdentifier},
    },
    bn::Bn,
    ec::{self, CurveId},
    ecdh,
    error::{CryptoError, CryptoResult},
    rng::Rng,
    rsa::{RsaPrivateKey, der::rsa_private_key_der},
    x509::keys::encode_ec_private_key,
};
use ratatui::{
    Frame,
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers},
    layout::{Constraint, Layout},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Clear, Paragraph, Wrap},
};
use zeroize::Zeroizing;

use crate::{
    App,
    editing::{Action, AliasPrompt},
    key_import::Key,
    save::OsRng,
    signing::{self, Purpose, Subject},
};

/// The kind and size of a generated key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Rsa(usize),
    Ec(CurveId),
    Ed25519,
}

impl Algorithm {
    pub const ALL: [Self; 7] = [
        Self::Rsa(2048),
        Self::Rsa(3072),
        Self::Rsa(4096),
        Self::Ec(CurveId::P256),
        Self::Ec(CurveId::P384),
        Self::Ec(CurveId::P521),
        Self::Ed25519,
    ];

    pub fn label(self) -> String {
        match self {
            Self::Rsa(bits) => format!("RSA {bits}"),
            Self::Ec(CurveId::P256) => "EC P-256".into(),
            Self::Ec(CurveId::P384) => "EC P-384".into(),
            Self::Ec(CurveId::P521) => "EC P-521".into(),
            Self::Ed25519 => "Ed25519".into(),
        }
    }
}

const NOT_GENERATED: &str = "The key pair could not be generated.";

/// A new private key of this algorithm, as PKCS #8.
pub fn key_pair(algorithm: Algorithm, rng: &mut impl Rng) -> Result<Key, String> {
    match algorithm {
        Algorithm::Rsa(bits) => rsa(bits, rng),
        Algorithm::Ec(curve) => elliptic(curve, rng),
        Algorithm::Ed25519 => {
            let mut seed = Zeroizing::new([0; 32]);
            rng.fill_bytes(&mut *seed);
            let key = Zeroizing::new(der::octet_string(&*seed));
            Ok(pkcs8(&der::oid(&object(oid::OID_ED25519)), &key))
        }
    }
    .map_err(|_| NOT_GENERATED.into())
}

fn object(arcs: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::new(arcs).expect("a constant object identifier")
}

/// The PKCS #8 structure around a private key in its algorithm's own
/// encoding; `algorithm` is the content of the algorithm identifier.
fn pkcs8(algorithm: &[u8], key: &[u8]) -> Key {
    let key = Zeroizing::new(der::octet_string(key));
    let content =
        Zeroizing::new([&der::integer(&[0])[..], &der::sequence(algorithm), &key[..]].concat());
    Zeroizing::new(der::sequence(&content))
}

fn elliptic(curve: CurveId, rng: &mut impl Rng) -> CryptoResult<Key> {
    let arcs = match curve {
        CurveId::P256 => oid::OID_SECP256R1,
        CurveId::P384 => oid::OID_SECP384R1,
        CurveId::P521 => oid::OID_SECP521R1,
    };
    let (scalar, public) = ecdh::generate(curve, rng)?;
    let public = public.to_bytes_with(&ec::curve(curve));
    let key = Zeroizing::new(encode_ec_private_key(arcs, &scalar, Some(&public))?);
    let algorithm = [
        der::oid(&object(oid::OID_EC_PUBLIC_KEY)),
        der::oid(&object(arcs)),
    ]
    .concat();
    Ok(pkcs8(&algorithm, &key))
}

/// Passes random bytes on, keeping every request of one length: the
/// candidates the RSA primes are chosen from.
struct Recorder<'a, R> {
    rng: &'a mut R,
    length: usize,
    draws: Vec<Zeroizing<Vec<u8>>>,
}

impl<R: Rng> Rng for Recorder<'_, R> {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        self.rng.fill_bytes(out);
        if out.len() == self.length {
            self.draws.push(Zeroizing::new(out.to_vec()));
        }
    }
}

/// The prime among the recorded candidates that divides `modulus`.
/// The generator sets a candidate's two highest bits and its lowest one.
fn factor(modulus: &Bn, draws: &[Zeroizing<Vec<u8>>]) -> Option<Bn> {
    draws.iter().find_map(|draw| {
        let mut bytes = draw.clone();
        *bytes.first_mut()? |= 0xc0;
        *bytes.last_mut()? |= 1;
        let candidate = Bn::from_be_bytes(&bytes);
        let (_, rest) = modulus.divrem(&candidate).ok()?;
        rest.is_zero().then_some(candidate)
    })
}

/// An RSA key of `bits` bits with the public exponent 65537.
///
/// The library generates the key but does not give out its private parts,
/// so they are worked out again from the modulus and the prime found among
/// the random candidates the generator drew.
fn rsa(bits: usize, rng: &mut impl Rng) -> CryptoResult<Key> {
    const EXPONENT: u64 = 65537;
    let mut recorder = Recorder {
        rng,
        length: bits / 16,
        draws: Vec::new(),
    };
    let key = RsaPrivateKey::generate(bits, EXPONENT, &mut recorder)?;
    let modulus = Bn::from_be_bytes(&key.public().n());
    let found = factor(&modulus, &recorder.draws)
        .ok_or(CryptoError::StrError("the generated primes were not found"))?;
    let (other, _) = modulus.divrem(&found)?;
    let (p, q) = if found.lt(&other) {
        (other, found)
    } else {
        (found, other)
    };
    let one = Bn::one();
    let (p1, q1) = (p.sub(&one)?, q.sub(&one)?);
    let exponent = Bn::from_u64(EXPONENT);
    let d = exponent.mod_inverse(&p1.mul(&q1))?;
    let bytes = |number: &Bn| Zeroizing::new(number.to_be_bytes());
    let key = Zeroizing::new(rsa_private_key_der(
        &modulus.to_be_bytes(),
        &exponent.to_be_bytes(),
        &bytes(&d),
        &bytes(&p),
        &bytes(&q),
        &bytes(&d.modulus(&p1)),
        &bytes(&d.modulus(&q1)),
        &bytes(&q.mod_inverse(&p)?),
    ));
    let algorithm = [der::oid(&object(oid::OID_RSA_ENCRYPTION)), der::null()].concat();
    Ok(pkcs8(&algorithm, &key))
}

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

/// The form asking for a new key pair's algorithm and certificate fields.
pub struct Form {
    selected: usize,
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
            selected: ALGORITHM,
            algorithm: 3,
            purpose: 0,
            text,
            error: None,
        }
    }
}

/// A filled-in form whose key pair is not generated yet.
pub struct Pending {
    form: Form,
    algorithm: Algorithm,
    request: signing::Request,
}

pub enum Outcome {
    Editing,
    Cancelled,
    Submitted(Algorithm, signing::Request),
}

impl Form {
    pub fn handle_key(&mut self, key: KeyEvent) -> Outcome {
        self.error = None;
        match key.code {
            KeyCode::Esc => return Outcome::Cancelled,
            KeyCode::Enter => match self.request() {
                Ok(request) => {
                    return Outcome::Submitted(Algorithm::ALL[self.algorithm], request);
                }
                Err((field, error)) => {
                    self.selected = field;
                    self.error = Some(error);
                }
            },
            KeyCode::Up | KeyCode::BackTab => {
                self.selected = (self.selected + LABELS.len() - 1) % LABELS.len();
            }
            KeyCode::Down | KeyCode::Tab => self.selected = (self.selected + 1) % LABELS.len(),
            _ => self.edit(key),
        }
        Outcome::Editing
    }

    /// Changes the selected field: a choice with the arrows, a text by typing.
    fn edit(&mut self, key: KeyEvent) {
        let choice = match self.selected {
            ALGORITHM => Some((&mut self.algorithm, Algorithm::ALL.len())),
            PURPOSE => Some((&mut self.purpose, Purpose::ALL.len())),
            _ => None,
        };
        let text = &mut self.text[self.selected];
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
        if field(COMMON_NAME).is_empty() {
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
            subject: Subject {
                common_name: field(COMMON_NAME),
                organization: field(ORGANIZATION),
                unit: field(UNIT),
                locality: field(LOCALITY),
                state: field(STATE),
                country: &country,
            }
            .name(),
            days,
            names,
            purpose: Purpose::ALL[self.purpose],
        })
    }

    /// What the selected field is for.
    fn hint(&self) -> &'static str {
        match self.selected {
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
        let block = Block::bordered().title(" Generate key pair ");
        let inner = block.inner(area);
        frame.render_widget(Clear, area);
        frame.render_widget(block, area);
        let [fields, _, hint, error] = Layout::vertical([
            Constraint::Length(LABELS.len() as u16),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .areas(inner);
        let width = usize::from(inner.width);
        let rows = LABELS.iter().enumerate().map(|(index, label)| {
            let selected = index == self.selected;
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

impl Pending {
    /// The form to go back to.
    pub fn into_form(self) -> Form {
        self.form
    }
}

impl App {
    /// Opens the form for a new key pair.
    pub(crate) fn ask_generate(&mut self) {
        if self.editable() {
            self.generating = Some(Form::default());
        }
    }

    pub(crate) fn handle_generate(&mut self, key: KeyEvent) {
        let Some(form) = &mut self.generating else {
            return;
        };
        match form.handle_key(key) {
            Outcome::Editing => {}
            Outcome::Cancelled => self.generating = None,
            // The alias is asked first, so that no generated key is thrown away.
            Outcome::Submitted(algorithm, request) => {
                if let Some(form) = self.generating.take() {
                    self.alias_prompt = Some(AliasPrompt {
                        alias: form.text[COMMON_NAME].trim().to_lowercase(),
                        action: Action::Generate(Box::new(Pending {
                            form,
                            algorithm,
                            request,
                        })),
                    });
                }
            }
        }
    }

    /// What is shown while the key pair is generated.
    pub(crate) fn generation_notice(&self) -> Option<String> {
        let (_, pending) = self.generation.as_ref()?;
        Some(format!(
            "Generating {} key pair...",
            pending.algorithm.label()
        ))
    }

    /// Generates the key pair that is waiting, once the screen says so.
    /// Returns whether there was one.
    pub(crate) fn finish_generation(&mut self) -> bool {
        let Some((alias, pending)) = self.generation.take() else {
            return false;
        };
        let algorithm = pending.algorithm;
        let message = format!("Generated {} key pair '{alias}'.", algorithm.label());
        match self.generate(alias, algorithm, &pending.request) {
            Ok(to) => {
                self.modified = true;
                self.message = Some((message, false));
                self.select_changed(to);
            }
            Err(error) => self.message = Some((error, true)),
        }
        true
    }

    /// Adds a new key pair with its self-signed certificate under `alias`,
    /// and returns where it is listed.
    fn generate(
        &mut self,
        alias: String,
        algorithm: Algorithm,
        request: &signing::Request,
    ) -> Result<usize, String> {
        let document = self.document.as_mut().ok_or("No keystore is open.")?;
        // Without random numbers the search for primes would never end.
        OsRng::default().check()?;
        let mut rng = OsRng::default();
        let key = key_pair(algorithm, &mut rng)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs() as i64);
        let certificate = signing::self_signed(&key, request, now, &mut rng)?;
        rng.check()?;
        document.import_key_pair(&mut self.entries, alias, &key, &[certificate])
    }
}

#[cfg(test)]
mod tests {
    use crown::x509::cert::Certificate;
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;
    use crate::{key_import::matching_chain, test_support::TestRng};

    /// Deterministic bytes that vary enough for primes to be found.
    struct Mixed(u64);

    impl Rng for Mixed {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            for byte in out {
                self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut mixed = self.0;
                mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                *byte = (mixed >> 56) as u8;
            }
        }
    }

    fn request() -> signing::Request {
        signing::Request {
            subject: Subject {
                common_name: "generated",
                ..Subject::default()
            }
            .name(),
            days: 1,
            names: Vec::new(),
            purpose: Purpose::None,
        }
    }

    #[test]
    fn every_algorithm_gives_a_key_that_signs_its_own_certificate() {
        // A small RSA key keeps the test fast; the sizes offered work alike.
        let algorithms = [Algorithm::Rsa(1024)]
            .into_iter()
            .chain(Algorithm::ALL.into_iter().skip(3));
        for algorithm in algorithms {
            let mut rng = Mixed(7);
            let key = key_pair(algorithm, &mut rng).unwrap();
            let der = signing::self_signed(&key, &request(), 0, &mut rng).unwrap();
            let parsed = Certificate::parse(&der).unwrap();
            assert_eq!(
                parsed.verify_signature(parsed.public_key()),
                Ok(true),
                "{}",
                algorithm.label()
            );
            let chains = [vec![der]];
            assert_eq!(matching_chain(&key, &chains), Ok(Some(chains[0].clone())));
        }
    }

    #[test]
    fn keys_differ_and_have_the_size_asked_for() {
        let summary = |algorithm, seed| {
            let mut rng = Mixed(seed);
            let key = key_pair(algorithm, &mut rng).unwrap();
            let der = signing::self_signed(&key, &request(), 0, &mut rng).unwrap();
            (key, crate::certificate::summarize(&der).unwrap())
        };
        let (first, rsa) = summary(Algorithm::Rsa(1024), 1);
        assert_eq!((rsa.algorithm.as_str(), rsa.key_size), ("RSA", Some(1024)));
        assert_ne!(first, summary(Algorithm::Rsa(1024), 2).0);
        for (curve, bits) in [
            (CurveId::P256, 256),
            (CurveId::P384, 384),
            (CurveId::P521, 521),
        ] {
            let (_, ec) = summary(Algorithm::Ec(curve), 1);
            assert_eq!((ec.algorithm.as_str(), ec.key_size), ("EC", Some(bits)));
        }
        assert_ne!(
            key_pair(Algorithm::Ed25519, &mut TestRng(1)),
            key_pair(Algorithm::Ed25519, &mut TestRng(2))
        );
        assert_eq!(
            Algorithm::ALL.map(Algorithm::label),
            [
                "RSA 2048", "RSA 3072", "RSA 4096", "EC P-256", "EC P-384", "EC P-521", "Ed25519"
            ]
        );
    }

    #[test]
    fn a_key_that_cannot_be_generated_is_reported() {
        // The library refuses an RSA key this small.
        assert_eq!(
            key_pair(Algorithm::Rsa(128), &mut Mixed(1)),
            Err(NOT_GENERATED.into())
        );
        // Without the recorded candidates, the primes are not found.
        assert!(factor(&Bn::from_u64(15), &[]).is_none());
        assert!(factor(&Bn::from_u64(15), &[Zeroizing::new(Vec::new())]).is_none());
        let seven = [Zeroizing::new(vec![0x07])];
        assert!(factor(&Bn::from_u64(15), &seven).is_none());
    }

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
}
