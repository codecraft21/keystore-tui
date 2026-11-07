//! A read-only dump of a certificate's or request's DER structure for the
//! detail view, one line per element with its byte offset, much like
//! `openssl asn1parse`. Wrapped DER inside OCTET and BIT STRINGs, such as
//! extension values and public keys, is shown as nested elements.
//!
//! A request's challenge password is a secret shared with the CA, so its value
//! is never shown; neither are a request's undecodable bytes, which could hold
//! it.
use crown::asn1::{
    Reader,
    der::{self, Class, Tag},
    oid::ObjectIdentifier,
};

use crate::certificate::{
    details::{signature_name, time_text},
    extensions::{self, hex, printable},
};

const OID_CHALLENGE_PASSWORD: &[u64] = &[1, 2, 840, 113549, 1, 9, 7];
/// Deeper elements are summarized; real certificates nest about ten levels.
const MAX_DEPTH: usize = 48;
/// Keeps an oversized encoding from making every frame slow.
const MAX_LINES: usize = 20_000;
/// Values up to this many bytes are shown inline, longer ones in rows of it.
const HEX_ROW: usize = 16;

/// Names for common OIDs beyond the signature algorithms and decoded extensions.
const NAMES: &[(&[u64], &str)] = &[
    (&[2, 5, 4, 3], "commonName"),
    (&[2, 5, 4, 4], "surname"),
    (&[2, 5, 4, 5], "serialNumber"),
    (&[2, 5, 4, 6], "countryName"),
    (&[2, 5, 4, 7], "localityName"),
    (&[2, 5, 4, 8], "stateOrProvinceName"),
    (&[2, 5, 4, 9], "streetAddress"),
    (&[2, 5, 4, 10], "organizationName"),
    (&[2, 5, 4, 11], "organizationalUnitName"),
    (&[2, 5, 4, 12], "title"),
    (&[2, 5, 4, 42], "givenName"),
    (&[0, 9, 2342, 19200300, 100, 1, 1], "userId"),
    (&[0, 9, 2342, 19200300, 100, 1, 25], "domainComponent"),
    (&[1, 2, 840, 113549, 1, 1, 1], "RSA"),
    (&[1, 2, 840, 10045, 2, 1], "EC public key"),
    (&[1, 2, 840, 10040, 4, 1], "DSA"),
    (&[1, 3, 101, 110], "X25519"),
    (&[1, 3, 101, 111], "X448"),
    (&[1, 2, 840, 10045, 3, 1, 7], "P-256 (secp256r1)"),
    (&[1, 3, 132, 0, 34], "P-384 (secp384r1)"),
    (&[1, 3, 132, 0, 35], "P-521 (secp521r1)"),
    (&[1, 3, 132, 0, 33], "P-224 (secp224r1)"),
    (&[1, 3, 132, 0, 10], "secp256k1"),
    (&[1, 2, 840, 113549, 1, 1, 8], "MGF1"),
    (&[2, 16, 840, 1, 101, 3, 4, 2, 1], "SHA-256"),
    (&[2, 16, 840, 1, 101, 3, 4, 2, 2], "SHA-384"),
    (&[2, 16, 840, 1, 101, 3, 4, 2, 3], "SHA-512"),
    (&[1, 3, 14, 3, 2, 26], "SHA-1"),
    (&[1, 2, 840, 113549, 1, 9, 1], "emailAddress"),
    (&[1, 2, 840, 113549, 1, 9, 2], "unstructuredName"),
    (OID_CHALLENGE_PASSWORD, "challengePassword"),
    (&[1, 2, 840, 113549, 1, 9, 14], "extensionRequest"),
    (
        &[1, 3, 6, 1, 4, 1, 311, 2, 1, 14],
        "Microsoft extension request",
    ),
    (&[2, 5, 29, 20], "CRL Number"),
    (&[2, 5, 29, 30], "Name Constraints"),
    (&[2, 5, 29, 36], "Policy Constraints"),
    (&[2, 5, 29, 54], "Inhibit Any Policy"),
    (&[2, 5, 29, 32, 0], "anyPolicy"),
    (&[2, 5, 29, 37, 0], "anyExtendedKeyUsage"),
    (&[1, 3, 6, 1, 5, 5, 7, 1, 11], "Subject Information Access"),
    (&[1, 3, 6, 1, 5, 5, 7, 1, 24], "TLS Feature"),
    (&[1, 3, 6, 1, 5, 5, 7, 2, 1], "CPS"),
    (&[1, 3, 6, 1, 5, 5, 7, 2, 2], "User Notice"),
    (&[1, 3, 6, 1, 5, 5, 7, 3, 1], "serverAuth"),
    (&[1, 3, 6, 1, 5, 5, 7, 3, 2], "clientAuth"),
    (&[1, 3, 6, 1, 5, 5, 7, 3, 3], "codeSigning"),
    (&[1, 3, 6, 1, 5, 5, 7, 3, 4], "emailProtection"),
    (&[1, 3, 6, 1, 5, 5, 7, 3, 8], "timeStamping"),
    (&[1, 3, 6, 1, 5, 5, 7, 3, 9], "OCSPSigning"),
    (&[1, 3, 6, 1, 5, 5, 7, 48, 1], "OCSP"),
    (&[1, 3, 6, 1, 5, 5, 7, 48, 2], "CA Issuers"),
    (
        &[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2],
        "Signed Certificate Timestamps",
    ),
    (
        &[1, 3, 6, 1, 4, 1, 11129, 2, 4, 3],
        "Certificate Transparency poison",
    ),
];

/// The dump's display lines, and whether anything was left out to protect a
/// request's challenge password.
pub struct Dump {
    pub lines: Vec<String>,
    pub withheld: bool,
}

/// Dumps every element in `encoding`. With `request`, challenge password
/// values and undecodable bytes are not shown.
pub fn dump(encoding: &[u8], request: bool) -> Dump {
    let mut dumper = Dumper {
        base: encoding,
        width: encoding.len().max(1).to_string().len(),
        request,
        lines: Vec::new(),
        truncated: false,
        withheld: false,
    };
    if encoding.is_empty() {
        dumper.lines.push("(empty)".into());
    }
    dumper.elements(encoding, 0);
    if dumper.truncated {
        dumper
            .lines
            .push(format!("Output stopped after {MAX_LINES} lines."));
    }
    Dump {
        lines: dumper.lines,
        withheld: dumper.withheld,
    }
}

/// The name of an OID, when known.
fn oid_name(oid: &ObjectIdentifier) -> Option<String> {
    if let Some((_, name)) = NAMES.iter().find(|(arcs, _)| oid.matches(arcs)) {
        return Some((*name).into());
    }
    if let Some(name) = extensions::name(oid) {
        return Some(name.into());
    }
    let name = signature_name(oid);
    (name != oid.to_dotted_string()).then_some(name)
}

fn tag_name(tag: Tag) -> String {
    match tag.class {
        Class::Universal => match tag.number {
            1 => "BOOLEAN".into(),
            2 => "INTEGER".into(),
            3 => "BIT STRING".into(),
            4 => "OCTET STRING".into(),
            5 => "NULL".into(),
            6 => "OBJECT IDENTIFIER".into(),
            10 => "ENUMERATED".into(),
            12 => "UTF8String".into(),
            16 => "SEQUENCE".into(),
            17 => "SET".into(),
            18 => "NumericString".into(),
            19 => "PrintableString".into(),
            20 => "TeletexString".into(),
            22 => "IA5String".into(),
            23 => "UTCTime".into(),
            24 => "GeneralizedTime".into(),
            26 => "VisibleString".into(),
            28 => "UniversalString".into(),
            30 => "BMPString".into(),
            number => format!("[UNIVERSAL {number}]"),
        },
        Class::ContextSpecific => format!("[{}]", tag.number),
        Class::Application => format!("[APPLICATION {}]", tag.number),
        Class::Private => format!("[PRIVATE {}]", tag.number),
    }
}

/// Whether `content` is exactly one well-formed element of a type that wraps
/// DER, rather than raw bytes that happen to parse. Random key and signature
/// bytes rarely pass this.
fn encapsulates(content: &[u8]) -> bool {
    let mut reader = Reader::new(content);
    let Ok(raw) = reader.read_raw_tlv() else {
        return false;
    };
    let Ok((tag, inner)) = Reader::new(raw).read_tlv() else {
        return false;
    };
    let plausible = if tag.constructed {
        well_formed(inner, 0)
    } else {
        tag.class == Class::Universal
            && matches!(tag.number, 1..=6 | 12 | 19 | 22 | 23 | 24 | 26 | 30)
    };
    reader.is_empty() && plausible
}

/// Whether `content` is a complete list of elements, recursively.
fn well_formed(content: &[u8], depth: usize) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }
    let mut reader = Reader::new(content);
    while !reader.is_empty() {
        match reader.read_tlv() {
            Ok((tag, inner)) if !tag.constructed || well_formed(inner, depth + 1) => {}
            _ => return false,
        }
    }
    true
}

/// The number of elements in a constructed value's content, or `None` when
/// some cannot be read.
fn count(content: &[u8]) -> Option<usize> {
    let mut reader = Reader::new(content);
    let mut count = 0;
    while !reader.is_empty() {
        reader.read_raw_tlv().ok()?;
        count += 1;
    }
    Some(count)
}

fn plural(count: usize, noun: &str) -> String {
    format!("{count} {noun}{}", if count == 1 { "" } else { "s" })
}

fn integer_text(content: &[u8]) -> Option<String> {
    if content.is_empty() || content.len() > 8 {
        return None;
    }
    let fill = if content[0] & 0x80 != 0 { 0xff } else { 0 };
    let mut bytes = [fill; 8];
    bytes[8 - content.len()..].copy_from_slice(content);
    Some(i64::from_be_bytes(bytes).to_string())
}

/// Visible ASCII as a quoted string, for implicitly tagged names and URIs.
fn ascii_text(content: &[u8]) -> Option<String> {
    (!content.is_empty() && content.iter().all(|&b| (b' '..=b'~').contains(&b)))
        .then(|| format!("\"{}\"", String::from_utf8_lossy(content)))
}

struct Dumper<'a> {
    /// The whole encoding, for offsets.
    base: &'a [u8],
    /// Digits in the largest offset.
    width: usize,
    request: bool,
    lines: Vec<String>,
    truncated: bool,
    withheld: bool,
}

impl<'a> Dumper<'a> {
    fn full(&mut self) -> bool {
        if self.lines.len() >= MAX_LINES {
            self.truncated = true;
        }
        self.truncated
    }

    fn offset(&self, slice: &[u8]) -> usize {
        slice.as_ptr() as usize - self.base.as_ptr() as usize
    }

    fn line(&mut self, offset: Option<usize>, depth: usize, text: String) {
        if self.full() {
            return;
        }
        let offset = offset.map_or_else(String::new, |offset| offset.to_string());
        let indent = "  ".repeat(depth.min(MAX_DEPTH));
        self.lines.push(format!(
            "{offset:>width$} {indent}{text}",
            width = self.width
        ));
    }

    /// A value's hex, after `label` when short, or below it in rows when long.
    fn bytes(&mut self, offset: usize, depth: usize, label: String, value: &[u8]) {
        if value.len() <= HEX_ROW {
            self.line(Some(offset), depth, format!("{label} {}", hex(value)));
            return;
        }
        self.line(
            Some(offset),
            depth,
            format!("{label} ({})", plural(value.len(), "byte")),
        );
        for row in value.chunks(HEX_ROW) {
            if self.full() {
                return;
            }
            self.line(None, depth + 1, hex(row));
        }
    }

    /// Each element of `content` in turn, then any bytes that cannot be read.
    fn elements(&mut self, content: &'a [u8], depth: usize) {
        let mut reader = Reader::new(content);
        // An attribute's values follow its type; a challenge password's are hidden.
        let mut hide_values = false;
        let mut first = true;
        while !reader.is_empty() {
            let rest = &content[content.len() - reader.remaining()..];
            let element = reader.read_raw_tlv().and_then(|raw| {
                Reader::new(raw)
                    .read_tlv()
                    .map(|(tag, inner)| (raw, tag, inner))
            });
            let (raw, tag, inner) = match element {
                Ok(element) => element,
                Err(error) => {
                    self.undecodable(rest, &error.to_string(), depth);
                    return;
                }
            };
            if hide_values {
                self.withheld = true;
                self.line(
                    Some(self.offset(raw)),
                    depth,
                    format!("{} (challenge password; not shown)", tag_name(tag)),
                );
                continue;
            }
            if first && tag == der::OBJECT_IDENTIFIER {
                hide_values = ObjectIdentifier::from_der_content(inner)
                    .is_ok_and(|oid| oid.matches(OID_CHALLENGE_PASSWORD));
            }
            first = false;
            self.element(raw, tag, inner, depth);
        }
    }

    fn undecodable(&mut self, rest: &[u8], error: &str, depth: usize) {
        let error = error.strip_prefix("asn1: ").unwrap_or(error);
        let label = format!("Could not decode {}: {error}", plural(rest.len(), "byte"));
        let offset = self.offset(rest);
        if self.request {
            self.withheld = true;
            self.line(Some(offset), depth, format!("{label}; not shown"));
        } else {
            self.bytes(offset, depth, label, rest);
        }
    }

    fn element(&mut self, raw: &'a [u8], tag: Tag, content: &'a [u8], depth: usize) {
        let offset = self.offset(raw);
        let name = tag_name(tag);
        if depth >= MAX_DEPTH {
            self.line(
                Some(offset),
                depth,
                format!("{name} (nested too deeply; not shown)"),
            );
            return;
        }
        if tag.constructed {
            let elements = match count(content) {
                Some(0) => "empty".into(),
                Some(count) => plural(count, "element"),
                None => "malformed".into(),
            };
            self.line(Some(offset), depth, format!("{name} ({elements})"));
            self.elements(content, depth + 1);
            return;
        }
        if tag.class != Class::Universal {
            match ascii_text(content) {
                Some(text) => self.line(Some(offset), depth, format!("{name} {text}")),
                None => self.bytes(offset, depth, name, content),
            }
            return;
        }
        match tag.number {
            1 => match content {
                [0] => self.line(Some(offset), depth, format!("{name} false")),
                [0xff] => self.line(Some(offset), depth, format!("{name} true")),
                _ => self.bytes(offset, depth, format!("{name} (invalid)"), content),
            },
            2 | 10 => match integer_text(content) {
                Some(value) => self.line(Some(offset), depth, format!("{name} {value}")),
                None => self.bytes(offset, depth, name, content),
            },
            3 => match content.split_first() {
                Some((0, value)) if encapsulates(value) => {
                    self.line(Some(offset), depth, format!("{name} (encapsulates)"));
                    self.elements(value, depth + 1);
                }
                Some((&unused, value)) if unused > 0 => self.bytes(
                    offset,
                    depth,
                    format!("{name} ({} unused)", plural(unused.into(), "bit")),
                    value,
                ),
                Some((_, value)) => self.bytes(offset, depth, name, value),
                None => self.line(Some(offset), depth, format!("{name} (invalid, empty)")),
            },
            4 if encapsulates(content) => {
                self.line(Some(offset), depth, format!("{name} (encapsulates)"));
                self.elements(content, depth + 1);
            }
            5 if content.is_empty() => self.line(Some(offset), depth, name),
            6 => match ObjectIdentifier::from_der_content(content) {
                Ok(oid) => {
                    let text = match oid_name(&oid) {
                        Some(known) => format!("{name} {oid} ({known})"),
                        None => format!("{name} {oid}"),
                    };
                    self.line(Some(offset), depth, text);
                }
                Err(_) => self.bytes(offset, depth, format!("{name} (invalid)"), content),
            },
            12 | 19 | 20 | 22 | 26 | 30 => match der::decode_string(tag, content) {
                Ok(text) => self.line(
                    Some(offset),
                    depth,
                    format!("{name} \"{}\"", printable(&text)),
                ),
                Err(_) => self.bytes(offset, depth, format!("{name} (invalid)"), content),
            },
            18 => match ascii_text(content) {
                Some(text) => self.line(Some(offset), depth, format!("{name} {text}")),
                None => self.bytes(offset, depth, name, content),
            },
            23 | 24 => {
                let parsed = Reader::new(raw).read_time().ok();
                match (ascii_text(content), parsed) {
                    (Some(text), Some(time)) => self.line(
                        Some(offset),
                        depth,
                        format!("{name} {} ({text})", time_text(&time)),
                    ),
                    _ => self.bytes(offset, depth, format!("{name} (invalid)"), content),
                }
            }
            _ => self.bytes(offset, depth, name, content),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ed25519_certificate, ed25519_request};

    fn oid(arcs: &[u64]) -> Vec<u8> {
        der::oid(&ObjectIdentifier::new(arcs).unwrap())
    }

    fn joined(dump: &Dump) -> String {
        dump.lines.join("\n")
    }

    #[test]
    fn dumps_certificate_structure_with_offsets_and_names() {
        let certificate = ed25519_certificate("leaf", "root", 3, 2);
        let dump = dump(&certificate, false);
        assert!(!dump.withheld);
        let width = certificate.len().to_string().len();
        assert_eq!(
            dump.lines[0],
            format!("{:>width$} SEQUENCE (3 elements)", 0)
        );
        let text = joined(&dump);
        for expected in [
            "  SEQUENCE (",
            "OBJECT IDENTIFIER 1.3.101.112 (Ed25519)",
            "OBJECT IDENTIFIER 2.5.4.3 (commonName)",
            "UTF8String \"leaf\"",
            " UTC (",
            "BIT STRING (32 bytes)",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in\n{text}");
        }
        // Nested elements are indented under their parent.
        let subject = dump
            .lines
            .iter()
            .find(|line| line.contains("\"leaf\""))
            .unwrap();
        let indent = subject[width + 1..].len() - subject[width + 1..].trim_start().len();
        assert!(indent >= 8, "{subject}");
    }

    #[test]
    fn values_are_decoded_and_wrapped_der_is_nested() {
        let extension = der::sequence(
            &[
                oid(&[2, 5, 29, 19]),
                der::boolean(true),
                der::octet_string(&der::sequence(
                    &[der::boolean(true), der::integer(&[1])].concat(),
                )),
            ]
            .concat(),
        );
        let text = joined(&dump(&extension, false));
        for expected in [
            "OBJECT IDENTIFIER 2.5.29.19 (Basic Constraints)",
            "BOOLEAN true",
            "OCTET STRING (encapsulates)",
            "INTEGER 1",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in\n{text}");
        }

        let values = der::sequence(
            &[
                der::tlv(der::INTEGER, &[0xff, 0x00]),
                der::integer(&[0x7f; 20]),
                der::octet_string(&[0x02, 0x01, 0x05, 0xaa]),
                der::bit_string(5, &[0xa0]),
                der::implicit(2, false, b"example.test"),
                der::implicit(7, false, &[127, 0, 0, 1]),
                der::null(),
                der::printable_string("A\u{1b}"),
            ]
            .concat(),
        );
        let dump = dump(&values, false);
        let text = joined(&dump);
        for expected in [
            "INTEGER -256",
            "INTEGER (20 bytes)",
            "7F:7F:7F:7F:7F:7F:7F:7F:7F:7F:7F:7F:7F:7F:7F:7F",
            "OCTET STRING 02:01:05:AA",
            "BIT STRING (5 bits unused) A0",
            "[2] \"example.test\"",
            "[7] 7F:00:00:01",
            "NULL",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in\n{text}");
        }
        // Control characters cannot restyle the terminal.
        assert!(!text.contains('\u{1b}'));
    }

    #[test]
    fn undecodable_bytes_are_reported_and_hidden_in_requests() {
        let certificate = ed25519_certificate("leaf", "root", 3, 2);
        let truncated = &certificate[..certificate.len() - 1];
        let dump = dump(truncated, false);
        assert!(joined(&dump).contains(&format!(
            "Could not decode {} bytes: truncated",
            truncated.len()
        )));
        assert!(joined(&dump).contains(&hex(&truncated[..4])));
        assert!(!dump.withheld);

        let trailing = [&certificate[..], &[0x05, 0x05]].concat();
        let text = joined(&self::dump(&trailing, false));
        assert!(text.contains("SEQUENCE (3 elements)"));
        assert!(
            text.contains("Could not decode 2 bytes: truncated 05:05"),
            "{text}"
        );

        let request = ed25519_request("device", &[]);
        let truncated = self::dump(&request[..40], true);
        assert!(truncated.withheld);
        assert_eq!(truncated.lines.len(), 1);
        assert!(truncated.lines[0].ends_with("Could not decode 40 bytes: truncated; not shown"));
        assert!(!self::dump(&request, true).withheld);
        assert_eq!(self::dump(b"", false).lines, ["(empty)"]);
    }

    #[test]
    fn challenge_passwords_are_never_shown() {
        let attribute = der::sequence(
            &[
                oid(OID_CHALLENGE_PASSWORD),
                der::set(&der::utf8_string("synthetic-secret")),
            ]
            .concat(),
        );
        let request = ed25519_request("device", &[attribute]);
        let dump = dump(&request, true);
        let text = joined(&dump);
        assert!(dump.withheld);
        assert!(text.contains("(challengePassword)"));
        assert!(text.contains("SET (challenge password; not shown)"));
        assert!(!text.contains("synthetic"));
        let secret = hex(b"synthetic-secret");
        assert!(!text.contains(&secret[..20]));
    }

    #[test]
    fn deep_nesting_and_huge_values_are_bounded() {
        let mut nested = der::null();
        for _ in 0..200 {
            nested = der::sequence(&nested);
        }
        let text = joined(&dump(&nested, false));
        assert!(text.contains("SEQUENCE (nested too deeply; not shown)"));

        let huge = der::octet_string(&vec![0x11; MAX_LINES * HEX_ROW * 2]);
        let dump = dump(&huge, false);
        assert_eq!(dump.lines.len(), MAX_LINES + 1);
        assert_eq!(
            dump.lines.last().unwrap(),
            &format!("Output stopped after {MAX_LINES} lines.")
        );
    }
}
