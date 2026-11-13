//! Building certificates and certificate requests signed with a PKCS #8
//! private key: the subject name, the extensions of a purpose, a
//! self-signed certificate, a certificate issued by another key for a new
//! key or for a certificate request, and a PKCS #10 request.
use std::net::IpAddr;

use crown::{
    asn1::{
        Asn1Time, der,
        oid::{self, ObjectIdentifier},
    },
    ec::CurveId,
    rng::Rng,
    x509::{
        algorithm::{Hash, SignatureAlgorithm},
        attribute::Attribute,
        cert::{Certificate, CertificateBuilder},
        csr::CertificationRequest,
        extensions::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, Extension, GeneralName,
            KeyUsage, encode_general_names,
        },
        keys::{PrivateKey, PrivateKeyInfo, SubjectPublicKeyInfo},
        name::{AttributeTypeAndValue, Name, Rdn},
    },
};

const UNSUPPORTED_KEY: &str = "This type of private key cannot sign a certificate.";

/// The fields of a subject name; empty ones are left out of the name.
#[derive(Default)]
pub struct Subject<'a> {
    pub common_name: &'a str,
    pub organization: &'a str,
    pub unit: &'a str,
    pub locality: &'a str,
    pub state: &'a str,
    /// A two-letter country code.
    pub country: &'a str,
}

impl Subject<'_> {
    /// The distinguished name, from the country down to the common name.
    pub fn name(&self) -> Name {
        let utf8 = AttributeTypeAndValue::from_utf8;
        let fields = [
            // A country is a PrintableString by definition.
            (
                oid::OID_AT_COUNTRY,
                self.country,
                AttributeTypeAndValue::from_printable as fn(_, &str) -> _,
            ),
            (oid::OID_AT_STATE, self.state, utf8),
            (oid::OID_AT_LOCALITY, self.locality, utf8),
            (oid::OID_AT_ORGANIZATION, self.organization, utf8),
            (oid::OID_AT_ORGANIZATIONAL_UNIT, self.unit, utf8),
            (oid::OID_AT_COMMON_NAME, self.common_name, utf8),
        ];
        Name {
            rdns: fields
                .into_iter()
                .filter(|(_, value, _)| !value.is_empty())
                .map(|(arcs, value, attribute)| Rdn {
                    attributes: vec![attribute(object(arcs), value)],
                })
                .collect(),
        }
    }
}

/// What a certificate is for, which sets its key usage, extended key usage,
/// and basic constraints together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    None,
    TlsServer,
    TlsClient,
    TlsServerAndClient,
    CertificateAuthority,
    CodeSigning,
}

impl Purpose {
    pub const ALL: [Self; 6] = [
        Self::None,
        Self::TlsServer,
        Self::TlsClient,
        Self::TlsServerAndClient,
        Self::CertificateAuthority,
        Self::CodeSigning,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::TlsServer => "TLS server",
            Self::TlsClient => "TLS client",
            Self::TlsServerAndClient => "TLS server and client",
            Self::CertificateAuthority => "Certificate authority",
            Self::CodeSigning => "Code signing",
        }
    }

    /// What the purpose puts in the certificate, for the form's hint.
    pub fn summary(self) -> &'static str {
        match self {
            Self::None => "No key usage extensions.",
            Self::TlsServer => "Digital signature, RSA key encipherment; TLS server.",
            Self::TlsClient => "Digital signature; TLS client.",
            Self::TlsServerAndClient => {
                "Digital signature, RSA key encipherment; TLS server and client."
            }
            Self::CertificateAuthority => "A CA certificate: certificate and CRL signing.",
            Self::CodeSigning => "Digital signature; code signing.",
        }
    }

    /// The key usage, extended key usage, and basic constraints extensions.
    /// Only an RSA key can encipher keys, as TLS servers with one may.
    fn extensions(self, rsa: bool) -> Vec<Extension> {
        let signature = KeyUsage {
            digital_signature: true,
            ..KeyUsage::default()
        };
        let server = KeyUsage {
            key_encipherment: rsa,
            ..signature
        };
        let (usage, purposes): (KeyUsage, &[&[u64]]) = match self {
            Self::None => return Vec::new(),
            Self::TlsServer => (server, &[oid::OID_KP_SERVER_AUTH]),
            Self::TlsClient => (signature, &[oid::OID_KP_CLIENT_AUTH]),
            Self::TlsServerAndClient => {
                (server, &[oid::OID_KP_SERVER_AUTH, oid::OID_KP_CLIENT_AUTH])
            }
            Self::CodeSigning => (signature, &[oid::OID_KP_CODE_SIGNING]),
            Self::CertificateAuthority => (
                KeyUsage {
                    key_cert_sign: true,
                    crl_sign: true,
                    ..KeyUsage::default()
                },
                &[],
            ),
        };
        let mut extensions = Vec::new();
        if self == Self::CertificateAuthority {
            let constraints = BasicConstraints {
                ca: true,
                path_len: None,
            };
            extensions.push(Extension::new(
                object(oid::OID_BASIC_CONSTRAINTS),
                true,
                constraints.encode(),
            ));
        }
        extensions.push(Extension::new(
            object(oid::OID_KEY_USAGE),
            true,
            usage.encode(),
        ));
        if !purposes.is_empty() {
            let usage = ExtendedKeyUsage {
                purposes: purposes.iter().map(|arcs| object(arcs)).collect(),
            };
            extensions.push(Extension::new(
                object(oid::OID_EXTENDED_KEY_USAGE),
                false,
                usage.encode(),
            ));
        }
        extensions
    }
}

fn object(arcs: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::new(arcs).expect("a constant object identifier")
}

/// The subject alternative names in `text`, separated by commas: an IP
/// address, an email address (it holds an `@`), or else a DNS name.
pub fn alternative_names(text: &str) -> Result<Vec<GeneralName>, String> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    text.split(',')
        .map(|name| {
            let name = name.trim();
            if name.is_empty() {
                Err("An alternative name is empty; check the commas.".into())
            } else if let Ok(address) = name.parse::<IpAddr>() {
                Ok(GeneralName::IpAddress(match address {
                    IpAddr::V4(address) => address.octets().to_vec(),
                    IpAddr::V6(address) => address.octets().to_vec(),
                }))
            } else if !name.is_ascii() || name.contains(char::is_whitespace) {
                // DNS names and email addresses are stored as ASCII.
                Err(format!(
                    "'{name}' is not a plain ASCII name; write international names in punycode."
                ))
            } else if name.contains('@') {
                Ok(GeneralName::Rfc822Name(name.into()))
            } else {
                Ok(GeneralName::DnsName(name.into()))
            }
        })
        .collect()
}

/// The signature algorithm a key signs with: SHA-256 with RSA, ECDSA with
/// the hash of the curve's size, or the key's own EdDSA.
pub fn signature_algorithm(key: &PrivateKey) -> Result<SignatureAlgorithm, String> {
    Ok(match key {
        PrivateKey::Rsa(_) => SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
        PrivateKey::Ec { curve, .. } => SignatureAlgorithm::Ecdsa(match curve {
            CurveId::P256 => Hash::Sha256,
            CurveId::P384 => Hash::Sha384,
            CurveId::P521 => Hash::Sha512,
        }),
        PrivateKey::Ed25519(_) => SignatureAlgorithm::Ed25519,
        PrivateKey::Ed448(_) => SignatureAlgorithm::Ed448,
        _ => return Err(UNSUPPORTED_KEY.into()),
    })
}

/// A random serial number: positive, and 16 bytes long.
fn serial(rng: &mut impl Rng) -> Vec<u8> {
    let mut serial = vec![0; 16];
    rng.fill_bytes(&mut serial);
    // Clear the sign bit, and keep the first byte from being zero.
    serial[0] = serial[0] & 0x7f | 0x40;
    serial
}

/// What a certificate or a certificate request holds besides its key.
pub struct Request {
    pub subject: Name,
    /// How many days a certificate is valid, from now; a request has no
    /// validity.
    pub days: u32,
    pub names: Vec<GeneralName>,
    pub purpose: Purpose,
}

/// The private key that signs for another subject, as PKCS #8, and its
/// certificate, whose subject becomes the issuer.
pub struct Issuer<'a> {
    pub key: &'a [u8],
    pub certificate: &'a [u8],
}

/// Why what the certificate signs may be rejected: it is not marked as a
/// certificate authority, or its key usage leaves certificate signing out.
/// `None` for a CA certificate, and for one that cannot be read.
pub fn ca_warning(certificate: &[u8]) -> Option<&'static str> {
    let certificate = Certificate::parse(certificate).ok()?;
    let tbs = certificate.tbs();
    if !tbs
        .basic_constraints()
        .is_some_and(|constraints| constraints.ca)
    {
        Some("its certificate is not a CA certificate")
    } else if tbs.key_usage().is_some_and(|usage| !usage.key_cert_sign) {
        Some("its key usage does not allow signing certificates")
    } else {
        None
    }
}

fn decode(key: &[u8]) -> Result<PrivateKey, String> {
    PrivateKeyInfo::parse(key)
        .and_then(|info| info.decode())
        .map_err(|_| UNSUPPORTED_KEY.into())
}

fn public_key(key: &PrivateKey) -> Result<SubjectPublicKeyInfo, String> {
    key.public_key()
        .and_then(|public| SubjectPublicKeyInfo::from_public_key(&public))
        .map_err(|_| UNSUPPORTED_KEY.into())
}

/// What a certificate holds, whoever signs it.
struct Content {
    subject: Name,
    public: SubjectPublicKeyInfo,
    serial: Vec<u8>,
    days: u32,
    /// The extensions after the key identifiers.
    extensions: Vec<Extension>,
}

/// The DER of a certificate holding `content`, valid from `now`. It is
/// signed by `issuer` and names it, or else by `own_key`, the subject's.
fn certificate(
    content: Content,
    own_key: Option<&PrivateKey>,
    issuer: Option<&Issuer>,
    now: i64,
    rng: &mut impl Rng,
) -> Result<Vec<u8>, String> {
    let not_signed = |error| format!("The certificate could not be signed: {error}.");
    let identifier = content
        .public
        .key_identifier()
        .map_err(|_| UNSUPPORTED_KEY)?;
    let mut extensions = vec![Extension::new(
        object(oid::OID_SUBJECT_KEY_IDENTIFIER),
        false,
        der::octet_string(&identifier),
    )];
    let issuing = match issuer {
        Some(issuer) => {
            let key = decode(issuer.key)?;
            let certificate = Certificate::parse(issuer.certificate)
                .map_err(|_| "The signing key's certificate cannot be read.")?;
            // The issuer's own identifier when it has one, as verifiers
            // compare the two; else the usual digest of its public key.
            let authority = certificate
                .tbs()
                .subject_key_identifier()
                .map_or_else(
                    || certificate.subject_public_key_info().key_identifier(),
                    Ok,
                )
                .map_err(|_| UNSUPPORTED_KEY)?;
            extensions.push(Extension::new(
                object(oid::OID_AUTHORITY_KEY_IDENTIFIER),
                false,
                AuthorityKeyIdentifier {
                    key_identifier: Some(authority),
                    authority_cert_issuer: None,
                    authority_cert_serial: None,
                }
                .encode(),
            ));
            Some((key, certificate))
        }
        None => None,
    };
    let signer = match (&issuing, own_key) {
        (Some((key, _)), _) => key,
        (None, Some(key)) => key,
        (None, None) => return Err(UNSUPPORTED_KEY.into()),
    };
    let mut builder = CertificateBuilder::new(
        content.subject,
        content.public,
        signature_algorithm(signer)?,
    )
    .serial(content.serial)
    .validity(
        Asn1Time::from_unix(now, true),
        Asn1Time::from_unix(now + i64::from(content.days) * 86_400, true),
    );
    if let Some((_, certificate)) = &issuing {
        builder = builder.issuer(certificate.subject().clone());
    }
    for extension in extensions.into_iter().chain(content.extensions) {
        builder = builder.extension(extension);
    }
    let signed = builder.sign(signer, rng).map_err(not_signed)?;
    // A key that is not its certificate's would sign what nothing verifies.
    if let Some((_, certificate)) = &issuing
        && signed.verify_signature(certificate.public_key()) != Ok(true)
    {
        return Err("The signing key does not match its certificate.".into());
    }
    Ok(signed.encode())
}

/// The extensions a form's request asks for, for a key of this type.
fn asked_extensions(request: &Request, rsa: bool) -> Vec<Extension> {
    let mut extensions = request.purpose.extensions(rsa);
    if !request.names.is_empty() {
        extensions.push(Extension::new(
            object(oid::OID_SUBJECT_ALT_NAME),
            false,
            encode_general_names(&request.names),
        ));
    }
    extensions
}

/// The DER of a certificate for the PKCS #8 private key `key`, valid from
/// `now`, in seconds since the Unix epoch. It is signed with that key, or
/// with the `issuer`'s when there is one.
pub fn key_certificate(
    key: &[u8],
    request: &Request,
    issuer: Option<&Issuer>,
    now: i64,
    rng: &mut impl Rng,
) -> Result<Vec<u8>, String> {
    let key = decode(key)?;
    let content = Content {
        subject: request.subject.clone(),
        public: public_key(&key)?,
        serial: serial(rng),
        days: request.days,
        extensions: asked_extensions(request, matches!(key, PrivateKey::Rsa(_))),
    };
    certificate(content, Some(&key), issuer, now, rng)
}

/// The DER of a certificate for the PKCS #8 private key `key`, signed with
/// that key and valid from `now`, in seconds since the Unix epoch.
#[cfg(test)]
pub fn self_signed(
    key: &[u8],
    request: &Request,
    now: i64,
    rng: &mut impl Rng,
) -> Result<Vec<u8>, String> {
    key_certificate(key, request, None, now, rng)
}

/// What the issuer decides about the certificate of a request it signs.
#[derive(Clone)]
pub struct Terms {
    pub days: u32,
    /// The serial number's bytes; random without one.
    pub serial: Option<Vec<u8>>,
    /// The requested extensions that the certificate holds.
    pub extensions: Vec<Extension>,
}

/// The DER of a certificate for the subject and public key of the PKCS #10
/// request `request`, signed by `issuer` and valid from `now`.
pub fn request_certificate(
    request: &[u8],
    terms: Terms,
    issuer: &Issuer,
    now: i64,
    rng: &mut impl Rng,
) -> Result<Vec<u8>, String> {
    let request = CertificationRequest::parse(request)
        .map_err(|_| "The certificate request cannot be read.")?;
    let info = request.info();
    let content = Content {
        subject: info.subject.clone(),
        public: info.subject_public_key_info.clone(),
        serial: terms.serial.unwrap_or_else(|| serial(rng)),
        days: terms.days,
        extensions: terms.extensions,
    };
    certificate(content, None, Some(issuer), now, rng)
}

/// The DER of a PKCS #10 certificate request for the PKCS #8 private key
/// `key`, signed with that key. The purpose's extensions and the alternative
/// names are asked for in an extension request, when there are any.
pub fn request(key: &[u8], request: &Request, rng: &mut impl Rng) -> Result<Vec<u8>, String> {
    let key = decode(key)?;
    let algorithm = signature_algorithm(&key)?;
    let public = public_key(&key)?;
    let extensions = asked_extensions(request, matches!(key, PrivateKey::Rsa(_)));
    let mut attributes = Vec::new();
    if !extensions.is_empty() {
        let extensions: Vec<u8> = extensions.iter().flat_map(Extension::encode).collect();
        attributes.push(Attribute::new(
            object(oid::OID_PKCS9_EXTENSION_REQUEST),
            vec![der::sequence(&extensions)],
        ));
    }
    CertificationRequest::build(
        request.subject.clone(),
        public,
        attributes,
        algorithm,
        &key,
        rng,
    )
    .map(|request| request.encode())
    .map_err(|error| format!("The certificate request could not be signed: {error}."))
}

#[cfg(test)]
mod tests {
    use crown::x509::cert::Certificate;

    use super::*;
    use crate::{
        certificate,
        test_support::{
            TestRng, ed25519_certificate, ed25519_pkcs8, ed25519_request, synthetic_pkcs8,
        },
    };

    fn request(purpose: Purpose) -> Request {
        Request {
            subject: Subject {
                common_name: "example.test",
                ..Subject::default()
            }
            .name(),
            days: 30,
            names: Vec::new(),
            purpose,
        }
    }

    /// 2026-01-01 00:00:00 UTC.
    const NOW: i64 = 1_767_225_600;

    #[test]
    fn subject_names_run_from_country_to_common_name_without_empty_fields() {
        let name = Subject {
            common_name: "example.test",
            organization: "Example",
            unit: "",
            locality: "Zürich",
            state: "",
            country: "CH",
        }
        .name();
        let text: Vec<_> = name
            .iter_attributes()
            .map(|attribute| attribute.text().unwrap())
            .collect();
        assert_eq!(text, ["CH", "Zürich", "Example", "example.test"]);
        assert_eq!(name.rdns[0].attributes[0].tag, der::PRINTABLE_STRING);
        assert_eq!(name.rdns[1].attributes[0].tag, der::UTF8_STRING);
        assert!(Subject::default().name().rdns.is_empty());
    }

    #[test]
    fn alternative_names_are_addresses_emails_or_dns_names() {
        assert_eq!(alternative_names("  "), Ok(Vec::new()));
        assert_eq!(
            alternative_names("example.test, 10.0.0.5 ,::1,admin@example.test"),
            Ok(vec![
                GeneralName::DnsName("example.test".into()),
                GeneralName::IpAddress(vec![10, 0, 0, 5]),
                GeneralName::IpAddress([&[0; 15][..], &[1]].concat()),
                GeneralName::Rfc822Name("admin@example.test".into()),
            ])
        );
        assert!(alternative_names("a,,b").unwrap_err().contains("empty"));
        assert!(
            alternative_names("zürich.test")
                .unwrap_err()
                .contains("punycode")
        );
        assert!(
            alternative_names("two words")
                .unwrap_err()
                .contains("ASCII")
        );
    }

    #[test]
    fn a_self_signed_certificate_verifies_and_holds_the_request() {
        let mut request = request(Purpose::TlsServer);
        request.names = alternative_names("example.test").unwrap();
        let der = self_signed(&ed25519_pkcs8(3), &request, NOW, &mut TestRng(0)).unwrap();
        let parsed = Certificate::parse(&der).unwrap();
        assert!(parsed.is_self_signed());
        assert_eq!(parsed.verify_signature(parsed.public_key()), Ok(true));
        assert_eq!(parsed.subject().common_name().unwrap(), "example.test");
        assert_eq!(parsed.validity().not_before.to_unix(), NOW);
        assert_eq!(parsed.validity().not_after.to_unix(), NOW + 30 * 86_400);
        // The test bytes count up from 1; the sign bit is cleared.
        assert_eq!(parsed.serial_number()[..2], [0x41, 2]);
        assert_eq!(parsed.serial_number().len(), 16);
        let tbs = parsed.tbs();
        assert_eq!(
            tbs.subject_alt_names(),
            Some(vec![GeneralName::DnsName("example.test".into())])
        );
        assert_eq!(
            tbs.subject_key_identifier(),
            parsed.subject_public_key_info().key_identifier().ok()
        );
        let summary = certificate::summarize(&der).unwrap();
        assert_eq!(summary.subject, "CN=example.test");
        assert_eq!(summary.algorithm, "Ed25519");
    }

    /// A certificate authority with the Ed25519 key `[9; 32]`.
    fn authority() -> (Vec<u8>, Vec<u8>) {
        let key = ed25519_pkcs8(9);
        let mut asked = request(Purpose::CertificateAuthority);
        asked.subject = Subject {
            common_name: "Test CA",
            organization: "Example",
            ..Subject::default()
        }
        .name();
        let certificate = self_signed(&key, &asked, NOW, &mut TestRng(0)).unwrap();
        (key, certificate)
    }

    #[test]
    fn a_key_certificate_signed_by_an_issuer_names_and_verifies_with_it() {
        let (key, certificate) = authority();
        let issuer = Issuer {
            key: &key,
            certificate: &certificate,
        };
        let ca = Certificate::parse(&certificate).unwrap();
        let mut asked = request(Purpose::TlsServer);
        asked.names = alternative_names("example.test").unwrap();
        let der = key_certificate(
            &ed25519_pkcs8(3),
            &asked,
            Some(&issuer),
            NOW,
            &mut TestRng(0),
        )
        .unwrap();
        let parsed = Certificate::parse(&der).unwrap();
        assert!(!parsed.is_self_signed());
        assert_eq!(parsed.issuer().encode(), ca.subject().encode());
        assert_eq!(parsed.subject().common_name().unwrap(), "example.test");
        assert_eq!(parsed.verify_signature(ca.public_key()), Ok(true));
        assert_eq!(parsed.validity().not_after.to_unix(), NOW + 30 * 86_400);
        let tbs = parsed.tbs();
        assert_eq!(
            tbs.subject_key_identifier(),
            parsed.subject_public_key_info().key_identifier().ok()
        );
        assert_eq!(
            tbs.authority_key_identifier().unwrap().key_identifier,
            ca.tbs().subject_key_identifier()
        );
        // The key identifiers come first, then what was asked for.
        let order: Vec<_> = tbs
            .extensions
            .iter()
            .map(|extension| extension.oid.to_dotted_string())
            .collect();
        assert_eq!(
            order,
            [
                "2.5.29.14",
                "2.5.29.35",
                "2.5.29.15",
                "2.5.29.37",
                "2.5.29.17"
            ]
        );
        // A self-signed certificate names no authority.
        assert!(ca.tbs().authority_key_identifier().is_none());
    }

    #[test]
    fn an_issuer_without_a_key_identifier_is_named_by_its_key_digest() {
        let key = ed25519_pkcs8(9);
        let certificate = ed25519_certificate("bare", "bare", 9, 9);
        let issuer = Issuer {
            key: &key,
            certificate: &certificate,
        };
        let der = key_certificate(
            &ed25519_pkcs8(3),
            &request(Purpose::None),
            Some(&issuer),
            NOW,
            &mut TestRng(0),
        )
        .unwrap();
        let ca = Certificate::parse(&certificate).unwrap();
        assert_eq!(
            Certificate::parse(&der)
                .unwrap()
                .tbs()
                .authority_key_identifier()
                .unwrap()
                .key_identifier,
            ca.subject_public_key_info().key_identifier().ok()
        );
    }

    #[test]
    fn an_issuer_must_be_a_key_with_its_own_readable_certificate() {
        let (key, certificate) = authority();
        let sign = |key: &[u8], certificate: &[u8]| {
            key_certificate(
                &ed25519_pkcs8(3),
                &request(Purpose::None),
                Some(&Issuer { key, certificate }),
                NOW,
                &mut TestRng(0),
            )
        };
        assert!(sign(&key, &certificate).is_ok());
        assert_eq!(
            sign(&ed25519_pkcs8(8), &certificate),
            Err("The signing key does not match its certificate.".into())
        );
        assert_eq!(
            sign(&key, &[0x30, 0]),
            Err("The signing key's certificate cannot be read.".into())
        );
        assert_eq!(
            sign(&synthetic_pkcs8(&[1]), &certificate),
            Err(UNSUPPORTED_KEY.into())
        );
        // Without an issuer, the subject's own key signs.
        let content = Content {
            subject: Name::from_common_name("nobody"),
            public: public_key(&decode(&key).unwrap()).unwrap(),
            serial: vec![1],
            days: 1,
            extensions: Vec::new(),
        };
        assert_eq!(
            super::certificate(content, None, None, NOW, &mut TestRng(0)),
            Err(UNSUPPORTED_KEY.into())
        );
    }

    #[test]
    fn a_request_gets_a_certificate_on_the_issuers_terms() {
        let (key, certificate) = authority();
        let issuer = Issuer {
            key: &key,
            certificate: &certificate,
        };
        let asked = ed25519_request("device", &[]);
        let names = Extension::new(
            object(oid::OID_SUBJECT_ALT_NAME),
            true,
            encode_general_names(&[GeneralName::DnsName("device.test".into())]),
        );
        let terms = Terms {
            days: 7,
            serial: Some(vec![1, 0xa4]),
            extensions: vec![names],
        };
        let der =
            request_certificate(&asked, terms.clone(), &issuer, NOW, &mut TestRng(0)).unwrap();
        let parsed = Certificate::parse(&der).unwrap();
        let ca = Certificate::parse(&certificate).unwrap();
        assert_eq!(parsed.verify_signature(ca.public_key()), Ok(true));
        assert_eq!(parsed.issuer().encode(), ca.subject().encode());
        assert_eq!(parsed.subject().common_name().unwrap(), "device");
        assert_eq!(parsed.serial_number(), [1, 0xa4]);
        assert_eq!(parsed.validity().not_before.to_unix(), NOW);
        assert_eq!(parsed.validity().not_after.to_unix(), NOW + 7 * 86_400);
        // The certificate holds the request's public key.
        let request = CertificationRequest::parse(&asked).unwrap();
        assert_eq!(
            parsed.subject_public_key_info().encode(),
            request.info().subject_public_key_info.encode()
        );
        let tbs = parsed.tbs();
        assert_eq!(
            tbs.subject_alt_names(),
            Some(vec![GeneralName::DnsName("device.test".into())])
        );
        assert!(tbs.extension(oid::OID_SUBJECT_ALT_NAME).unwrap().critical);
        assert!(tbs.subject_key_identifier().is_some());
        assert!(tbs.authority_key_identifier().is_some());

        // Without a serial number, it is random.
        let random = Terms {
            serial: None,
            ..terms.clone()
        };
        let der = request_certificate(&asked, random, &issuer, NOW, &mut TestRng(0)).unwrap();
        assert_eq!(Certificate::parse(&der).unwrap().serial_number().len(), 16);
        assert_eq!(
            request_certificate(&[0x30, 0], terms, &issuer, NOW, &mut TestRng(0)),
            Err("The certificate request cannot be read.".into())
        );
    }

    #[test]
    fn only_a_certificate_authority_signs_without_a_warning() {
        let (key, certificate) = authority();
        assert_eq!(ca_warning(&certificate), None);
        let plain = self_signed(&key, &request(Purpose::TlsServer), NOW, &mut TestRng(0)).unwrap();
        assert_eq!(
            ca_warning(&plain),
            Some("its certificate is not a CA certificate")
        );
        assert_eq!(
            ca_warning(&ed25519_certificate("bare", "bare", 9, 9)),
            Some("its certificate is not a CA certificate")
        );
        // A CA whose key usage leaves certificate signing out.
        let decoded = decode(&key).unwrap();
        let content = Content {
            subject: Name::from_common_name("limited"),
            public: public_key(&decoded).unwrap(),
            serial: vec![1],
            days: 1,
            extensions: vec![
                Extension::new(
                    object(oid::OID_BASIC_CONSTRAINTS),
                    true,
                    BasicConstraints {
                        ca: true,
                        path_len: None,
                    }
                    .encode(),
                ),
                Extension::new(
                    object(oid::OID_KEY_USAGE),
                    true,
                    KeyUsage {
                        crl_sign: true,
                        ..KeyUsage::default()
                    }
                    .encode(),
                ),
            ],
        };
        let limited =
            super::certificate(content, Some(&decoded), None, NOW, &mut TestRng(0)).unwrap();
        assert_eq!(
            ca_warning(&limited),
            Some("its key usage does not allow signing certificates")
        );
        assert_eq!(ca_warning(&[0x30, 0]), None);
    }

    #[test]
    fn each_purpose_sets_its_extensions() {
        let extensions = |purpose: Purpose, rsa| {
            let extensions = purpose.extensions(rsa);
            let find = |arcs: &[u64]| {
                extensions
                    .iter()
                    .find(|extension| extension.oid.matches(arcs))
            };
            (
                find(oid::OID_KEY_USAGE).map(|usage| {
                    assert!(usage.critical);
                    KeyUsage::parse(&usage.value).unwrap()
                }),
                find(oid::OID_EXTENDED_KEY_USAGE)
                    .map(|usage| ExtendedKeyUsage::parse(&usage.value).unwrap().purposes),
                find(oid::OID_BASIC_CONSTRAINTS).map(|constraints| {
                    assert!(constraints.critical);
                    BasicConstraints::parse(&constraints.value).unwrap().ca
                }),
            )
        };
        let signature = KeyUsage {
            digital_signature: true,
            ..KeyUsage::default()
        };
        let encipherment = KeyUsage {
            key_encipherment: true,
            ..signature
        };
        assert_eq!(extensions(Purpose::None, true), (None, None, None));
        assert_eq!(
            extensions(Purpose::TlsServer, true),
            (
                Some(encipherment),
                Some(vec![object(oid::OID_KP_SERVER_AUTH)]),
                None
            )
        );
        assert_eq!(extensions(Purpose::TlsServer, false).0, Some(signature));
        assert_eq!(
            extensions(Purpose::TlsClient, true),
            (
                Some(signature),
                Some(vec![object(oid::OID_KP_CLIENT_AUTH)]),
                None
            )
        );
        assert_eq!(
            extensions(Purpose::TlsServerAndClient, false),
            (
                Some(signature),
                Some(vec![
                    object(oid::OID_KP_SERVER_AUTH),
                    object(oid::OID_KP_CLIENT_AUTH)
                ]),
                None
            )
        );
        assert_eq!(
            extensions(Purpose::CodeSigning, true),
            (
                Some(signature),
                Some(vec![object(oid::OID_KP_CODE_SIGNING)]),
                None
            )
        );
        assert_eq!(
            extensions(Purpose::CertificateAuthority, true),
            (
                Some(KeyUsage {
                    key_cert_sign: true,
                    crl_sign: true,
                    ..KeyUsage::default()
                }),
                None,
                Some(true)
            )
        );
        for purpose in Purpose::ALL {
            assert!(!purpose.label().is_empty());
            assert!(purpose.summary().ends_with('.'));
        }
    }

    #[test]
    fn a_request_verifies_and_asks_for_its_extensions() {
        let mut asked = request(Purpose::TlsClient);
        asked.names = alternative_names("example.test, 10.0.0.5").unwrap();
        let der = super::request(&ed25519_pkcs8(3), &asked, &mut TestRng(0)).unwrap();
        let parsed = CertificationRequest::parse(&der).unwrap();
        assert_eq!(parsed.verify_signature(), Ok(true));
        assert_eq!(parsed.info().subject, asked.subject);
        let extensions = parsed.extensions().unwrap();
        let oids: Vec<_> = extensions
            .iter()
            .map(|extension| extension.oid.to_dotted_string())
            .collect();
        assert_eq!(oids, ["2.5.29.15", "2.5.29.37", "2.5.29.17"]);
        // The app reads its own request like any other.
        let shown = crate::certificate_request::Request::parse(&der).unwrap();
        assert_eq!(shown.subject, asked.subject);
        assert_eq!(shown.extensions.len(), 3);

        // Without a purpose or names there is nothing to ask for.
        let der = super::request(&ed25519_pkcs8(3), &request(Purpose::None), &mut TestRng(0));
        let parsed = CertificationRequest::parse(&der.unwrap()).unwrap();
        assert_eq!(parsed.verify_signature(), Ok(true));
        assert!(parsed.info().attributes.is_empty());

        for key in [synthetic_pkcs8(&[1, 2, 3]), vec![1, 2, 3]] {
            assert_eq!(
                super::request(&key, &request(Purpose::None), &mut TestRng(0)),
                Err(UNSUPPORTED_KEY.into())
            );
        }
    }

    #[test]
    fn a_ca_certificate_is_read_as_one() {
        let der = self_signed(
            &ed25519_pkcs8(3),
            &request(Purpose::CertificateAuthority),
            NOW,
            &mut TestRng(0),
        )
        .unwrap();
        assert!(Certificate::parse(&der).unwrap().tbs().is_ca());
    }

    #[test]
    fn keys_sign_with_the_algorithm_of_their_type() {
        let ed448 = der::sequence(
            &[
                der::integer(&[0]),
                der::sequence(&der::oid(&object(oid::OID_ED448))),
                der::octet_string(&der::octet_string(&[5; 57])),
            ]
            .concat(),
        );
        let der = self_signed(&ed448, &request(Purpose::None), NOW, &mut TestRng(0)).unwrap();
        let parsed = Certificate::parse(&der).unwrap();
        assert_eq!(parsed.verify_signature(parsed.public_key()), Ok(true));
        assert!(parsed.extensions().len() == 1);

        // An X25519 key agrees on keys and cannot sign.
        let x25519 = der::sequence(
            &[
                der::integer(&[0]),
                der::sequence(&der::oid(&object(oid::OID_X25519))),
                der::octet_string(&der::octet_string(&[5; 32])),
            ]
            .concat(),
        );
        for key in [x25519, synthetic_pkcs8(&[1, 2, 3]), vec![1, 2, 3]] {
            assert_eq!(
                self_signed(&key, &request(Purpose::None), NOW, &mut TestRng(0)),
                Err(UNSUPPORTED_KEY.into())
            );
        }
    }
}
