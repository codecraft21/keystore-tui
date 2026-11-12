//! Building certificates signed with a PKCS #8 private key: the subject
//! name, the extensions of a purpose, and a self-signed certificate.
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
        cert::CertificateBuilder,
        extensions::{
            BasicConstraints, ExtendedKeyUsage, Extension, GeneralName, KeyUsage,
            encode_general_names,
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

/// What a self-signed certificate holds besides its key.
pub struct Request {
    pub subject: Name,
    /// How many days the certificate is valid, from now.
    pub days: u32,
    pub names: Vec<GeneralName>,
    pub purpose: Purpose,
}

/// The DER of a certificate for the PKCS #8 private key `key`, signed with
/// that key and valid from `now`, in seconds since the Unix epoch.
pub fn self_signed(
    key: &[u8],
    request: &Request,
    now: i64,
    rng: &mut impl Rng,
) -> Result<Vec<u8>, String> {
    let key = PrivateKeyInfo::parse(key)
        .and_then(|info| info.decode())
        .map_err(|_| UNSUPPORTED_KEY)?;
    let algorithm = signature_algorithm(&key)?;
    let public = key
        .public_key()
        .and_then(|public| SubjectPublicKeyInfo::from_public_key(&public))
        .map_err(|_| UNSUPPORTED_KEY)?;
    let identifier = public.key_identifier().map_err(|_| UNSUPPORTED_KEY)?;
    let mut builder = CertificateBuilder::new(request.subject.clone(), public, algorithm)
        .serial(serial(rng))
        .validity(
            Asn1Time::from_unix(now, true),
            Asn1Time::from_unix(now + i64::from(request.days) * 86_400, true),
        )
        .extension(Extension::new(
            object(oid::OID_SUBJECT_KEY_IDENTIFIER),
            false,
            der::octet_string(&identifier),
        ));
    for extension in request
        .purpose
        .extensions(matches!(key, PrivateKey::Rsa(_)))
    {
        builder = builder.extension(extension);
    }
    if !request.names.is_empty() {
        builder = builder.extension(Extension::new(
            object(oid::OID_SUBJECT_ALT_NAME),
            false,
            encode_general_names(&request.names),
        ));
    }
    builder
        .sign(&key, rng)
        .map(|certificate| certificate.encode())
        .map_err(|error| format!("The certificate could not be signed: {error}."))
}

#[cfg(test)]
mod tests {
    use crown::x509::cert::Certificate;

    use super::*;
    use crate::{
        certificate,
        test_support::{TestRng, ed25519_pkcs8, synthetic_pkcs8},
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
