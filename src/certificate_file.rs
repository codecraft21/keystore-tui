//! Standalone certificate files: PEM or DER certificates, PKCS#7 bundles,
//! PKCS#10 certificate requests, and certificate revocation lists. Each
//! certificate, request, or list becomes one entry; a certificate's chain is assembled from the other certificates in
//! the same file by matching issuer and subject names.
use std::collections::HashMap;

use crown::{
    asn1::{Reader, der, oid, pem},
    error::CryptoError,
    pkcs7::ContentInfo,
    x509::name::Name,
};

use crate::{
    certificate::{self, Summary, details::MAX_CHAIN_DEPTH},
    certificate_request,
    keystore::{Content, KeystoreEntry, Kind},
    revocation_list,
};

/// File name extensions offered by the file browser alongside keystores.
pub const EXTENSIONS: &[&str] = &[
    "pem", "crt", "cer", "der", "p7b", "p7c", "csr", "p10", "crl",
];

pub struct CertificateFile {
    /// In file order.
    pub entries: Vec<KeystoreEntry>,
    /// Whether PEM blocks other than certificates and requests, such as
    /// private keys, were ignored.
    pub skipped: bool,
}

/// A certificate, request, or revocation list in file order, as exact DER.
enum Item {
    Certificate {
        der: Vec<u8>,
        /// Pre-parsed `(alias, summary)` when `single_der_item` already
        /// parsed this DER certificate.
        parsed: Option<(Option<String>, Summary)>,
    },
    Request {
        der: Vec<u8>,
        /// Pre-parsed `(alias, summary)` when `single_der_item` already
        /// parsed this DER request.
        parsed: Option<(Option<String>, Summary)>,
    },
    Crl {
        der: Vec<u8>,
        /// Pre-parsed issuer alias when `single_der_item` already parsed this
        /// DER revocation list.
        alias: Option<Option<String>>,
    },
}

impl Item {
    fn certificate(der: Vec<u8>) -> Self {
        Self::Certificate { der, parsed: None }
    }

    fn request(der: Vec<u8>) -> Self {
        Self::Request { der, parsed: None }
    }

    fn crl(der: Vec<u8>) -> Self {
        Self::Crl { der, alias: None }
    }
}

pub fn is_pem(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_ok_and(|text| {
        text.lines().any(|line| {
            line.trim_start_matches('\u{feff}')
                .trim_start()
                .starts_with("-----BEGIN ")
        })
    })
}

pub fn has_extension(path: &std::path::Path) -> bool {
    path.extension().is_some_and(|extension| {
        EXTENSIONS
            .iter()
            .any(|known| extension.eq_ignore_ascii_case(known))
    })
}

pub fn parse(data: &[u8]) -> Result<CertificateFile, &'static str> {
    let mut items = Vec::new();
    let mut skipped = false;
    if is_pem(data) {
        let text = std::str::from_utf8(data).map_err(|_| "PEM file is not valid UTF-8 text")?;
        for block in pem::parse(text).map_err(|_| "malformed PEM block")? {
            match block.label.as_str() {
                "CERTIFICATE" | "X509 CERTIFICATE" => items.push(Item::certificate(block.data)),
                // OpenSSL appends trust settings after the certificate.
                "TRUSTED CERTIFICATE" => items.push(Item::certificate(
                    Reader::new(&block.data)
                        .read_raw_tlv()
                        .map_err(|_| "malformed trusted certificate")?
                        .to_vec(),
                )),
                // Java's keytool writes the older "NEW" label.
                "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => {
                    items.push(Item::request(block.data))
                }
                "X509 CRL" => items.push(Item::crl(block.data)),
                "PKCS7" | "CMS" => items.extend(
                    pkcs7_certificates(&block.data)?
                        .into_iter()
                        .map(Item::certificate),
                ),
                _ => skipped = true,
            }
        }
    } else if let Some(item) = single_der_item(data) {
        items.push(item);
    } else {
        items = pkcs7_certificates(data)?
            .into_iter()
            .map(Item::certificate)
            .collect();
    }
    if items.is_empty() {
        return Err("the file contains no certificates or certificate requests");
    }
    Ok(CertificateFile {
        entries: entries(items),
        skipped,
    })
}

/// A certificate, request, or revocation list that is exactly one DER element.
fn single_der_item(data: &[u8]) -> Option<Item> {
    let tlv = Reader::new(data).read_raw_tlv().ok()?;
    if tlv.len() != data.len() {
        None
    } else if let Some(parsed) = certificate::summarize_full(data) {
        let alias = parsed
            .subject_name
            .as_ref()
            .and_then(certificate::name_alias);
        Some(Item::Certificate {
            der: data.to_vec(),
            parsed: Some((alias, parsed.summary)),
        })
    } else if let Some((summary, alias)) = certificate_request::summarize_with_alias(data) {
        Some(Item::Request {
            der: data.to_vec(),
            parsed: Some((alias, summary)),
        })
    } else if let Ok(issuer) = revocation_list::parse_issuer(data) {
        Some(Item::Crl {
            der: data.to_vec(),
            alias: Some(certificate::name_alias(&issuer)),
        })
    } else {
        None
    }
}

/// The X.509 certificates of a PKCS#7 SignedData, as exact DER.
fn pkcs7_certificates(data: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    let info = ContentInfo::parse(data)
        .map_err(|_| "not a certificate, certificate request, or PKCS#7 file")?;
    if !info.content_type.matches(oid::OID_PKCS7_SIGNED_DATA) {
        return Err("PKCS#7 content is not signed data");
    }
    let malformed = |_: CryptoError| "malformed PKCS#7 signed data";
    let mut reader = Reader::new(&info.content);
    let mut signed = reader.read_sequence().map_err(malformed)?;
    signed.read_raw_tlv().map_err(malformed)?; // Version.
    signed.read_raw_tlv().map_err(malformed)?; // Digest algorithms.
    signed.read_raw_tlv().map_err(malformed)?; // Encapsulated content.
    let mut certificates = Vec::new();
    if !signed.is_empty()
        && signed.peek_tag().map_err(malformed)? == der::Tag::context_constructed(0)
    {
        let mut set = signed.read_implicit_constructed(0).map_err(malformed)?;
        while !set.is_empty() {
            let raw = set.read_raw_tlv().map_err(malformed)?;
            // Attribute certificates use other tags and are not listed.
            if Reader::new(raw).peek_tag().map_err(malformed)? == der::SEQUENCE {
                certificates.push(raw.to_vec());
            }
        }
    }
    Ok(certificates)
}

/// Encodes `certificates` as a DER-encoded degenerate PKCS#7 SignedData:
/// `ContentInfo` holding `id-signedData` with version 1, empty digest
/// algorithms, `id-data` content info, `[0] IMPLICIT` `CertificateSet`
/// (when non-empty, in the given order, so a chain keeps its leaf first, as
/// OpenSSL and keytool write it), and empty signer infos.
pub fn encode_pkcs7<T: AsRef<[u8]>>(certificates: &[T]) -> Vec<u8> {
    let mut signed = Vec::new();
    signed.extend(der::integer_i64(1));
    signed.extend(der::set(&[]));
    signed.extend(der::sequence(&der::oid(
        &oid::ObjectIdentifier::new(oid::OID_PKCS7_DATA).expect("constant OID"),
    )));
    if !certificates.is_empty() {
        let mut concat = Vec::new();
        for cert in certificates {
            concat.extend_from_slice(cert.as_ref());
        }
        signed.extend(der::implicit(0, true, &concat));
    }
    signed.extend(der::set(&[]));
    ContentInfo {
        content_type: oid::ObjectIdentifier::new(oid::OID_PKCS7_SIGNED_DATA).expect("constant OID"),
        content: der::sequence(&signed),
    }
    .encode()
}

/// Comparable issuer and subject names, plus subject alias, for certificates
/// that could not be summarized (e.g. malformed SPKI or validity).
fn fallback_names(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Option<String>)> {
    let mut tbs = Reader::new(der)
        .read_sequence()
        .ok()?
        .read_sequence()
        .ok()?;
    if tbs.peek_tag().ok()? == der::Tag::context_constructed(0) {
        tbs.read_raw_tlv().ok()?; // Version.
    }
    tbs.read_raw_tlv().ok()?; // Serial number.
    tbs.read_raw_tlv().ok()?; // Signature algorithm.
    let issuer = tbs.read_raw_tlv().ok()?;
    tbs.read_raw_tlv().ok()?; // Validity.
    let subject = tbs.read_raw_tlv().ok()?;
    let subject_name = Name::parse(&mut Reader::new(subject)).ok();
    let alias = subject_name.as_ref().and_then(certificate::name_alias);
    Some((
        name_key(issuer),
        name_key_from(subject_name.as_ref(), subject),
        alias,
    ))
}

/// The decoded name ignoring case, so the same name matches across string
/// encodings; the raw DER when it cannot be decoded.
fn name_key(raw: &[u8]) -> Vec<u8> {
    let parsed = Name::parse(&mut Reader::new(raw)).ok();
    name_key_from(parsed.as_ref(), raw)
}

fn name_key_from(parsed: Option<&Name>, raw: &[u8]) -> Vec<u8> {
    parsed.map_or_else(
        || raw.to_vec(),
        |name| name.to_string().to_lowercase().into_bytes(),
    )
}

struct ParsedCert {
    names: Option<(Vec<u8>, Vec<u8>)>,
    alias: Option<String>,
    summary: Option<Summary>,
}

fn entries(mut items: Vec<Item>) -> Vec<KeystoreEntry> {
    // Requests and revocation lists have no issuer chain.
    let mut certs: Vec<Option<ParsedCert>> = items
        .iter_mut()
        .map(|item| match item {
            Item::Certificate { der, parsed } => {
                Some(if let Some((alias, summary)) = parsed.take() {
                    // Pre-parsed certificates only come from single_der_item, so
                    // there are no other certificates to link into a chain.
                    ParsedCert {
                        names: None,
                        alias,
                        summary: Some(summary),
                    }
                } else if let Some(info) = certificate::summarize_full(der) {
                    let alias = info.subject_name.as_ref().and_then(certificate::name_alias);
                    let subject_key = name_key_from(info.subject_name.as_ref(), info.subject);
                    ParsedCert {
                        names: Some((name_key(info.issuer), subject_key)),
                        alias,
                        summary: Some(info.summary),
                    }
                } else {
                    let (names, alias) = match fallback_names(der) {
                        Some((issuer, subject, alias)) => (Some((issuer, subject)), alias),
                        None => (None, None),
                    };
                    ParsedCert {
                        names,
                        alias,
                        summary: None,
                    }
                })
            }
            Item::Request { .. } | Item::Crl { .. } => None,
        })
        .collect();
    let mut by_subject: HashMap<&[u8], Vec<usize>> = HashMap::new();
    for (index, entry) in certs.iter().enumerate() {
        if let Some(ParsedCert {
            names: Some((_, subject)),
            ..
        }) = entry
        {
            by_subject
                .entry(subject.as_slice())
                .or_default()
                .push(index);
        }
    }
    let der = |index: usize| match &items[index] {
        Item::Certificate { der, .. } | Item::Request { der, .. } | Item::Crl { der, .. } => der,
    };
    // Certificates may appear in several chains, so their entries copy them;
    // requests and revocation lists are then moved into theirs.
    let chain_indices: Vec<_> = (0..items.len())
        .map(|index| {
            let Some(ParsedCert { names, .. }) = &certs[index] else {
                return None;
            };
            // Follow issuers through the file, stopping at a self-issued
            // certificate, a missing issuer, a certificate already used, or
            // MAX_CHAIN_DEPTH.
            let mut chain = vec![index];
            let mut chain_warning = None;
            if names.is_some() {
                while let Some(ParsedCert {
                    names: Some((issuer, subject)),
                    ..
                }) = &certs[chain[chain.len() - 1]]
                    && issuer != subject
                    && let Some(next) = by_subject.get(issuer.as_slice()).and_then(|candidates| {
                        candidates.iter().copied().find(|c| !chain.contains(c))
                    })
                {
                    if chain.len() >= MAX_CHAIN_DEPTH {
                        chain_warning = Some("Certificate chain exceeds the maximum depth.");
                        break;
                    }
                    chain.push(next);
                }
            }
            let certificates: Vec<Vec<u8>> = chain.iter().map(|&i| der(i).clone()).collect();
            Some((certificates, chain_warning))
        })
        .collect();
    items
        .into_iter()
        .zip(chain_indices)
        .enumerate()
        .map(|(index, (item, chain))| match item {
            Item::Certificate { .. } => {
                let (certificates, chain_warning) =
                    chain.expect("every certificate has a chain entry");
                let parsed = certs[index]
                    .take()
                    .expect("every certificate has parsed metadata");
                KeystoreEntry {
                    alias: parsed
                        .alias
                        .unwrap_or_else(|| format!("Certificate {}", index + 1)),
                    certificate: parsed.summary,
                    content: Content::Certificates {
                        kind: Kind::Certificate,
                        certificates,
                    },
                    chain_warning,
                }
            }
            Item::Request { der, parsed } => {
                let (alias, summary) = match parsed {
                    Some((alias, summary)) => (alias, Some(summary)),
                    None => match certificate_request::summarize_with_alias(&der) {
                        Some((summary, alias)) => (alias, Some(summary)),
                        None => (certificate_request::subject_name(&der), None),
                    },
                };
                KeystoreEntry {
                    alias: alias.unwrap_or_else(|| format!("Certificate request {}", index + 1)),
                    certificate: summary,
                    content: Content::Request(der),
                    chain_warning: None,
                }
            }
            Item::Crl { der, alias } => {
                let alias = alias.unwrap_or_else(|| revocation_list::issuer_name(&der));
                KeystoreEntry {
                    alias: alias.unwrap_or_else(|| format!("Revocation list {}", index + 1)),
                    certificate: None,
                    content: Content::Crl(der),
                    chain_warning: None,
                }
            }
        })
        .collect()
}

/// The subject common name, else the whole subject, if either is non-empty.
pub fn subject_name(der: &[u8]) -> Option<String> {
    let mut reader = Reader::new(der);
    let mut certificate = reader.read_sequence().ok()?;
    reader.expect_end().ok()?;
    let mut tbs = certificate.read_sequence().ok()?;
    if tbs.peek_tag().ok()? == der::Tag::context_constructed(0) {
        tbs.read_raw_tlv().ok()?; // Version.
    }
    tbs.read_expected(der::INTEGER).ok()?; // Serial number.
    tbs.read_sequence().ok()?; // Signature algorithm.
    tbs.read_sequence().ok()?; // Issuer.
    tbs.read_sequence().ok()?; // Validity.
    let subject = Name::parse(&mut tbs).ok()?;
    certificate::name_alias(&subject)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{fixture_certificate_der, metadata_certificate};

    fn aliases(file: &CertificateFile) -> Vec<&str> {
        file.entries
            .iter()
            .map(|entry| entry.alias.as_str())
            .collect()
    }

    #[test]
    fn reads_a_der_certificate() {
        let file = parse(fixture_certificate_der()).unwrap();
        assert_eq!(file.entries.len(), 1);
        assert!(!file.skipped);
        let entry = &file.entries[0];
        assert_eq!(entry.kind(), "Certificate");
        assert_eq!(entry.certificates(), [fixture_certificate_der()]);
        assert!(entry.certificate.is_some());
    }

    #[test]
    fn pem_bundles_keep_file_order_link_chains_and_skip_other_blocks() {
        let root = metadata_certificate("root", "root", &[1], &[]);
        let intermediate = metadata_certificate("intermediate", "root", &[2], &[]);
        let leaf = metadata_certificate("leaf", "intermediate", &[3], &[]);
        let text = [
            pem::encode("CERTIFICATE", &leaf),
            "comment between blocks\n".into(),
            pem::encode("PRIVATE KEY", b"synthetic, not a key"),
            pem::encode("CERTIFICATE", &root),
            pem::encode("CERTIFICATE", &intermediate),
        ]
        .concat();
        let file = parse(text.as_bytes()).unwrap();
        assert!(file.skipped);
        assert_eq!(aliases(&file), ["leaf", "root", "intermediate"]);
        assert_eq!(
            file.entries[0].certificates(),
            [leaf, intermediate.clone(), root.clone()]
        );
        assert_eq!(file.entries[1].certificates(), std::slice::from_ref(&root));
        assert_eq!(file.entries[2].certificates(), [intermediate, root]);
    }

    #[test]
    fn issuer_cycles_and_unreadable_certificates_do_not_loop() {
        let a = metadata_certificate("a", "b", &[1], &[]);
        let b = metadata_certificate("b", "a", &[2], &[]);
        let text = [
            pem::encode("CERTIFICATE", &a),
            pem::encode("CERTIFICATE", &b),
            pem::encode("CERTIFICATE", b"unreadable"),
        ]
        .concat();
        let file = parse(text.as_bytes()).unwrap();
        assert_eq!(aliases(&file), ["a", "b", "Certificate 3"]);
        assert_eq!(file.entries[0].certificates(), [a.clone(), b.clone()]);
        assert_eq!(file.entries[1].certificates(), [b, a]);
        assert_eq!(file.entries[2].certificates(), [b"unreadable".to_vec()]);
        assert!(file.entries[2].certificate.is_none());
    }

    #[test]
    fn reads_der_and_pem_pkcs7_bundles() {
        let root = metadata_certificate("root", "root", &[1], &[]);
        let leaf = metadata_certificate("leaf", "root", &[2], &[]);
        let bundle = encode_pkcs7(&[leaf.clone(), root.clone()]);
        // The certificates keep the given order, leaf first.
        assert_eq!(
            pkcs7_certificates(&bundle).unwrap(),
            [leaf.clone(), root.clone()]
        );
        assert_eq!(
            pkcs7_certificates(&encode_pkcs7(&[root.clone(), leaf.clone()])).unwrap(),
            [root.clone(), leaf.clone()]
        );
        for data in [bundle.clone(), pem::encode("PKCS7", &bundle).into_bytes()] {
            let file = parse(&data).unwrap();
            assert_eq!(aliases(&file), ["leaf", "root"]);
            assert_eq!(file.entries[0].certificates(), [leaf.clone(), root.clone()]);
        }
    }

    #[test]
    fn revocation_lists_are_listed_in_file_order_outside_chains() {
        use crate::test_support::{TestRng, ed25519_certificate, ed25519_crl, ed25519_pkcs8};
        let list = ed25519_crl();
        let ca = ed25519_certificate("ca", "ca", 9, 9);
        let text = [
            pem::encode("X509 CRL", &list),
            pem::encode("CERTIFICATE", &ca),
        ]
        .concat();
        let file = parse(text.as_bytes()).unwrap();
        assert!(!file.skipped);
        assert_eq!(aliases(&file), ["ca", "ca"]);
        assert_eq!(file.entries[0].kind(), revocation_list::KIND);
        assert_eq!(file.entries[0].content, Content::Crl(list.clone()));
        assert!(file.entries[0].certificate.is_none());
        assert!(file.entries[0].certificates().is_empty());
        assert_eq!(file.entries[1].certificates(), [ca]);
        // DER is recognized by its content, and a list without an issuer
        // name is named by its place.
        let file = parse(&list).unwrap();
        assert_eq!(file.entries[0].content, Content::Crl(list));
        let empty = crate::signing::Revocations {
            this_update: crown::asn1::Asn1Time::from_unix(0, true),
            next_update: crown::asn1::Asn1Time::from_unix(1, true),
            number: 1,
            revoked: Vec::new(),
        };
        let issuer = crate::signing::Issuer {
            key: &ed25519_pkcs8(9),
            certificate: &ed25519_certificate("", "", 9, 9),
        };
        let unnamed = crate::signing::revocation_list(&empty, &issuer, &mut TestRng(0)).unwrap();
        assert_eq!(aliases(&parse(&unnamed).unwrap()), ["Revocation list 1"]);
    }

    #[test]
    fn requests_are_listed_in_file_order_outside_chains() {
        use crate::test_support::{KEYTOOL_REQUEST, OPENSSL_REQUEST_DER, ed25519_request};
        let root = metadata_certificate("root", "root", &[1], &[]);
        let request = ed25519_request("root", &[]);
        let unnamed = ed25519_request("", &[]);
        let text = [
            pem::encode("CERTIFICATE REQUEST", &request),
            pem::encode("CERTIFICATE", &root),
            pem::encode("NEW CERTIFICATE REQUEST", &unnamed),
        ]
        .concat();
        let file = parse(text.as_bytes()).unwrap();
        assert!(!file.skipped);
        assert_eq!(aliases(&file), ["root", "root", "Certificate request 3"]);
        let kinds: Vec<_> = file.entries.iter().map(KeystoreEntry::kind).collect();
        assert_eq!(
            kinds,
            [
                certificate_request::KIND,
                "Certificate",
                certificate_request::KIND
            ]
        );
        assert_eq!(file.entries[0].content, Content::Request(request.clone()));
        assert_eq!(
            file.entries[0].certificate.as_ref().unwrap().algorithm,
            "Ed25519"
        );
        assert_eq!(file.entries[1].certificates(), [root]);

        let keytool = parse(KEYTOOL_REQUEST).unwrap();
        assert_eq!(aliases(&keytool), ["CSR TUI test fixture"]);
        let openssl = parse(OPENSSL_REQUEST_DER).unwrap();
        assert_eq!(aliases(&openssl), ["OpenSSL CSR fixture"]);
        assert_eq!(
            openssl.entries[0].content,
            Content::Request(OPENSSL_REQUEST_DER.to_vec())
        );
    }

    #[test]
    fn binary_der_containing_pem_marker_is_not_misclassified_as_pem() {
        let cert = metadata_certificate("-----BEGIN CERTIFICATE-----\nspoof", "ca", &[0x80], &[]);
        assert!(!is_pem(&cert));
        let file = parse(&cert).unwrap();
        assert_eq!(file.entries.len(), 1);
        assert_eq!(file.entries[0].certificates(), [cert]);
        assert_eq!(
            file.entries[0].alias,
            "-----BEGIN CERTIFICATE-----\\u{a}spoof"
        );
    }

    #[test]
    fn rejects_files_without_certificates() {
        assert!(parse(&encode_pkcs7::<&[u8]>(&[])).is_err());
        assert!(parse(pem::encode("PRIVATE KEY", b"synthetic").as_bytes()).is_err());
        assert!(parse(b"-----BEGIN CERTIFICATE-----\nnot base64!\n").is_err());
        assert!(parse(b"\x30\x03\x02\x01\x01").is_err());
        let mut trailing = fixture_certificate_der().to_vec();
        trailing.push(0);
        assert!(parse(&trailing).is_err());
    }

    #[test]
    fn caps_deep_chains_at_max_depth() {
        let total = MAX_CHAIN_DEPTH + 4;
        let certs: Vec<Vec<u8>> = (0..total)
            .map(|i| {
                let subject = format!("c{i}");
                let issuer = if i + 1 == total {
                    subject.clone()
                } else {
                    format!("c{}", i + 1)
                };
                metadata_certificate(&subject, &issuer, &[(i + 1) as u8], &[])
            })
            .collect();
        let text: String = certs
            .iter()
            .map(|der| pem::encode("CERTIFICATE", der))
            .collect();
        let file = parse(text.as_bytes()).unwrap();
        assert_eq!(file.entries.len(), total);
        assert_eq!(file.entries[0].certificates().len(), MAX_CHAIN_DEPTH);
        assert_eq!(
            file.entries[0].chain_warning,
            Some("Certificate chain exceeds the maximum depth.")
        );
        let exact = &file.entries[total - MAX_CHAIN_DEPTH];
        assert_eq!(exact.certificates().len(), MAX_CHAIN_DEPTH);
        assert_eq!(exact.chain_warning, None);
    }

    #[test]
    fn subject_name_reads_only_subject_tlv_and_rejects_non_certificates() {
        use crate::test_support::{OPENSSL_REQUEST_DER, ed25519_crl};

        let cert = metadata_certificate("leaf", "ca", &[1], &[]);
        assert_eq!(subject_name(&cert).as_deref(), Some("leaf"));

        // Trailing bytes, truncated input, CSR, CRL, and empty subject return None.
        let mut trailing = cert.clone();
        trailing.push(0);
        assert_eq!(subject_name(&trailing), None);
        assert_eq!(subject_name(&cert[..cert.len() - 1]), None);
        assert_eq!(subject_name(OPENSSL_REQUEST_DER), None);
        assert_eq!(subject_name(&ed25519_crl()), None);
        let empty = metadata_certificate("", "ca", &[1], &[]);
        assert_eq!(subject_name(&empty), None);

        // A PEM certificate whose SPKI is unreadable still links into a chain
        // and uses its subject name as alias via fallback_names.
        let ca = metadata_certificate("ca", "ca", &[1], &[]);
        let sig = der::sequence(&der::oid(
            &oid::ObjectIdentifier::new(oid::OID_ED25519).unwrap(),
        ));
        let bad_spki_tbs = der::sequence(
            &[
                der::integer_i64(2),
                sig.clone(),
                Name::from_common_name("ca").encode(),
                der::sequence(&[]), // Invalid validity so summarize_full returns None.
                Name::from_common_name("broken-leaf").encode(),
                der::sequence(&[]),
            ]
            .concat(),
        );
        let bad_cert = der::sequence(&[bad_spki_tbs, sig, der::bit_string(0, &[0])].concat());
        assert!(certificate::summarize(&bad_cert).is_none());
        let pem = [
            pem::encode("CERTIFICATE", &bad_cert),
            pem::encode("CERTIFICATE", &ca),
        ]
        .concat();
        let file = parse(pem.as_bytes()).unwrap();
        assert_eq!(aliases(&file), ["broken-leaf", "ca"]);
        assert!(file.entries[0].certificate.is_none());
        assert_eq!(file.entries[0].certificates(), [bad_cert, ca]);
    }
}
