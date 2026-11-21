//! X.509 certificate revocation lists (CRLs), read for display only. Whether
//! a list is current or trusted is not checked.
use crown::{
    asn1::{Asn1Time, Reader, der},
    error::{CryptoError, CryptoResult},
    x509::{algorithm::AlgorithmIdentifier, name::Name},
};

use crate::certificate::{
    details::{serial_text, signature_name},
    extensions::Extension,
    name_alias,
};

pub const KIND: &str = "Revocation list";

/// The PEM label of a revocation list.
pub const PEM_LABEL: &str = "X509 CRL";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct List {
    pub version: i64,
    pub issuer: Name,
    pub this_update: Asn1Time,
    pub next_update: Option<Asn1Time>,
    pub signature_algorithm: String,
    /// The list's own extensions, such as its number.
    pub extensions: Vec<Extension>,
    /// The revoked certificates, in list order.
    pub revoked: Vec<Revoked>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revoked {
    /// The serial number in hex, as certificates show theirs.
    pub serial: String,
    pub date: Asn1Time,
    /// The entry's extensions, such as the reason.
    pub extensions: Vec<Extension>,
}

impl List {
    pub fn parse(encoding: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(encoding);
        let mut list = reader.read_sequence()?;
        reader.expect_end()?;
        let mut tbs = list.read_sequence()?;
        let signature_algorithm = signature_name(&AlgorithmIdentifier::parse(&mut list)?.oid);
        list.read_bit_string()?;
        list.expect_end()?;

        // The stored value plus one, as for certificates; omitted means v1.
        let version = if !tbs.is_empty() && tbs.peek_tag()? == der::INTEGER {
            tbs.read_integer_i64()?
                .checked_add(1)
                .ok_or(CryptoError::StrError("invalid revocation list version"))?
        } else {
            1
        };
        AlgorithmIdentifier::parse(&mut tbs)?;
        let issuer = Name::parse(&mut tbs)?;
        let this_update = tbs.read_time()?;
        let next_update = if !tbs.is_empty()
            && matches!(tbs.peek_tag()?, der::UTC_TIME | der::GENERALIZED_TIME)
        {
            Some(tbs.read_time()?)
        } else {
            None
        };
        let mut revoked = Vec::new();
        if !tbs.is_empty() && tbs.peek_tag()? == der::SEQUENCE {
            let mut entries = tbs.read_sequence()?;
            while !entries.is_empty() {
                let mut entry = entries.read_sequence()?;
                let serial = entry.read_expected(der::INTEGER)?;
                if serial.is_empty() {
                    return Err(CryptoError::StrError("empty revoked certificate serial"));
                }
                let date = entry.read_time()?;
                let mut entry_extensions = Vec::new();
                if !entry.is_empty() {
                    let mut exts = entry.read_sequence()?;
                    while !exts.is_empty() {
                        // A malformed extension is described, not fatal to the list.
                        entry_extensions.push(Extension::parse(exts.read_raw_tlv()?));
                    }
                }
                entry.expect_end()?;
                revoked.push(Revoked {
                    serial: serial_text(serial, true),
                    date,
                    extensions: entry_extensions,
                });
            }
        }
        let mut extensions = Vec::new();
        if !tbs.is_empty() && tbs.peek_tag()? == der::Tag::context_constructed(0) {
            let mut explicit = tbs.read_explicit(0)?;
            let mut exts = explicit.read_sequence()?;
            explicit.expect_end()?;
            while !exts.is_empty() {
                // A malformed extension is described, not fatal to the list.
                extensions.push(Extension::parse(exts.read_raw_tlv()?));
            }
        }
        tbs.expect_end()?;
        Ok(Self {
            version,
            issuer,
            this_update,
            next_update,
            signature_algorithm,
            extensions,
            revoked,
        })
    }
}

/// The issuer's common name, else its whole name, if either is non-empty.
pub fn issuer_name(encoding: &[u8]) -> Option<String> {
    List::parse(encoding)
        .ok()
        .and_then(|list| name_alias(&list.issuer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{certificate::details::time_text, test_support::ed25519_crl};

    #[test]
    fn a_list_shows_its_issuer_updates_number_and_revoked_serials() {
        let der = ed25519_crl();
        let list = List::parse(&der).unwrap();
        assert_eq!(list.version, 2);
        assert_eq!(list.issuer.to_string(), "CN=ca");
        assert_eq!(time_text(&list.this_update), "2026-01-01 00:00:00 UTC");
        assert_eq!(
            list.next_update.as_ref().map(time_text).as_deref(),
            Some("2026-01-31 00:00:00 UTC")
        );
        assert_eq!(list.signature_algorithm, "Ed25519");
        let shown: Vec<_> = list
            .extensions
            .iter()
            .map(|extension| (extension.title(), extension.lines.clone()))
            .collect();
        assert_eq!(shown[0].0, "Authority Key Identifier (2.5.29.35)");
        assert_eq!(
            shown[1],
            ("CRL Number (2.5.29.20)".into(), vec!["7".into()])
        );
        assert_eq!(list.revoked.len(), 2);
        assert_eq!(list.revoked[0].serial, "0x01A4");
        assert_eq!(list.revoked[0].date, list.this_update);
        assert_eq!(
            list.revoked[0].extensions[0].title(),
            "Reason Code (2.5.29.21)"
        );
        assert_eq!(list.revoked[0].extensions[0].lines, ["keyCompromise"]);
        assert_eq!(list.revoked[1].serial, "0x0F");
        assert!(list.revoked[1].extensions.is_empty());
        assert_eq!(issuer_name(&der).as_deref(), Some("ca"));
        assert_eq!(issuer_name(b"junk"), None);
        assert!(List::parse(&der[..der.len() - 1]).is_err());
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(List::parse(&trailing).is_err());
    }

    #[test]
    fn parses_minimal_v1_crl_and_tolerates_malformed_extensions_and_negative_serials() {
        use crown::asn1::oid::{self, ObjectIdentifier};

        let ed25519 =
            der::algorithm_identifier(&ObjectIdentifier::new(oid::OID_ED25519).unwrap(), None);
        let sha256_ecdsa = der::algorithm_identifier(
            &ObjectIdentifier::new(oid::OID_ECDSA_WITH_SHA256).unwrap(),
            None,
        );
        let this_update = Asn1Time::new(2026, 1, 1, 0, 0, 0, true).unwrap();

        // Minimal v1 CRL: omits version, nextUpdate, revokedCertificates, and crlExtensions.
        let minimal_tbs = der::sequence(
            &[
                ed25519.clone(),
                Name::from_common_name("minimal-ca").encode(),
                der::time(&this_update),
            ]
            .concat(),
        );
        let minimal =
            der::sequence(&[minimal_tbs, ed25519.clone(), der::bit_string(0, &[1, 2, 3])].concat());
        let parsed = List::parse(&minimal).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.issuer.to_string(), "CN=minimal-ca");
        assert_eq!(parsed.this_update, this_update);
        assert_eq!(parsed.next_update, None);
        assert_eq!(parsed.signature_algorithm, "Ed25519");
        assert!(parsed.revoked.is_empty());
        assert!(parsed.extensions.is_empty());

        // v2 CRL with negative revoked serial, malformed entry & CRL extensions,
        // and outer signatureAlgorithm differing from inner TBS signature.
        let malformed_ext = der::sequence(&der::null());
        let revoked_entry = der::sequence(
            &[
                der::tlv(der::INTEGER, &[0xff]), // Negative serial -1.
                der::time(&this_update),
                der::sequence(&malformed_ext),
            ]
            .concat(),
        );
        let tbs = der::sequence(
            &[
                der::integer_i64(1), // v2
                ed25519,             // inner signature
                Name::from_common_name("ca").encode(),
                der::time(&this_update),
                der::sequence(&revoked_entry),
                der::explicit(0, &der::sequence(&malformed_ext)),
            ]
            .concat(),
        );
        let crl = der::sequence(&[tbs, sha256_ecdsa, der::bit_string(0, &[1, 2, 3])].concat());
        let parsed = List::parse(&crl).unwrap();
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.signature_algorithm, "SHA-256 with ECDSA");
        assert_eq!(parsed.revoked.len(), 1);
        assert_eq!(parsed.revoked[0].serial, "-0x01");
        assert_eq!(
            parsed.revoked[0].extensions[0].title(),
            "Malformed extension"
        );
        assert_eq!(parsed.extensions[0].title(), "Malformed extension");
    }
}
