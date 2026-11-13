//! X.509 certificate revocation lists (CRLs), read for display only. Whether
//! a list is current or trusted is not checked.
use crown::{
    asn1::Asn1Time,
    error::CryptoResult,
    x509::{crl::CertificateList, name::Name},
};

use crate::certificate::{
    details::{serial_hex, signature_name},
    extensions::Extension,
    name_alias,
};

pub const KIND: &str = "Revocation list";

/// The PEM label of a revocation list.
pub const PEM_LABEL: &str = "X509 CRL";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct List {
    pub version: u8,
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
        let list = CertificateList::parse(encoding)?;
        let tbs = list.tbs();
        let shown = |extensions: &[crown::x509::extensions::Extension]| {
            extensions
                .iter()
                .map(|extension| Extension::parse(&extension.encode()))
                .collect()
        };
        Ok(Self {
            // The stored value plus one, as for certificates; none is 1.
            version: tbs.version.map_or(1, |version| version.saturating_add(1)),
            issuer: tbs.issuer.clone(),
            this_update: tbs.this_update,
            next_update: tbs.next_update,
            signature_algorithm: signature_name(&tbs.signature.oid),
            extensions: shown(&tbs.extensions),
            revoked: tbs
                .revoked_certificates
                .iter()
                .map(|entry| Revoked {
                    serial: serial_hex(&entry.serial_number),
                    date: entry.revocation_date,
                    extensions: shown(&entry.extensions),
                })
                .collect(),
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
    }
}
