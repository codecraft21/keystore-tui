use super::*;

pub(super) fn object_id(arcs: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::new(arcs).expect("static oid")
}

/// An `Attribute` with a single value.
pub(super) fn attribute(arcs: &[u64], value: &[u8]) -> Vec<u8> {
    der::sequence(&[der::oid(&object_id(arcs)), der::set(value)].concat())
}

/// The `friendlyName` attribute, a BMPString as PKCS #9 requires.
pub(super) fn friendly_name_attribute(alias: &str) -> Vec<u8> {
    let name: Vec<u8> = alias.encode_utf16().flat_map(u16::to_be_bytes).collect();
    let mut value = vec![0x1e];
    der::write_length(&mut value, name.len());
    value.extend(name);
    attribute(oid::OID_PKCS9_FRIENDLY_NAME, &value)
}

/// The bag `raw` with `alias` as its only friendly name. The bag's value
/// and other attributes keep their bytes.
pub(super) fn with_friendly_name(raw: &[u8], alias: &str) -> Result<Vec<u8>, CryptoError> {
    with_attribute(
        raw,
        oid::OID_PKCS9_FRIENDLY_NAME,
        friendly_name_attribute(alias),
    )
}

/// The bag `raw` with `attribute` as its only attribute of the type `arcs`.
/// The bag's value and other attributes keep their bytes.
pub(super) fn with_attribute(
    raw: &[u8],
    arcs: &[u64],
    attribute: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    let mut reader = Reader::new(raw);
    let mut bag = reader.read_sequence()?;
    let id = bag.read_raw_tlv()?;
    let value = bag.read_raw_tlv()?;
    let mut attributes = vec![attribute];
    if !bag.is_empty() {
        let mut set = bag.read_set()?;
        while !set.is_empty() {
            let attribute = set.read_raw_tlv()?;
            let replaced = Reader::new(attribute)
                .read_sequence()?
                .read_oid()?
                .matches(arcs);
            if !replaced {
                attributes.push(attribute.to_vec());
            }
        }
    }
    // DER orders the elements of a SET OF by their encoding.
    attributes.sort();
    Ok(der::sequence(
        &[id, value, &der::set(&attributes.concat())].concat(),
    ))
}

#[derive(Clone)]
pub(super) struct MetadataBag {
    metadata: SafeBag,
    pub(super) certificate_der: Option<Vec<u8>>,
    /// The bag as stored.
    pub(super) raw: Vec<u8>,
    /// The index of the safe the bag is stored in.
    pub(super) safe: usize,
}

impl std::ops::Deref for MetadataBag {
    type Target = SafeBag;
    fn deref(&self) -> &Self::Target {
        &self.metadata
    }
}

pub(super) fn parse_metadata_bag(raw: &[u8]) -> Result<Option<MetadataBag>, CryptoError> {
    let mut reader = Reader::new(raw);
    let mut bag = reader.read_sequence()?;
    let id = bag.read_oid()?;
    // Crown parses plaintext keyBag contents; Java PKCS12 uses shrouded key bags.
    if id.matches(oid::OID_PKCS12_KEY_BAG) || id.matches(oid::OID_PKCS12_SAFE_CONTENTS_BAG) {
        return Ok(None);
    }
    // Keep original DER and bag attributes even when a certificate or its
    // public-key algorithm cannot be decoded by crown. Keys stay opaque.
    if id.matches(oid::OID_PKCS12_CERT_BAG) {
        let mut value = bag.read_explicit(0)?;
        let mut cert_bag = value.read_sequence()?;
        if !cert_bag.read_oid()?.matches(oid::OID_X509_CERTIFICATE) {
            return Ok(None);
        }
        let mut cert_value = cert_bag.read_explicit(0)?;
        let certificate_der = cert_value.read_octet_string_owned()?;
        cert_value.expect_end()?;
        cert_bag.expect_end()?;
        value.expect_end()?;
        let attributes = if bag.is_empty() {
            vec![]
        } else {
            parse_attributes(&mut bag)?
        };
        bag.expect_end()?;
        reader.expect_end()?;
        return Ok(Some(MetadataBag {
            metadata: SafeBag {
                bag: Bag::Other {
                    oid: id,
                    value: vec![],
                },
                attributes,
            },
            certificate_der: Some(certificate_der),
            raw: raw.to_vec(),
            safe: 0,
        }));
    }
    let mut reader = Reader::new(raw);
    let bag = SafeBag::parse(&mut reader)?;
    reader.expect_end()?;
    Ok(Some(MetadataBag {
        metadata: bag,
        certificate_der: None,
        raw: raw.to_vec(),
        safe: 0,
    }))
}
