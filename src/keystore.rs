use std::{fmt, ops::Range};

use sha1::{Digest, Sha1};
use zeroize::Zeroize;

use crate::{
    certificate::{self, Summary},
    certificate_request, java_serialization,
};

pub(crate) const MAGIC: u32 = 0xfeed_feed;
/// JCEKS shares the JKS layout and digest, and adds secret-key entries.
pub(crate) const JCEKS_MAGIC: u32 = 0xcece_cece;
pub(crate) const VERSION_01: u32 = 1;
pub(crate) const VERSION_02: u32 = 2;
pub(crate) const PRIVATE_KEY_TAG: u32 = 1;
pub(crate) const TRUSTED_CERT_TAG: u32 = 2;
pub(crate) const SECRET_KEY_TAG: u32 = 3;
/// The class Java seals JCEKS secret keys in.
const SEALED_KEY_CLASS: &[u8] = b"com.sun.crypto.provider.SealedObjectForKeyProtector";
/// Java appends this to the password before hashing the keystore body.
const WHITENER_MESSAGE: &[u8] = b"Mighty Aphrodite";

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidMagic,
    UnknownVersion(u32),
    UnknownEntryTag(u32),
    Truncated,
    Invalid(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => f.write_str("not a JKS or JCEKS file (bad magic number)"),
            Self::UnknownVersion(version) => write!(f, "unsupported keystore version {version}"),
            Self::UnknownEntryTag(tag) => write!(f, "unknown entry tag {tag}"),
            Self::Truncated => f.write_str("truncated keystore data"),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, PartialEq, Eq)]
pub struct KeystoreEntry {
    pub alias: String,
    /// The entry's certificate, the first of a private key's chain, or a
    /// certificate request's subject and key.
    pub certificate: Option<Summary>,
    pub content: Content,
    pub chain_warning: Option<&'static str>,
}

/// What an entry stores. A certificate request's type follows from its
/// content, so no other entry can claim to be one.
#[derive(Debug, PartialEq, Eq)]
pub enum Content {
    Certificates {
        kind: Kind,
        /// Original DER in leaf-first stored order, including unreadable
        /// certificates. Empty for a secret key or a key without a chain.
        certificates: Vec<Vec<u8>>,
    },
    /// A PKCS#10 certificate request's DER.
    Request(Vec<u8>),
}

/// The type of an entry that stores certificates (or none, for a secret key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    PrivateKey,
    TrustedCertificate,
    SecretKey,
    /// A certificate from a certificate file, or a PKCS12 certificate
    /// without Java's trusted-certificate attribute.
    Certificate,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Self::PrivateKey => "Private key",
            Self::TrustedCertificate => "Trusted certificate",
            Self::SecretKey => "Secret key",
            Self::Certificate => "Certificate",
        }
    }
}

impl KeystoreEntry {
    /// The entry's type, as shown.
    pub fn kind(&self) -> &'static str {
        match &self.content {
            Content::Certificates { kind, .. } => kind.label(),
            Content::Request(_) => certificate_request::KIND,
        }
    }

    /// The stored certificates; a certificate request stores none.
    pub fn certificates(&self) -> &[Vec<u8>] {
        match &self.content {
            Content::Certificates { certificates, .. } => certificates,
            Content::Request(_) => &[],
        }
    }
}

/// A structurally valid keystore whose integrity digest has not been checked.
/// Parse once, then call `verify` for each password attempt. Entries are only
/// reachable through a successful `verify`.
pub struct Keystore {
    data: Vec<u8>,
    body_len: usize,
    entries: Vec<KeystoreEntry>,
    /// Where each of `entries` is stored in `data`, in the same order.
    spans: Vec<Range<usize>>,
}

/// A verified keystore's entries as stored, for writing it back. Each entry
/// keeps its original bytes, so protected keys, timestamps, and aliases are
/// written exactly as they were read, and keys stay encrypted throughout.
pub struct Writable {
    /// The magic number and version.
    header: [u8; 8],
    /// Each listed entry's offset in the file it was read from, and its
    /// bytes, in listing order.
    entries: Vec<(usize, Vec<u8>)>,
}

impl Writable {
    /// Removes the entry listed at `index`.
    pub fn remove(&mut self, index: usize) {
        self.entries.remove(index);
    }

    /// Gives the entry listed at `index` another alias and lists it at `to`.
    /// The rest of the entry, and its place in the file, stay as they were.
    pub fn rename(&mut self, index: usize, alias: &str, to: usize) -> Result<(), Error> {
        let alias = encode_string(alias)?;
        let (offset, entry) = self.entries.remove(index);
        // An entry starts with its tag, then the alias and its length.
        let old_len = usize::from(u16::from_be_bytes([entry[4], entry[5]]));
        let renamed = [&entry[..4], &alias, &entry[6 + old_len..]].concat();
        self.entries.insert(to, (offset, renamed));
        Ok(())
    }

    /// Adds a trusted certificate, listed at `to` and stored after every
    /// other entry. `created` is in milliseconds since the Unix epoch.
    pub fn insert_trusted_certificate(
        &mut self,
        to: usize,
        alias: &str,
        certificate: &[u8],
        created: u64,
    ) -> Result<(), Error> {
        let length = u32::try_from(certificate.len())
            .map_err(|_| Error::Invalid("the certificate is too large for a keystore"))?;
        let mut entry = TRUSTED_CERT_TAG.to_be_bytes().to_vec();
        entry.extend(encode_string(alias)?);
        entry.extend_from_slice(&created.to_be_bytes());
        if self.header[4..] == VERSION_02.to_be_bytes() {
            entry.extend(encode_string(CERTIFICATE_TYPE)?);
        }
        entry.extend_from_slice(&length.to_be_bytes());
        entry.extend_from_slice(certificate);
        let offset = self
            .entries
            .iter()
            .map(|(offset, _)| offset + 1)
            .max()
            .unwrap_or(0);
        self.entries.insert(to, (offset, entry));
        Ok(())
    }

    /// The keystore file: the entries in their stored order, followed by the
    /// integrity digest for `password`.
    pub fn encode(&self, password: &str) -> Vec<u8> {
        let mut stored: Vec<_> = self.entries.iter().collect();
        stored.sort_by_key(|(offset, _)| *offset);
        let mut data = self.header.to_vec();
        data.extend_from_slice(&(stored.len() as u32).to_be_bytes());
        for (_, entry) in stored {
            data.extend_from_slice(entry);
        }
        let digest = digest_of(password, &data);
        data.extend_from_slice(&digest);
        data
    }
}

pub(crate) const DIGEST_LEN: usize = 20;
/// The only certificate type standard Java providers can load from a JKS file.
pub(crate) const CERTIFICATE_TYPE: &str = "X.509";

/// Whether the data starts with the JKS or JCEKS magic number.
pub fn has_magic(data: &[u8]) -> bool {
    data.starts_with(&MAGIC.to_be_bytes()) || is_jceks(data)
}

pub fn is_jceks(data: &[u8]) -> bool {
    data.starts_with(&JCEKS_MAGIC.to_be_bytes())
}

pub fn parse(mut data: Vec<u8>) -> Result<Keystore, Error> {
    // Check the magic first so short or empty non-JKS files are reported as
    // such rather than as truncated keystores.
    if !has_magic(&data) {
        return Err(Error::InvalidMagic);
    }
    let jceks = is_jceks(&data);
    let mut reader = Reader {
        remaining: &data[4..],
    };
    let version = reader.u32()?;
    if !matches!(version, VERSION_01 | VERSION_02) {
        return Err(Error::UnknownVersion(version));
    }

    // Even the smallest v1 entry needs a tag, alias length, timestamp and
    // certificate length. Never reserve memory from an untrusted count.
    let count = reader.count(18)?;
    let mut entries = Vec::new();
    for _ in 0..count {
        let start = data.len() - reader.remaining.len();
        let tag = reader.u32()?;
        let alias = reader.string()?;
        reader.take(8)?; // Creation timestamp; listing does not need it.
        let mut certificates = Vec::new();
        let (kind, certificate) = match tag {
            PRIVATE_KEY_TAG => {
                // Encrypted key bytes remain opaque. Like Java, accept any
                // length (even empty) and a key entry without a chain.
                reader.payload()?;
                let cert_count = reader.count(if version == VERSION_01 { 4 } else { 6 })?;
                let mut leaf = None;
                for index in 0..cert_count {
                    let encoding = reader.certificate(version)?;
                    certificates.push(encoding.to_vec());
                    if index == 0 {
                        leaf = certificate::summarize(encoding);
                    }
                }
                (Kind::PrivateKey, leaf)
            }
            TRUSTED_CERT_TAG => {
                let encoding = reader.certificate(version)?;
                certificates.push(encoding.to_vec());
                (Kind::TrustedCertificate, certificate::summarize(encoding))
            }
            SECRET_KEY_TAG if jceks => {
                // Java writes the sealed key as a serialized object with no
                // length, so its layout is walked to find the next entry.
                let (class, rest) = java_serialization::skip_object(reader.remaining).map_err(
                    |error| match error {
                        java_serialization::Error::Truncated => Error::Truncated,
                        _ => Error::Invalid("unsupported secret key encoding in JCEKS data"),
                    },
                )?;
                if class != SEALED_KEY_CLASS {
                    return Err(Error::Invalid("unsupported secret key type in JCEKS data"));
                }
                reader.remaining = rest;
                (Kind::SecretKey, None)
            }
            _ => return Err(Error::UnknownEntryTag(tag)),
        };
        entries.push((
            KeystoreEntry {
                alias,
                certificate,
                content: Content::Certificates { kind, certificates },
                chain_warning: None,
            },
            start..data.len() - reader.remaining.len(),
        ));
    }
    let body_len = data.len() - reader.remaining.len();
    reader.take(DIGEST_LEN)?;
    // Like Java's JavaKeyStore, ignore anything after the digest, and do not
    // keep it in memory while waiting for a password.
    data.truncate(body_len + DIGEST_LEN);
    data.shrink_to_fit();

    // Keep duplicate aliases visible instead of letting one entry hide another.
    entries.sort_by(|a, b| a.0.alias.cmp(&b.0.alias));
    let (entries, spans) = entries.into_iter().unzip();
    Ok(Keystore {
        data,
        body_len,
        entries,
        spans,
    })
}

impl Keystore {
    /// Returns the entries, and what is needed to write them back, if the
    /// password matches the integrity digest, or the keystore back for
    /// another attempt if it does not.
    pub fn open(self, password: &str) -> Result<(Vec<KeystoreEntry>, Writable), Self> {
        let (body, digest) = self.data.split_at(self.body_len);
        if digest_of(password, body)[..] != *digest {
            return Err(self);
        }
        let writable = Writable {
            header: self.data[..8].try_into().unwrap(),
            entries: self
                .spans
                .iter()
                .map(|span| (span.start, self.data[span.clone()].to_vec()))
                .collect(),
        };
        Ok((self.entries, writable))
    }

    #[cfg(test)]
    pub fn verify(self, password: &str) -> Result<Vec<KeystoreEntry>, Self> {
        self.open(password).map(|(entries, _)| entries)
    }
}

/// The integrity digest Java stores after the keystore body.
pub(crate) fn digest_of(password: &str, body: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha1::new();
    hash_password(password, |bytes| hasher.update(bytes));
    hasher.update(body);
    hasher.finalize().into()
}

/// Feeds the digest prefix Java uses: the password's UTF-16 code units in
/// big-endian order, then the whitener.
fn hash_password(password: &str, mut update: impl FnMut(&[u8])) {
    for unit in password.encode_utf16() {
        let mut bytes = unit.to_be_bytes();
        update(&bytes);
        bytes.zeroize();
    }
    update(WHITENER_MESSAGE);
}

/// A string as Java's `DataOutput.writeUTF` writes it: a two-byte length,
/// then each UTF-16 unit in modified UTF-8, where NUL takes two bytes and a
/// supplementary character is two three-byte surrogates.
fn encode_string(text: &str) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0, 0];
    for unit in text.encode_utf16() {
        match unit {
            0x01..=0x7f => bytes.push(unit as u8),
            0x00 | 0x80..=0x7ff => {
                bytes.extend([0xc0 | (unit >> 6) as u8, 0x80 | (unit & 0x3f) as u8]);
            }
            _ => bytes.extend([
                0xe0 | (unit >> 12) as u8,
                0x80 | ((unit >> 6) & 0x3f) as u8,
                0x80 | (unit & 0x3f) as u8,
            ]),
        }
    }
    let length = u16::try_from(bytes.len() - 2)
        .map_err(|_| Error::Invalid("the alias is too long for a keystore"))?;
    bytes[..2].copy_from_slice(&length.to_be_bytes());
    Ok(bytes)
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        if len > self.remaining.len() {
            return Err(Error::Truncated);
        }
        let (bytes, remaining) = self.remaining.split_at(len);
        self.remaining = remaining;
        Ok(bytes)
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn count(&mut self, minimum_size: usize) -> Result<u32, Error> {
        let count = self.u32()?;
        if u64::from(count) > (self.remaining.len() / minimum_size) as u64 {
            return Err(Error::Truncated);
        }
        Ok(count)
    }

    fn payload(&mut self) -> Result<&'a [u8], Error> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn certificate(&mut self, version: u32) -> Result<&'a [u8], Error> {
        // Java resolves the type with CertificateFactory (case-insensitively),
        // and standard providers only support X.509. Version 1 implies X.509.
        if version == VERSION_02 && !self.string()?.eq_ignore_ascii_case(CERTIFICATE_TYPE) {
            return Err(Error::Invalid(
                "unsupported certificate type in keystore data",
            ));
        }
        // Java fails to load a keystore whose certificate encoding is empty.
        let encoding = self.payload()?;
        if encoding.is_empty() {
            return Err(Error::Invalid("empty certificate in keystore data"));
        }
        Ok(encoding)
    }

    fn string(&mut self) -> Result<String, Error> {
        let len = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as usize;
        let mut bytes = self.take(len)?;
        // Java's DataInput.readUTF encodes UTF-16 units: NUL uses C0 80 and
        // supplementary characters use two three-byte surrogate sequences.
        let invalid = || Error::Invalid("invalid modified UTF-8 in keystore string");
        let mut units = Vec::with_capacity(bytes.len());
        while let Some((&first, rest)) = bytes.split_first() {
            bytes = rest;
            let unit = match first {
                0x00..=0x7f => u16::from(first),
                0xc0..=0xef => {
                    let continuations = if first < 0xe0 { 1 } else { 2 };
                    if bytes.len() < continuations {
                        return Err(invalid());
                    }
                    let mut unit = u16::from(first & (0x7f >> (continuations + 1)));
                    for &byte in &bytes[..continuations] {
                        if byte & 0xc0 != 0x80 {
                            return Err(invalid());
                        }
                        unit = (unit << 6) | u16::from(byte & 0x3f);
                    }
                    bytes = &bytes[continuations..];
                    unit
                }
                _ => return Err(invalid()),
            };
            units.push(unit);
        }
        // Java strings may hold unpaired surrogates. Show each as a \uXXXX
        // escape so aliases that differ only in them stay distinguishable.
        Ok(char::decode_utf16(units)
            .map(|unit| match unit {
                Ok(ch) => ch.to_string(),
                Err(error) => format!("\\u{:04X}", error.unpaired_surrogate()),
            })
            .collect())
    }
}

#[cfg(test)]
/// Parses valid test data and returns its entries, or `None` if the password
/// does not match the digest.
pub fn load_entries(data: &[u8], password: &str) -> Option<Vec<KeystoreEntry>> {
    parse(data.to_vec()).unwrap().verify(password).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        Builder, KEYTOOL_JCEKS, KEYTOOL_JKS, UNICODE_ALIAS_JKS, UNICODE_PASSWORD_JKS,
        empty_keystore, fixture_certificate_der, fixture_summary, mixed_keystore,
    };
    fn key(alias: &str) -> KeystoreEntry {
        KeystoreEntry {
            alias: alias.into(),
            certificate: None,
            content: Content::Certificates {
                kind: Kind::PrivateKey,
                certificates: vec![b"opaque synthetic certificate".to_vec()],
            },
            chain_warning: None,
        }
    }

    fn cert(alias: &str) -> KeystoreEntry {
        KeystoreEntry {
            alias: alias.into(),
            certificate: None,
            content: Content::Certificates {
                kind: Kind::TrustedCertificate,
                certificates: vec![b"opaque synthetic certificate".to_vec()],
            },
            chain_warning: None,
        }
    }

    fn fixture_cert(alias: &str) -> KeystoreEntry {
        KeystoreEntry {
            certificate: Some(fixture_summary()),
            content: Content::Certificates {
                kind: Kind::TrustedCertificate,
                certificates: vec![fixture_certificate_der().to_vec()],
            },
            ..cert(alias)
        }
    }

    #[test]
    fn summarizes_the_first_certificate_of_a_private_key_chain() {
        let mut data = Builder::new(VERSION_02, 1);
        data.entry_header(PRIVATE_KEY_TAG, b"key");
        data.payload(b"synthetic test payload, not a private key");
        data.u32_field(2);
        data.raw_string(CERTIFICATE_TYPE.as_bytes());
        data.payload(fixture_certificate_der());
        data.certificate(VERSION_02);
        assert_eq!(
            load_entries(&data.finish(""), "").unwrap(),
            [KeystoreEntry {
                certificate: Some(fixture_summary()),
                content: Content::Certificates {
                    kind: Kind::PrivateKey,
                    certificates: vec![
                        fixture_certificate_der().to_vec(),
                        b"opaque synthetic certificate".to_vec()
                    ],
                },
                ..key("key")
            }]
        );
    }

    #[test]
    fn verifies_java_passwords_with_accented_and_supplementary_characters() {
        assert_eq!(
            load_entries(UNICODE_PASSWORD_JKS, "pässwörd-😀").unwrap(),
            load_entries(KEYTOOL_JKS, "changeit").unwrap()
        );
        for password in ["", "pässwörd", "pässwörd-😁"] {
            assert!(load_entries(UNICODE_PASSWORD_JKS, password).is_none());
        }
    }

    #[test]
    fn a_parsed_keystore_can_be_verified_repeatedly() {
        let mut keystore = parse(KEYTOOL_JKS.to_vec()).unwrap();
        for _ in 0..2 {
            keystore = keystore.verify("wrong").err().unwrap();
        }
        assert_eq!(
            keystore.verify("changeit").ok().unwrap(),
            [fixture_cert("root-cert")]
        );
    }

    #[test]
    fn reads_java_aliases_with_supplementary_characters() {
        assert_eq!(
            load_entries(UNICODE_ALIAS_JKS, "changeit").unwrap(),
            [fixture_cert("certificate-😀")]
        );
    }

    #[test]
    fn lists_aliases_with_unpaired_surrogates_that_java_accepts() {
        let mut builder = Builder::new(VERSION_02, 2);
        builder.entry(TRUSTED_CERT_TAG, b"a\xed\xb0\x80", VERSION_02, 1);
        builder.entry(TRUSTED_CERT_TAG, b"a\xed\xa0\xbd", VERSION_02, 1);
        assert_eq!(
            load_entries(&builder.finish(""), "").unwrap(),
            [cert("a\\uD83D"), cert("a\\uDC00")]
        );
    }

    #[test]
    fn duplicate_aliases_do_not_hide_entries() {
        let mut builder = Builder::new(VERSION_02, 3);
        builder.entry(PRIVATE_KEY_TAG, b"a", VERSION_02, 1);
        builder.entry(TRUSTED_CERT_TAG, b"b", VERSION_02, 1);
        builder.entry(TRUSTED_CERT_TAG, b"a", VERSION_02, 1);
        assert_eq!(
            load_entries(&builder.finish(""), "").unwrap(),
            [key("a"), cert("a"), cert("b")]
        );
    }

    #[test]
    fn accepts_empty_key_material_like_java() {
        let mut data = Builder::new(VERSION_02, 1);
        data.entry_header(PRIVATE_KEY_TAG, b"key");
        data.payload(b"");
        data.u32_field(1);
        data.certificate(VERSION_02);
        assert_eq!(load_entries(&data.finish(""), "").unwrap(), [key("key")]);
    }

    #[test]
    fn rejects_certificates_java_cannot_load() {
        for (version, cert_type, encoding, message) in [
            (VERSION_01, None, &b""[..], "empty certificate"),
            (
                VERSION_02,
                Some(&b"x.509"[..]),
                &b""[..],
                "empty certificate",
            ),
            (
                VERSION_02,
                Some(&b"FOO"[..]),
                &b"cert"[..],
                "unsupported certificate type",
            ),
            (
                VERSION_02,
                Some(&b""[..]),
                &b"cert"[..],
                "unsupported certificate type",
            ),
            (
                VERSION_02,
                Some(&b"\xc0"[..]),
                &b"cert"[..],
                "invalid modified UTF-8",
            ),
        ] {
            let mut data = Builder::new(version, 1);
            data.entry_header(TRUSTED_CERT_TAG, b"cert");
            if let Some(cert_type) = cert_type {
                data.raw_string(cert_type);
            }
            data.payload(encoding);
            let error = parse(data.finish("")).err().unwrap();
            assert!(error.to_string().contains(message), "{error}");
        }
    }

    #[test]
    fn drops_trailing_data_from_memory() {
        let mut data = KEYTOOL_JKS.to_vec();
        data.resize(KEYTOOL_JKS.len() + 4096, 0);
        let keystore = parse(data).unwrap();
        assert_eq!(keystore.data, KEYTOOL_JKS);
        assert!(keystore.data.capacity() < KEYTOOL_JKS.len() + 4096);
    }

    #[test]
    fn lists_private_keys_without_a_certificate_chain() {
        let mut builder = Builder::new(VERSION_02, 1);
        builder.entry(PRIVATE_KEY_TAG, b"key", VERSION_02, 0);
        assert_eq!(
            load_entries(&builder.finish(""), "").unwrap(),
            [KeystoreEntry {
                content: Content::Certificates {
                    kind: Kind::PrivateKey,
                    certificates: vec![],
                },
                ..key("key")
            }]
        );
    }

    #[test]
    fn rejects_every_truncated_prefix_before_requesting_a_password() {
        let mixed = mixed_keystore();
        for data in [KEYTOOL_JKS, UNICODE_ALIAS_JKS, mixed.as_slice()] {
            for end in 0..data.len() {
                assert!(parse(data[..end].to_vec()).is_err());
            }
        }
    }

    #[test]
    fn rejects_unbounded_lengths_and_counts_without_allocating_payloads() {
        let mut builder = Builder::new(VERSION_02, 2);
        builder.entry(PRIVATE_KEY_TAG, b"key", VERSION_02, 2);
        builder.entry(TRUSTED_CERT_TAG, b"cert", VERSION_02, 1);
        let mut data = builder.finish("changeit");
        assert_eq!(load_entries(&data, "changeit").unwrap().len(), 2);
        // Every length and count in both entry types, including the original
        // crashing private-key chain count, is overwritten with its maximum.
        let fields = builder
            .u32_fields
            .iter()
            .map(|&offset| (offset, &[0xff; 4][..]))
            .chain(
                builder
                    .u16_fields
                    .iter()
                    .map(|&offset| (offset, &[0xff; 2][..])),
            );
        assert_eq!(fields.clone().count(), 11);
        for (offset, replacement) in fields {
            let range = offset..offset + replacement.len();
            let original = data[range.clone()].to_vec();
            data[range.clone()].copy_from_slice(replacement);
            assert!(parse(data.clone()).is_err(), "field at {offset}");
            data[range].copy_from_slice(&original);
        }
    }

    #[test]
    fn decodes_modified_utf8_and_rejects_malformed_strings() {
        let mut reader = Reader {
            remaining: b"\x00\x0ea\xc0\x80\xc3\xa9\xe4\xb8\xad\xed\xa0\xbd\xed\xb8\x80",
        };
        assert_eq!(reader.string().unwrap(), "a\0é中😀");
        assert!(reader.remaining.is_empty());
        for bytes in [
            &b"\x00\x01\x80"[..],             // Unexpected continuation.
            &b"\x00\x01\xc0"[..],             // Missing continuation.
            &b"\x00\x02\xc0A"[..],            // Invalid continuation.
            &b"\x00\x02\xe0\x80"[..],         // Truncated three-byte sequence.
            &b"\x00\x04\xf0\x9f\x98\x80"[..], // Standard UTF-8 is not modified UTF-8.
        ] {
            assert!(Reader { remaining: bytes }.string().is_err());
        }
    }

    #[test]
    fn supports_v1_entries_without_certificate_type_fields() {
        let mut builder = Builder::new(VERSION_01, 2);
        builder.entry(PRIVATE_KEY_TAG, b"key", VERSION_01, 1);
        builder.entry(TRUSTED_CERT_TAG, b"cert", VERSION_01, 1);
        assert_eq!(
            load_entries(&builder.finish(""), "").unwrap(),
            [cert("cert"), key("key")]
        );
    }

    #[test]
    fn reads_a_java_generated_keystore() {
        assert_eq!(
            load_entries(KEYTOOL_JKS, "changeit").unwrap(),
            [fixture_cert("root-cert")]
        );
    }

    #[test]
    fn lists_both_entry_types_in_alias_order_without_the_key_password() {
        assert_eq!(
            load_entries(&mixed_keystore(), "changeit").unwrap(),
            [cert("root-cert"), key("server-key")]
        );
    }

    #[test]
    fn reports_short_and_empty_non_jks_files_as_invalid_magic() {
        for data in [
            &b""[..],
            &b"PK"[..],
            &b"not a keystore"[..],
            &b"\x30\x82PKCS12"[..],
            &b"\xce\xce\xce"[..],
        ] {
            assert!(matches!(parse(data.to_vec()), Err(Error::InvalidMagic)));
        }
    }

    #[test]
    fn rejects_truncated_files() {
        for end in [4, 12, KEYTOOL_JKS.len() - 1] {
            let error = parse(KEYTOOL_JKS[..end].to_vec()).err().unwrap();
            assert!(error.to_string().contains("truncated"));
        }
    }

    #[test]
    fn rejects_wrong_password_and_corrupt_digest_without_returning_entries() {
        assert!(load_entries(KEYTOOL_JKS, "wrong-password").is_none());
        let mut data = KEYTOOL_JKS.to_vec();
        *data.last_mut().unwrap() ^= 1;
        assert!(load_entries(&data, "changeit").is_none());
    }

    #[test]
    fn rejects_unsupported_versions_even_without_entries() {
        let mut data = empty_keystore();
        data[4..8].copy_from_slice(&3_u32.to_be_bytes());
        assert!(matches!(parse(data), Err(Error::UnknownVersion(3))));
    }

    #[test]
    fn ignores_trailing_data_after_the_digest_like_java() {
        let mut data = KEYTOOL_JKS.to_vec();
        data.extend_from_slice(b"\0trailing");
        assert_eq!(
            load_entries(&data, "changeit").unwrap(),
            [fixture_cert("root-cert")]
        );
        assert!(load_entries(&data, "").is_none());
    }

    #[test]
    fn reads_a_java_generated_jceks_keystore() {
        assert!(is_jceks(KEYTOOL_JCEKS));
        assert!(load_entries(KEYTOOL_JCEKS, "wrong").is_none());
        assert_eq!(
            load_entries(KEYTOOL_JCEKS, "changeit").unwrap(),
            [fixture_cert("root-cert")]
        );
    }

    fn secret(alias: &str) -> KeystoreEntry {
        KeystoreEntry {
            alias: alias.into(),
            certificate: None,
            content: Content::Certificates {
                kind: Kind::SecretKey,
                certificates: vec![],
            },
            chain_warning: None,
        }
    }

    #[test]
    fn lists_jceks_secret_keys_alongside_other_entries() {
        for version in [VERSION_01, VERSION_02] {
            let mut builder = Builder::jceks(version, 4);
            builder.entry(SECRET_KEY_TAG, b"aes", version, 0);
            builder.entry(PRIVATE_KEY_TAG, b"key", version, 1);
            builder.entry(SECRET_KEY_TAG, b"hmac", version, 0);
            builder.entry(TRUSTED_CERT_TAG, b"cert", version, 1);
            assert_eq!(
                load_entries(&builder.finish("changeit"), "changeit").unwrap(),
                [secret("aes"), cert("cert"), secret("hmac"), key("key")]
            );
        }
    }

    #[test]
    fn secret_keys_are_jceks_only_and_must_be_sealed_keys() {
        let mut builder = Builder::new(VERSION_02, 1);
        builder.entry(SECRET_KEY_TAG, b"aes", VERSION_02, 0);
        assert_eq!(
            parse(builder.finish("")).err(),
            Some(Error::UnknownEntryTag(SECRET_KEY_TAG))
        );
        let mut builder = Builder::jceks(VERSION_02, 1);
        builder.entry(SECRET_KEY_TAG, b"aes", VERSION_02, 0);
        let data = builder.finish("");
        let class = data
            .windows(SEALED_KEY_CLASS.len())
            .position(|window| window == SEALED_KEY_CLASS)
            .unwrap();
        let mut renamed = data.clone();
        renamed[class] = b'x';
        let error = parse(renamed).err().unwrap();
        assert!(error.to_string().contains("secret key type"), "{error}");
        for end in 0..data.len() {
            assert!(parse(data[..end].to_vec()).is_err(), "prefix {end}");
        }
    }

    #[test]
    fn writes_unchanged_keystores_back_byte_for_byte() {
        let mut builder = Builder::jceks(VERSION_02, 4);
        builder.entry(SECRET_KEY_TAG, b"aes", VERSION_02, 0);
        builder.entry(PRIVATE_KEY_TAG, b"key", VERSION_02, 2);
        builder.entry(TRUSTED_CERT_TAG, b"cert", VERSION_02, 1);
        // Stored after `cert`, listed before it.
        builder.entry(TRUSTED_CERT_TAG, b"a\xed\xb0\x80", VERSION_02, 1);
        let mut v1 = Builder::new(VERSION_01, 2);
        v1.entry(PRIVATE_KEY_TAG, b"key", VERSION_01, 1);
        v1.entry(TRUSTED_CERT_TAG, b"cert", VERSION_01, 1);
        for (data, password) in [
            (KEYTOOL_JKS.to_vec(), "changeit"),
            (KEYTOOL_JCEKS.to_vec(), "changeit"),
            (UNICODE_ALIAS_JKS.to_vec(), "changeit"),
            (UNICODE_PASSWORD_JKS.to_vec(), "pässwörd-😀"),
            (builder.finish("changeit"), "changeit"),
            (v1.finish(""), ""),
            (empty_keystore(), ""),
        ] {
            let (_, writable) = parse(data.clone()).unwrap().open(password).ok().unwrap();
            assert_eq!(writable.encode(password), data);
        }
    }

    #[test]
    fn removing_an_entry_keeps_the_others_as_stored() {
        let mut builder = Builder::new(VERSION_02, 3);
        builder.entry(TRUSTED_CERT_TAG, b"b", VERSION_02, 1);
        builder.entry(PRIVATE_KEY_TAG, b"c", VERSION_02, 1);
        builder.entry(TRUSTED_CERT_TAG, b"a", VERSION_02, 1);
        let (mut entries, mut writable) = parse(builder.finish("changeit"))
            .unwrap()
            .open("changeit")
            .ok()
            .unwrap();
        assert_eq!(entries, [cert("a"), cert("b"), key("c")]);
        // The listed position, not the stored one, names the entry.
        writable.remove(1);
        entries.remove(1);
        let mut expected = Builder::new(VERSION_02, 2);
        expected.entry(PRIVATE_KEY_TAG, b"c", VERSION_02, 1);
        expected.entry(TRUSTED_CERT_TAG, b"a", VERSION_02, 1);
        let saved = writable.encode("changeit");
        assert_eq!(saved, expected.finish("changeit"));
        assert_eq!(load_entries(&saved, "changeit").unwrap(), entries);
    }

    #[test]
    fn encodes_strings_as_the_reader_decodes_them() {
        for text in ["", "plain", "a\0é中😀", "certificate-😀"] {
            let encoded = encode_string(text).unwrap();
            let mut reader = Reader {
                remaining: &encoded,
            };
            assert_eq!(reader.string().unwrap(), text);
            assert!(reader.remaining.is_empty());
        }
        assert_eq!(
            encode_string("a\0é中😀").unwrap(),
            b"\x00\x0ea\xc0\x80\xc3\xa9\xe4\xb8\xad\xed\xa0\xbd\xed\xb8\x80"
        );
        assert!(encode_string(&"a".repeat(65_535)).is_ok());
        assert!(encode_string(&"a".repeat(65_536)).is_err());
        assert!(encode_string(&"é".repeat(32_768)).is_err());
    }

    #[test]
    fn renaming_changes_only_the_alias_and_the_listed_position() {
        for version in [VERSION_01, VERSION_02] {
            let mut builder = Builder::jceks(version, 3);
            builder.entry(PRIVATE_KEY_TAG, b"b", version, 1);
            builder.entry(SECRET_KEY_TAG, b"c", version, 0);
            builder.entry(TRUSTED_CERT_TAG, b"a", version, 1);
            let (_, mut writable) = parse(builder.finish("changeit"))
                .unwrap()
                .open("changeit")
                .ok()
                .unwrap();
            // Listed as a, b, c; `b` becomes `zoé-😀`, listed last.
            writable.rename(1, "zoé-😀", 2).unwrap();
            let saved = writable.encode("changeit");
            assert_eq!(
                load_entries(&saved, "changeit").unwrap(),
                [cert("a"), secret("c"), key("zoé-😀")]
            );
            // A second rename back restores the original bytes.
            writable.rename(2, "b", 1).unwrap();
            assert_eq!(writable.encode("changeit"), builder.finish("changeit"));
        }
    }

    #[test]
    fn inserts_trusted_certificates_as_java_stores_them() {
        // Rebuilding keytool's file from an empty keystore gives its bytes.
        let created = u64::from_be_bytes(KEYTOOL_JKS[27..35].try_into().unwrap());
        let (_, mut writable) = parse(Builder::new(VERSION_02, 0).finish("changeit"))
            .unwrap()
            .open("changeit")
            .ok()
            .unwrap();
        writable
            .insert_trusted_certificate(0, "root-cert", fixture_certificate_der(), created)
            .unwrap();
        assert_eq!(writable.encode("changeit"), KEYTOOL_JKS);

        // Version 1 has no certificate type, and new entries are stored last.
        let mut builder = Builder::new(VERSION_01, 1);
        builder.entry(TRUSTED_CERT_TAG, b"z", VERSION_01, 1);
        let (_, mut writable) = parse(builder.finish("")).unwrap().open("").ok().unwrap();
        writable
            .insert_trusted_certificate(0, "a", b"opaque synthetic certificate", 0)
            .unwrap();
        let mut expected = Builder::new(VERSION_01, 2);
        expected.entry(TRUSTED_CERT_TAG, b"z", VERSION_01, 1);
        expected.entry(TRUSTED_CERT_TAG, b"a", VERSION_01, 1);
        let saved = writable.encode("");
        assert_eq!(saved, expected.finish(""));
        assert_eq!(load_entries(&saved, "").unwrap(), [cert("a"), cert("z")]);
    }

    #[test]
    fn supports_empty_keystores() {
        assert!(load_entries(&empty_keystore(), "").unwrap().is_empty());
    }

    #[test]
    fn preserves_alias_case_when_identifying_entry_types() {
        let mut builder = Builder::new(VERSION_02, 1);
        builder.entry(PRIVATE_KEY_TAG, b"MixedCase", VERSION_02, 1);
        assert_eq!(
            load_entries(&builder.finish("changeit"), "changeit").unwrap(),
            [key("MixedCase")]
        );
    }
}
