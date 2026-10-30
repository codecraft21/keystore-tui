use crown::{
    asn1::{der::Reader, oid},
    error::CryptoError,
    pkcs7::ContentInfo,
    pkcs12::{Bag, Pfx, SafeBag},
    x509::{
        algorithm::AlgorithmIdentifier,
        attribute::parse_attributes,
        pbe::{LegacyPbe, LegacyPbeKind, Pbes2, Pbes2Cipher},
    },
};
use zeroize::Zeroizing;

use crate::{
    certificate, certificate_file,
    keystore::{Content, KeystoreEntry, Kind},
};

const MAX_ITERATIONS: u32 = 1_000_000;
const MAX_SALT_SIZE: usize = 64;
const TRUSTED_KEY_USAGE: &[u64] = &[2, 16, 840, 1, 113894, 746875, 1, 1];
// RFC 7292, appendix C. Crown 0.31 swaps these two OIDs.
const PBE_SHA1_128BIT_RC4: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 1];
const PBE_SHA1_40BIT_RC4: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 2];

pub struct Store(Pfx);

#[derive(Debug)]
pub enum VerifyError {
    Password,
    Invalid(&'static str),
}

pub struct Verified {
    pub entries: Vec<KeystoreEntry>,
    pub incomplete: bool,
}

pub fn parse(data: &[u8]) -> Result<Store, &'static str> {
    let pfx = Pfx::parse(data).map_err(|_| "invalid PKCS12 structure")?;
    if pfx.version != 3 {
        return Err("unsupported PKCS12 version");
    }
    if let Some(mac) = &pfx.mac
        && (mac.iterations == 0
            || mac.iterations > MAX_ITERATIONS
            || mac.salt.len() > MAX_SALT_SIZE)
    {
        return Err("PKCS12 MAC iteration count is unsupported");
    }
    Ok(Store(pfx))
}

impl Store {
    pub fn verify(&self, password: &str) -> Result<Verified, VerifyError> {
        let mut password_bytes = password.as_bytes();
        // PKCS12 stores can omit MacData even when their contents are encrypted.
        // When a MAC is present, it must still verify before reading any entries.
        if self.0.mac.is_some() {
            let mut mac_result = self.0.verify_mac(password_bytes);
            // Java also accepts a NUL character as the encoding of an empty password.
            if password.is_empty() && mac_result == Err(CryptoError::AuthenticationFailed) {
                mac_result = self.0.verify_mac(b"\0");
                if mac_result.is_ok() {
                    password_bytes = b"\0";
                }
            }
            mac_result.map_err(|error| {
                if error == CryptoError::AuthenticationFailed {
                    VerifyError::Password
                } else {
                    VerifyError::Invalid("unsupported or invalid PKCS12 integrity MAC")
                }
            })?;
        }

        let (bags, mut incomplete) = match self.read_bags(password_bytes) {
            // Without a MAC, only decryption can tell whether an empty password
            // was stored in Java's NUL encoding.
            Err(VerifyError::Password) if password.is_empty() => self.read_bags(b"\0")?,
            result => result?,
        };

        let pool: Vec<_> = bags
            .iter()
            .filter_map(|bag| bag.certificate_der.as_deref())
            .collect();
        let mut entries = Vec::new();
        let mut unnamed_keys = 0;
        for bag in &bags {
            if matches!(bag.bag, Bag::ShroudedKey(_)) {
                // Java and OpenSSL give the key and its end-entity certificate
                // the same local key ID.
                let leaf = bag
                    .local_key_id()
                    .and_then(|id| {
                        bags.iter().find(|other| {
                            other.certificate_der.is_some()
                                && other.local_key_id().as_ref() == Some(&id)
                        })
                    })
                    .and_then(|bag| bag.certificate_der.as_deref());
                // OpenSSL only stores a friendly name when given one.
                let alias = bag
                    .friendly_name()
                    .or_else(|| leaf.and_then(certificate_file::subject_name))
                    .unwrap_or_else(|| {
                        unnamed_keys += 1;
                        format!("Private key {unnamed_keys}")
                    });
                let (certificates, chain_warning) = leaf.map_or_else(
                    || (vec![], None),
                    |leaf| certificate::details::chain(leaf, &pool),
                );
                entries.push(KeystoreEntry {
                    alias,
                    certificate: leaf.and_then(certificate::summarize),
                    content: Content::Certificates {
                        kind: Kind::PrivateKey,
                        certificates,
                    },
                    chain_warning,
                });
            }
        }
        let mut unnamed_certificates = 0;
        for bag in &bags {
            match &bag.bag {
                Bag::Secret { .. } => {
                    if let Some(alias) = bag.friendly_name() {
                        entries.push(KeystoreEntry {
                            alias,
                            certificate: None,
                            content: Content::Certificates {
                                kind: Kind::SecretKey,
                                certificates: vec![],
                            },
                            chain_warning: None,
                        });
                    } else {
                        incomplete = true;
                    }
                }
                _ if bag.certificate_der.is_some() => {
                    let der = bag.certificate_der.as_deref().unwrap();
                    // Java identifies trusted entries with its trustedKeyUsage
                    // attribute. Other tools store plain certificates, which
                    // are listed unless they belong to a key's chain.
                    if !bag
                        .attributes
                        .iter()
                        .any(|attr| attr.oid.matches(TRUSTED_KEY_USAGE))
                    {
                        if entries.iter().any(|entry| {
                            matches!(
                                entry.content,
                                Content::Certificates {
                                    kind: Kind::PrivateKey,
                                    ..
                                }
                            ) && entry.certificates().iter().any(|stored| stored == der)
                        }) {
                            continue;
                        }
                        let alias = bag
                            .friendly_name()
                            .or_else(|| certificate_file::subject_name(der))
                            .unwrap_or_else(|| {
                                unnamed_certificates += 1;
                                format!("Certificate {unnamed_certificates}")
                            });
                        let (certificates, chain_warning) = certificate::details::chain(der, &pool);
                        entries.push(KeystoreEntry {
                            alias,
                            certificate: certificate::summarize(der),
                            content: Content::Certificates {
                                kind: Kind::Certificate,
                                certificates,
                            },
                            chain_warning,
                        });
                        continue;
                    }
                    if let Some(alias) = bag.friendly_name() {
                        if !entries
                            .iter()
                            .any(|entry| entry.alias.eq_ignore_ascii_case(&alias))
                        {
                            let (certificates, chain_warning) =
                                certificate::details::chain(der, &pool);
                            entries.push(KeystoreEntry {
                                alias,
                                certificate: certificate::summarize(der),
                                content: Content::Certificates {
                                    kind: Kind::TrustedCertificate,
                                    certificates,
                                },
                                chain_warning,
                            });
                        }
                    } else {
                        incomplete = true;
                    }
                }
                Bag::ShroudedKey(_) => {}
                _ => incomplete = true,
            }
        }
        entries.sort_by(|a, b| a.alias.cmp(&b.alias));
        Ok(Verified {
            entries,
            incomplete,
        })
    }

    /// Reads every safe's bags, decrypting with `password`, and whether any
    /// part could not be read.
    fn read_bags(&self, password: &[u8]) -> Result<(Vec<MetadataBag>, bool), VerifyError> {
        let safe = self
            .0
            .authenticated_safe()
            .map_err(|_| VerifyError::Invalid("invalid PKCS12 content"))?;
        let mut reader = Reader::new(&safe);
        let mut sequence = reader
            .read_sequence()
            .map_err(|_| VerifyError::Invalid("invalid PKCS12 content"))?;
        let mut bags = Vec::new();
        let mut incomplete = false;
        while !sequence.is_empty() {
            let info = match ContentInfo::parse_reader(&mut sequence) {
                Ok(info) => info,
                Err(_) => {
                    incomplete = true;
                    break;
                }
            };
            let content = if info.content_type.matches(oid::OID_PKCS7_DATA) {
                Reader::new(&info.content)
                    .read_octet_string_owned()
                    .map(Zeroizing::new)
                    .ok()
            } else if info.content_type.matches(oid::OID_PKCS7_ENCRYPTED_DATA) {
                // Without a MAC, only decryption shows whether the password
                // is right. Most wrong keys fail CBC padding, but about 1 in
                // 256 pass it and RC4 has no padding, so plaintext that is
                // not SafeContents also means a wrong password.
                match decrypt_safe(&info.content, password).map(Zeroizing::new) {
                    Ok(content) if self.0.mac.is_some() || is_safe_contents(&content) => {
                        Some(content)
                    }
                    Ok(_) | Err(SafeError::Decryption) if self.0.mac.is_none() => {
                        return Err(VerifyError::Password);
                    }
                    _ => None,
                }
            } else {
                None
            };
            if let Some(content) = content {
                let mut reader = Reader::new(&content);
                if let Ok(mut sequence) = reader.read_sequence() {
                    while !sequence.is_empty() {
                        match sequence.read_raw_tlv() {
                            Ok(raw) => match parse_metadata_bag(raw) {
                                Ok(Some(bag)) => bags.push(bag),
                                Ok(None) | Err(_) => incomplete = true,
                            },
                            Err(_) => {
                                incomplete = true;
                                break;
                            }
                        }
                    }
                } else {
                    incomplete = true;
                }
            } else {
                incomplete = true;
            }
        }
        Ok((bags, incomplete))
    }
}

struct MetadataBag {
    metadata: SafeBag,
    certificate_der: Option<Vec<u8>>,
}

impl std::ops::Deref for MetadataBag {
    type Target = SafeBag;
    fn deref(&self) -> &Self::Target {
        &self.metadata
    }
}

fn parse_metadata_bag(raw: &[u8]) -> Result<Option<MetadataBag>, CryptoError> {
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
        }));
    }
    let mut reader = Reader::new(raw);
    let bag = SafeBag::parse(&mut reader)?;
    reader.expect_end()?;
    Ok(Some(MetadataBag {
        metadata: bag,
        certificate_der: None,
    }))
}

/// Why an encrypted safe could not be read.
enum SafeError {
    /// The safe is malformed, or uses unsupported or excessive parameters.
    Unreadable,
    /// Decryption failed, as it does for most wrong passwords.
    Decryption,
}

fn decrypt_safe(content: &[u8], password: &[u8]) -> Result<Vec<u8>, SafeError> {
    let unreadable = |_| SafeError::Unreadable;
    let mut reader = Reader::new(content);
    let mut sequence = reader.read_sequence().map_err(unreadable)?;
    let _version = sequence.read_integer().map_err(unreadable)?;
    let mut info = sequence.read_sequence().map_err(unreadable)?;
    let _content_type = info.read_oid().map_err(unreadable)?;
    let algorithm = AlgorithmIdentifier::parse(&mut info).map_err(unreadable)?;
    let ciphertext = info.read_implicit(0, false).map_err(unreadable)?;
    let check = |iterations, salt: &[u8], block_size| {
        if iterations == 0
            || iterations > MAX_ITERATIONS
            || salt.len() > MAX_SALT_SIZE
            || ciphertext.is_empty()
            || !ciphertext.len().is_multiple_of(block_size)
        {
            Err(SafeError::Unreadable)
        } else {
            Ok(())
        }
    };
    let decrypted = if algorithm.oid.matches(oid::OID_PBES2) {
        let pbe = Pbes2::parse(&algorithm).map_err(unreadable)?;
        let block_size = match pbe.cipher {
            Pbes2Cipher::Aes128Cbc { .. }
            | Pbes2Cipher::Aes192Cbc { .. }
            | Pbes2Cipher::Aes256Cbc { .. } => 16,
            Pbes2Cipher::DesEde3Cbc { .. } => 8,
        };
        check(pbe.iterations, &pbe.salt, block_size)?;
        pbe.decrypt(ciphertext, password)
    } else {
        let mut pbe = LegacyPbe::parse(&algorithm).map_err(unreadable)?;
        if algorithm.oid.matches(PBE_SHA1_128BIT_RC4) {
            pbe.kind = LegacyPbeKind::Rc4_128;
        } else if algorithm.oid.matches(PBE_SHA1_40BIT_RC4) {
            pbe.kind = LegacyPbeKind::Rc4_40;
        }
        let block_size = match pbe.kind {
            LegacyPbeKind::Rc4_40 | LegacyPbeKind::Rc4_128 => 1,
            LegacyPbeKind::DesEde3 | LegacyPbeKind::DesEde2 | LegacyPbeKind::Rc2_40 => 8,
        };
        check(pbe.iterations, &pbe.salt, block_size)?;
        pbe.decrypt(ciphertext, password)
    };
    // An unsupported parameter is not a wrong password; any other failure can be.
    decrypted.map_err(|error| match error {
        CryptoError::UnsupportedOperation(_) => SafeError::Unreadable,
        _ => SafeError::Decryption,
    })
}

/// Whether `content` is a single SafeContents sequence of bags.
fn is_safe_contents(content: &[u8]) -> bool {
    let mut reader = Reader::new(content);
    let Ok(mut bags) = reader.read_sequence() else {
        return false;
    };
    while !bags.is_empty() {
        if bags.read_sequence().is_err() {
            return false;
        }
    }
    reader.expect_end().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{fixture_certificate_der, fixture_summary};
    use crown::{
        asn1::{der, oid::ObjectIdentifier},
        pkcs12::{SafeBag, encode_safe_contents},
        rng::Rng,
        x509::{
            Certificate,
            algorithm::{AlgorithmIdentifier, Hash},
            attribute::{friendly_name, local_key_id},
            keys::EncryptedPrivateKeyInfo,
        },
    };

    const MODERN: &[u8] = include_bytes!("../tests/fixtures/trusted-cert.p12");
    const LEGACY: &[u8] = include_bytes!("../tests/fixtures/trusted-cert-legacy.p12");
    const UNICODE_ALIAS: &[u8] = include_bytes!("../tests/fixtures/unicode-alias.p12");
    const EMPTY_PASSWORD: &[u8] = include_bytes!("../tests/fixtures/empty-password.p12");
    const NUL_PASSWORD: &[u8] = include_bytes!("../tests/fixtures/nul-password.p12");
    const EMPTY_PASSWORD_NO_MAC: &[u8] =
        include_bytes!("../tests/fixtures/empty-password-no-mac.p12");
    const OPENSSL: &[u8] = include_bytes!("../tests/fixtures/openssl-cert.p12");
    const OPENSSL_LEGACY: &[u8] = include_bytes!("../tests/fixtures/openssl-cert-legacy.p12");
    const OPENSSL_NO_MAC_AES: &[u8] = include_bytes!("../tests/fixtures/openssl-no-mac-aes.p12");
    const OPENSSL_NO_MAC: [&[u8]; 5] = [
        OPENSSL_NO_MAC_AES,
        include_bytes!("../tests/fixtures/openssl-no-mac-3des.p12"),
        include_bytes!("../tests/fixtures/openssl-no-mac-rc2.p12"),
        include_bytes!("../tests/fixtures/openssl-no-mac-rc4.p12"),
        include_bytes!("../tests/fixtures/openssl-no-mac-rc4-40.p12"),
    ];
    /// A wrong password that passes the padding check of `OPENSSL_NO_MAC_AES`.
    const VALID_PADDING_PASSWORD: &str = "wrong130";

    struct TestRng(u8);
    impl Rng for TestRng {
        fn fill_bytes(&mut self, bytes: &mut [u8]) {
            for byte in bytes {
                self.0 = self.0.wrapping_add(1);
                *byte = self.0;
            }
        }
    }

    fn synthetic(bags: Vec<SafeBag>) -> Vec<u8> {
        Pfx::build(bags, b"changeit", 100, &mut TestRng(0))
            .unwrap()
            .encode()
    }

    #[test]
    fn reads_java_truststores_with_modern_and_legacy_crypto() {
        for data in [MODERN, LEGACY] {
            let store = parse(data).unwrap();
            assert!(matches!(store.verify("wrong"), Err(VerifyError::Password)));
            let verified = store.verify("changeit").unwrap();
            assert_eq!(
                verified.entries,
                vec![KeystoreEntry {
                    alias: "root-cert".into(),
                    certificate: Some(fixture_summary()),
                    content: Content::Certificates {
                        kind: Kind::TrustedCertificate,
                        certificates: vec![fixture_certificate_der().to_vec()],
                    },
                    chain_warning: None,
                }]
            );
            assert!(!verified.incomplete);
        }
    }

    #[test]
    fn reads_openssl_certificate_stores_without_java_attributes() {
        for data in [OPENSSL, OPENSSL_LEGACY] {
            let store = parse(data).unwrap();
            assert!(matches!(store.verify("wrong"), Err(VerifyError::Password)));
            let verified = store.verify("changeit").unwrap();
            assert_eq!(
                verified.entries,
                vec![KeystoreEntry {
                    alias: "JKS TUI test fixture".into(),
                    certificate: Some(fixture_summary()),
                    content: Content::Certificates {
                        kind: Kind::Certificate,
                        certificates: vec![fixture_certificate_der().to_vec()],
                    },
                    chain_warning: None,
                }]
            );
            assert!(!verified.incomplete);
        }
    }

    #[test]
    fn reads_a_java_unicode_alias() {
        let verified = parse(UNICODE_ALIAS).unwrap().verify("changeit").unwrap();
        assert_eq!(verified.entries[0].alias, "certificate-😀");
        assert!(!verified.incomplete);
    }

    #[test]
    fn lists_keys_without_decrypting_them_and_warns_about_unknown_bags() {
        let key = SafeBag {
            bag: Bag::ShroudedKey(EncryptedPrivateKeyInfo {
                algorithm: AlgorithmIdentifier::with_null(
                    ObjectIdentifier::new(oid::OID_PBES2).unwrap(),
                ),
                encrypted_data: vec![1, 2, 3],
            }),
            attributes: vec![friendly_name("private"), local_key_id(&[1])],
        };
        let secret = SafeBag {
            bag: Bag::Secret {
                oid: ObjectIdentifier::new(oid::OID_PKCS12_SECRET_BAG).unwrap(),
                value: der::octet_string(&[1, 2, 3]),
            },
            attributes: vec![friendly_name("secret")],
        };
        let unknown = SafeBag {
            bag: Bag::Other {
                oid: ObjectIdentifier::new(&[1, 2, 3, 4]).unwrap(),
                value: der::null(),
            },
            attributes: vec![friendly_name("other")],
        };
        let plaintext_key = SafeBag {
            bag: Bag::Other {
                oid: ObjectIdentifier::new(oid::OID_PKCS12_KEY_BAG).unwrap(),
                value: der::octet_string(&[1, 2, 3]),
            },
            attributes: vec![friendly_name("plaintext")],
        };
        let data = synthetic(vec![key, secret, unknown, plaintext_key]);
        let verified = parse(&data).unwrap().verify("changeit").unwrap();
        assert_eq!(
            verified.entries,
            vec![
                KeystoreEntry {
                    alias: "private".into(),
                    certificate: None,
                    content: Content::Certificates {
                        kind: Kind::PrivateKey,
                        certificates: vec![],
                    },
                    chain_warning: None,
                },
                KeystoreEntry {
                    alias: "secret".into(),
                    certificate: None,
                    content: Content::Certificates {
                        kind: Kind::SecretKey,
                        certificates: vec![],
                    },
                    chain_warning: None,
                },
            ]
        );
        assert!(verified.incomplete);
    }

    #[test]
    fn summarizes_the_certificate_sharing_a_private_key_id() {
        let key = |alias, id: &[u8]| SafeBag {
            bag: Bag::ShroudedKey(EncryptedPrivateKeyInfo {
                algorithm: AlgorithmIdentifier::with_null(
                    ObjectIdentifier::new(oid::OID_PBES2).unwrap(),
                ),
                encrypted_data: vec![1, 2, 3],
            }),
            attributes: vec![friendly_name(alias), local_key_id(id)],
        };
        let certificate = SafeBag {
            bag: Bag::Cert(Certificate::parse(fixture_certificate_der()).unwrap()),
            attributes: vec![friendly_name("matched"), local_key_id(&[2])],
        };
        let data = synthetic(vec![
            key("matched", &[2]),
            key("unmatched", &[3]),
            certificate,
        ]);
        let verified = parse(&data).unwrap().verify("changeit").unwrap();
        assert_eq!(verified.entries[0].alias, "matched");
        assert_eq!(verified.entries[0].certificate, Some(fixture_summary()));
        assert_eq!(verified.entries[1].alias, "unmatched");
        assert_eq!(verified.entries[1].certificate, None);
        assert!(!verified.incomplete);
    }

    #[test]
    fn malformed_bag_does_not_hide_later_entries_in_a_verified_store() {
        let secret = |alias| SafeBag {
            bag: Bag::Secret {
                oid: ObjectIdentifier::new(oid::OID_PKCS12_SECRET_BAG).unwrap(),
                value: der::octet_string(&[1]),
            },
            attributes: vec![friendly_name(alias)],
        };
        let malformed = SafeBag {
            bag: Bag::Other {
                oid: ObjectIdentifier::new(oid::OID_PKCS12_CERT_BAG).unwrap(),
                value: der::null(),
            },
            attributes: vec![],
        };
        let data = synthetic(vec![secret("first"), malformed, secret("last")]);
        let verified = parse(&data).unwrap().verify("changeit").unwrap();
        assert_eq!(verified.entries.len(), 2);
        assert_eq!(verified.entries[0].alias, "first");
        assert_eq!(verified.entries[1].alias, "last");
        assert!(verified.incomplete);
    }

    #[test]
    fn reads_passwordless_java_truststores_without_a_mac() {
        let data = include_bytes!("../tests/fixtures/passwordless.p12");
        assert!(Pfx::parse(data).unwrap().mac.is_none());
        for password in ["", "changeit"] {
            let verified = parse(data).unwrap().verify(password).unwrap();
            assert!(!verified.incomplete);
            assert_eq!(verified.entries.len(), 1);
            assert_eq!(verified.entries[0].alias, "root-cert");
            assert_eq!(verified.entries[0].kind(), "Trusted certificate");
            assert_eq!(verified.entries[0].certificate, Some(fixture_summary()));
            assert_eq!(
                verified.entries[0].certificates(),
                [fixture_certificate_der().to_vec()]
            );
        }
    }

    #[test]
    fn encrypted_store_without_mac_still_requires_a_password() {
        let data = include_bytes!("../tests/fixtures/encrypted-no-mac.p12");
        assert!(Pfx::parse(data).unwrap().mac.is_none());
        let store = parse(data).unwrap();
        for password in ["", "wrong"] {
            assert!(matches!(store.verify(password), Err(VerifyError::Password)));
        }
        let verified = store.verify("changeit").unwrap();
        assert!(!verified.incomplete);
        assert_eq!(verified.entries.len(), 1);
        assert_eq!(verified.entries[0].alias, "root-cert");
        assert_eq!(verified.entries[0].certificate, Some(fixture_summary()));
        assert_eq!(
            verified.entries[0].certificates(),
            [fixture_certificate_der().to_vec()]
        );
    }

    fn secret_bag() -> SafeBag {
        SafeBag {
            bag: Bag::Secret {
                oid: ObjectIdentifier::new(oid::OID_PKCS12_SECRET_BAG).unwrap(),
                value: der::octet_string(&[1, 2, 3]),
            },
            attributes: vec![friendly_name("secret")],
        }
    }

    fn pbes2(cipher: Pbes2Cipher) -> Pbes2 {
        Pbes2 {
            salt: vec![7; 8],
            iterations: 1,
            key_length: None,
            prf: Hash::Sha256,
            cipher,
        }
    }

    fn legacy(kind: LegacyPbeKind) -> LegacyPbe {
        LegacyPbe {
            salt: vec![7; 8],
            iterations: 1,
            kind,
        }
    }

    /// A store whose only safe is EncryptedData, with no MacData.
    fn encrypted_without_mac(algorithm: AlgorithmIdentifier, ciphertext: &[u8]) -> Vec<u8> {
        let data = ObjectIdentifier::new(oid::OID_PKCS7_DATA).unwrap();
        let encrypted = der::sequence(
            &[
                der::integer(&[0]),
                der::sequence(
                    &[
                        der::oid(&data),
                        algorithm.encode(),
                        der::implicit(0, false, ciphertext),
                    ]
                    .concat(),
                ),
            ]
            .concat(),
        );
        let safe = ContentInfo {
            content_type: ObjectIdentifier::new(oid::OID_PKCS7_ENCRYPTED_DATA).unwrap(),
            content: encrypted,
        };
        Pfx {
            version: 3,
            auth_safe: ContentInfo {
                content_type: data,
                content: der::octet_string(&der::sequence(&safe.encode())),
            },
            mac: None,
        }
        .encode()
    }

    #[test]
    fn encrypted_stores_without_mac_reject_wrong_passwords_with_every_scheme() {
        let plaintext = encode_safe_contents(&[secret_bag()]);
        let mut stores = Vec::new();
        for cipher in [
            Pbes2Cipher::Aes128Cbc { iv: vec![1; 16] },
            Pbes2Cipher::Aes192Cbc { iv: vec![1; 16] },
            Pbes2Cipher::Aes256Cbc { iv: vec![1; 16] },
            Pbes2Cipher::DesEde3Cbc { iv: vec![1; 8] },
        ] {
            let pbe = pbes2(cipher);
            let ciphertext = pbe.encrypt(&plaintext, b"changeit").unwrap();
            stores.push(encrypted_without_mac(pbe.to_algorithm(), &ciphertext));
        }
        for kind in [
            LegacyPbeKind::Rc4_40,
            LegacyPbeKind::Rc4_128,
            LegacyPbeKind::DesEde3,
            LegacyPbeKind::DesEde2,
            LegacyPbeKind::Rc2_40,
        ] {
            let pbe = legacy(kind);
            let ciphertext = pbe.encrypt(&plaintext, b"changeit").unwrap();
            let mut algorithm = pbe.to_algorithm();
            // Crown writes the two RC4 OIDs swapped.
            let rfc_oid = match kind {
                LegacyPbeKind::Rc4_40 => Some(PBE_SHA1_40BIT_RC4),
                LegacyPbeKind::Rc4_128 => Some(PBE_SHA1_128BIT_RC4),
                _ => None,
            };
            if let Some(arcs) = rfc_oid {
                algorithm.oid = ObjectIdentifier::new(arcs).unwrap();
            }
            stores.push(encrypted_without_mac(algorithm, &ciphertext));
        }
        for data in stores {
            let store = parse(&data).unwrap();
            for password in ["", "\0", "wrong", "changeiT"] {
                assert!(matches!(store.verify(password), Err(VerifyError::Password)));
            }
            let verified = store.verify("changeit").unwrap();
            assert!(!verified.incomplete);
            assert_eq!(verified.entries.len(), 1);
            assert_eq!(verified.entries[0].alias, "secret");
        }
    }

    #[test]
    fn wrong_password_with_valid_padding_is_rejected_without_a_mac() {
        let pbe = pbes2(Pbes2Cipher::Aes256Cbc { iv: vec![1; 16] });
        let ciphertext = pbe
            .encrypt(&encode_safe_contents(&[secret_bag()]), b"changeit")
            .unwrap();
        let store = parse(&encrypted_without_mac(pbe.to_algorithm(), &ciphertext)).unwrap();
        // About 1 wrong key in 256 decrypts to plaintext with valid padding.
        let password = (0..10_000)
            .map(|n| format!("wrong{n}"))
            .find(|password| pbe.decrypt(&ciphertext, password.as_bytes()).is_ok())
            .unwrap();
        assert!(matches!(
            store.verify(&password),
            Err(VerifyError::Password)
        ));
    }

    #[test]
    fn unreadable_encryption_without_a_mac_is_incomplete_rather_than_a_wrong_password() {
        let plaintext = encode_safe_contents(&[secret_bag()]);
        let aes = pbes2(Pbes2Cipher::Aes256Cbc { iv: vec![1; 16] });
        let ciphertext = aes.encrypt(&plaintext, b"changeit").unwrap();
        let unknown = AlgorithmIdentifier::with_null(ObjectIdentifier::new(&[1, 2, 3, 4]).unwrap());
        let excessive = Pbes2 {
            iterations: MAX_ITERATIONS + 1,
            ..aes.clone()
        };
        let mismatched_key = Pbes2 {
            key_length: Some(16),
            ..aes.clone()
        };
        let triple_des = legacy(LegacyPbeKind::DesEde3);
        for data in [
            encrypted_without_mac(unknown, &ciphertext),
            encrypted_without_mac(excessive.to_algorithm(), &ciphertext),
            encrypted_without_mac(mismatched_key.to_algorithm(), &ciphertext),
            encrypted_without_mac(aes.to_algorithm(), &ciphertext[1..]),
            encrypted_without_mac(aes.to_algorithm(), &[]),
            encrypted_without_mac(triple_des.to_algorithm(), &[0; 15]),
        ] {
            let verified = parse(&data).unwrap().verify("").unwrap();
            assert!(verified.entries.is_empty());
            assert!(verified.incomplete);
        }
    }

    #[test]
    fn reads_openssl_stores_without_a_mac_only_with_the_right_password() {
        for data in OPENSSL_NO_MAC {
            let store = parse(data).unwrap();
            assert!(store.0.mac.is_none());
            for password in ["", "wrong", VALID_PADDING_PASSWORD] {
                assert!(matches!(store.verify(password), Err(VerifyError::Password)));
            }
            let verified = store.verify("changeit").unwrap();
            assert_eq!(
                verified.entries,
                vec![KeystoreEntry {
                    alias: "JKS TUI test fixture".into(),
                    certificate: Some(fixture_summary()),
                    content: Content::Certificates {
                        kind: Kind::Certificate,
                        certificates: vec![fixture_certificate_der().to_vec()],
                    },
                    chain_warning: None,
                }]
            );
            assert!(!verified.incomplete);
        }
    }

    #[test]
    fn openssl_aes_fixture_has_a_wrong_password_with_valid_padding() {
        // tests/fixtures/README.md names this password for manual testing.
        let safe = Pfx::parse(OPENSSL_NO_MAC_AES)
            .unwrap()
            .authenticated_safe()
            .unwrap();
        let mut reader = Reader::new(&safe);
        let mut safes = reader.read_sequence().unwrap();
        let info = ContentInfo::parse_reader(&mut safes).unwrap();
        let plaintext = decrypt_safe(&info.content, VALID_PADDING_PASSWORD.as_bytes())
            .ok()
            .unwrap();
        assert!(!is_safe_contents(&plaintext));
    }

    #[test]
    fn invalid_ciphertext_length_without_a_mac_is_incomplete() {
        let data = include_bytes!("../tests/fixtures/invalid-ciphertext-no-mac.p12");
        let store = parse(data).unwrap();
        for password in ["", "changeit"] {
            let verified = store.verify(password).unwrap();
            assert!(verified.entries.is_empty());
            assert!(verified.incomplete);
        }
    }

    #[test]
    fn opens_empty_and_nul_password_stores_without_a_mac_with_an_empty_password() {
        let plaintext = encode_safe_contents(&[secret_bag()]);
        for password in [b"".as_slice(), b"\0".as_slice()] {
            let aes = pbes2(Pbes2Cipher::Aes256Cbc { iv: vec![1; 16] });
            let triple_des = legacy(LegacyPbeKind::DesEde3);
            for data in [
                encrypted_without_mac(
                    aes.to_algorithm(),
                    &aes.encrypt(&plaintext, password).unwrap(),
                ),
                encrypted_without_mac(
                    triple_des.to_algorithm(),
                    &triple_des.encrypt(&plaintext, password).unwrap(),
                ),
            ] {
                let store = parse(&data).unwrap();
                assert!(matches!(
                    store.verify("changeit"),
                    Err(VerifyError::Password)
                ));
                let verified = store.verify("").unwrap();
                assert!(!verified.incomplete);
                assert_eq!(verified.entries.len(), 1);
                assert_eq!(verified.entries[0].alias, "secret");
            }
        }
    }

    #[test]
    fn rejects_failed_mac() {
        let mut pfx = Pfx::parse(MODERN).unwrap();
        pfx.mac.as_mut().unwrap().digest[0] ^= 1;
        assert!(matches!(
            parse(&pfx.encode()).unwrap().verify("changeit"),
            Err(VerifyError::Password)
        ));
    }

    #[test]
    fn rejects_excessive_mac_work_before_prompting() {
        let mut pfx = Pfx::parse(MODERN).unwrap();
        pfx.mac.as_mut().unwrap().iterations = MAX_ITERATIONS + 1;
        assert!(parse(&pfx.encode()).is_err());
    }

    #[test]
    fn opens_empty_password_stores_without_a_prompt() {
        for password in [b"".as_slice(), b"\0".as_slice()] {
            let data = Pfx::build(vec![], password, 100, &mut TestRng(0))
                .unwrap()
                .encode();
            let verified = parse(&data).unwrap().verify("").unwrap();
            assert!(verified.entries.is_empty());
            assert!(!verified.incomplete);
        }
    }

    #[test]
    fn opens_java_empty_and_nul_password_stores_with_an_empty_password() {
        // Java's empty-password store only opens through the NUL fallback.
        assert!(parse(EMPTY_PASSWORD).unwrap().0.verify_mac(b"").is_err());
        assert!(parse(EMPTY_PASSWORD_NO_MAC).unwrap().0.mac.is_none());
        for data in [EMPTY_PASSWORD, NUL_PASSWORD, EMPTY_PASSWORD_NO_MAC] {
            let store = parse(data).unwrap();
            assert!(matches!(
                store.verify("changeit"),
                Err(VerifyError::Password)
            ));
            let verified = store.verify("").unwrap();
            assert_eq!(
                verified.entries,
                vec![KeystoreEntry {
                    alias: "root-cert".into(),
                    certificate: Some(fixture_summary()),
                    content: Content::Certificates {
                        kind: Kind::TrustedCertificate,
                        certificates: vec![fixture_certificate_der().to_vec()],
                    },
                    chain_warning: None,
                }]
            );
            assert!(!verified.incomplete);
        }
    }
    fn raw_certificate(der: &[u8], attributes: Vec<crown::x509::attribute::Attribute>) -> SafeBag {
        SafeBag {
            bag: Bag::Other {
                oid: ObjectIdentifier::new(oid::OID_PKCS12_CERT_BAG).unwrap(),
                value: der::sequence(
                    &[
                        der::oid(&ObjectIdentifier::new(oid::OID_X509_CERTIFICATE).unwrap()),
                        der::explicit(0, &der::octet_string(der)),
                    ]
                    .concat(),
                ),
            },
            attributes,
        }
    }

    #[test]
    fn retains_exact_certificates_and_builds_key_chains_from_unnamed_ca_bags() {
        use crate::test_support::metadata_certificate;
        let leaf = metadata_certificate("leaf", "intermediate", &[0, 0, 1], &[]);
        let intermediate = metadata_certificate("intermediate", "root", &[2], &[]);
        let root = metadata_certificate("root", "root", &[3], &[]);
        let unrelated = metadata_certificate("other", "other", &[4], &[]);
        let key = SafeBag {
            bag: Bag::ShroudedKey(EncryptedPrivateKeyInfo {
                algorithm: AlgorithmIdentifier::with_null(
                    ObjectIdentifier::new(oid::OID_PBES2).unwrap(),
                ),
                encrypted_data: vec![1, 2, 3],
            }),
            attributes: vec![friendly_name("key"), local_key_id(&[1])],
        };
        let data = synthetic(vec![
            key,
            raw_certificate(&root, vec![]),
            raw_certificate(&unrelated, vec![]),
            raw_certificate(&leaf, vec![local_key_id(&[1])]),
            raw_certificate(&intermediate, vec![]),
            raw_certificate(&root, vec![]),
        ]);
        let verified = parse(&data).unwrap().verify("changeit").unwrap();
        assert!(!verified.incomplete);
        // Chain members are not listed again, but an unrelated certificate is.
        assert_eq!(verified.entries.len(), 2);
        assert_eq!(
            verified.entries[0].certificates(),
            [leaf, intermediate, root]
        );
        assert_eq!(verified.entries[0].chain_warning, None);
        assert_eq!(verified.entries[1].alias, "other");
        assert_eq!(verified.entries[1].kind(), "Certificate");
        assert_eq!(verified.entries[1].certificates(), [unrelated]);
    }

    #[test]
    fn names_unnamed_keys_and_lists_plain_certificates_like_openssl_writes_them() {
        use crate::test_support::metadata_certificate;
        let leaf = metadata_certificate("leaf", "ca", &[1], &[]);
        let ca = metadata_certificate("ca", "ca", &[2], &[]);
        let loose = metadata_certificate("loose", "loose", &[3], &[]);
        let key = |id: &[u8]| SafeBag {
            bag: Bag::ShroudedKey(EncryptedPrivateKeyInfo {
                algorithm: AlgorithmIdentifier::with_null(
                    ObjectIdentifier::new(oid::OID_PBES2).unwrap(),
                ),
                encrypted_data: vec![1, 2, 3],
            }),
            attributes: vec![local_key_id(id)],
        };
        let data = synthetic(vec![
            key(&[1]),
            key(&[9]),
            raw_certificate(&leaf, vec![local_key_id(&[1])]),
            raw_certificate(&ca, vec![]),
            raw_certificate(&loose, vec![friendly_name("named")]),
            raw_certificate(b"unreadable", vec![]),
        ]);
        let verified = parse(&data).unwrap().verify("changeit").unwrap();
        assert!(!verified.incomplete);
        let listed: Vec<_> = verified
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.alias.as_str(),
                    entry.kind(),
                    entry.certificates().len(),
                )
            })
            .collect();
        assert_eq!(
            listed,
            [
                ("Certificate 1", "Certificate", 1),
                ("Private key 1", "Private key", 0),
                ("leaf", "Private key", 2),
                ("named", "Certificate", 1),
            ]
        );
    }

    #[test]
    fn malformed_and_negative_serial_certificates_remain_inspectable() {
        use crate::test_support::metadata_certificate;
        use crown::x509::attribute::Attribute;
        let negative = metadata_certificate("negative", "negative", &[0xff], &[]);
        let trusted = |name| {
            vec![
                friendly_name(name),
                Attribute::new(
                    ObjectIdentifier::new(TRUSTED_KEY_USAGE).unwrap(),
                    vec![der::oid(
                        &ObjectIdentifier::new(&[2, 5, 29, 37, 0]).unwrap(),
                    )],
                ),
            ]
        };
        let data = synthetic(vec![
            raw_certificate(b"unreadable", trusted("malformed")),
            raw_certificate(&negative, trusted("negative")),
        ]);
        let verified = parse(&data).unwrap().verify("changeit").unwrap();
        assert!(!verified.incomplete);
        assert_eq!(verified.entries.len(), 2);
        assert_eq!(verified.entries[0].certificates(), [b"unreadable".to_vec()]);
        assert!(verified.entries[0].certificate.is_none());
        assert_eq!(verified.entries[1].certificates(), [negative]);
        assert_eq!(
            certificate::details::Details::parse(&verified.entries[1].certificates()[0])
                .unwrap()
                .serial_decimal,
            "-1"
        );
    }
}
