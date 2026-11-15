use super::*;

pub struct Store(pub(super) Pfx);

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
        self.open(password).map(|(verified, _)| verified)
    }

    /// Verifies the password and lists the entries. A store that was read
    /// completely also comes in its writable form.
    pub fn open(&self, password: &str) -> Result<(Verified, Option<Writable>), VerifyError> {
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

        let (contents, password_bytes) = match self.read_bags(password_bytes) {
            // Without a MAC, only decryption can tell whether an empty password
            // was stored in Java's NUL encoding.
            Err(VerifyError::Password) if password.is_empty() => {
                (self.read_bags(b"\0")?, &b"\0"[..])
            }
            result => (result?, password_bytes),
        };
        let (listed, unlisted) = list(&contents.bags);
        let incomplete = contents.incomplete || unlisted;
        let (entries, sources) = listed.into_iter().unzip();
        // Saving a store that was not read completely would lose the rest.
        let writable = (!incomplete).then(|| Writable {
            bags: contents.bags,
            safes: contents.safes,
            mac: self.0.mac.is_some(),
            password: Zeroizing::new(password_bytes.to_vec()),
            sources,
        });
        Ok((
            Verified {
                entries,
                incomplete,
            },
            writable,
        ))
    }

    /// Reads every safe's bags, decrypting with `password`.
    pub(super) fn read_bags(&self, password: &[u8]) -> Result<Contents, VerifyError> {
        let safe = self
            .0
            .authenticated_safe()
            .map_err(|_| VerifyError::Invalid("invalid PKCS12 content"))?;
        let mut reader = Reader::new(&safe);
        let mut sequence = reader
            .read_sequence()
            .map_err(|_| VerifyError::Invalid("invalid PKCS12 content"))?;
        let mut bags = Vec::new();
        let mut safes = Vec::new();
        let mut incomplete = false;
        while !sequence.is_empty() {
            let info = match ContentInfo::parse_reader(&mut sequence) {
                Ok(info) => info,
                Err(_) => {
                    incomplete = true;
                    break;
                }
            };
            let encrypted = info.content_type.matches(oid::OID_PKCS7_ENCRYPTED_DATA);
            let content = if info.content_type.matches(oid::OID_PKCS7_DATA) {
                Reader::new(&info.content)
                    .read_octet_string_owned()
                    .map(Zeroizing::new)
                    .ok()
            } else if encrypted {
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
                                Ok(Some(mut bag)) => {
                                    bag.safe = safes.len();
                                    bags.push(bag);
                                }
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
            safes.push(encrypted);
        }
        Ok(Contents {
            bags,
            safes,
            incomplete,
        })
    }
}

/// What the safes of a store hold.
pub(super) struct Contents {
    pub(super) bags: Vec<MetadataBag>,
    /// Whether each safe, in file order, is encrypted.
    pub(super) safes: Vec<bool>,
    /// Whether any part could not be read.
    incomplete: bool,
}

/// Lists the entries that `bags` hold, sorted by alias, each with the indices
/// of the bags it comes from, and whether any bag could not be listed.
pub(super) fn list(bags: &[MetadataBag]) -> (Vec<(KeystoreEntry, Vec<usize>)>, bool) {
    let pool: Vec<_> = bags
        .iter()
        .filter_map(|bag| bag.certificate_der.as_deref())
        .collect();
    let is_key = |entry: &KeystoreEntry| {
        matches!(
            entry.content,
            Content::Certificates {
                kind: Kind::PrivateKey,
                ..
            }
        )
    };
    let mut incomplete = false;
    let mut entries: Vec<(KeystoreEntry, Vec<usize>)> = Vec::new();
    let mut unnamed_keys = 0;
    for (index, bag) in bags.iter().enumerate() {
        if matches!(bag.bag, Bag::ShroudedKey(_)) {
            // Java and OpenSSL give the key and its end-entity certificate
            // the same local key ID.
            let leaf_index = bag.local_key_id().and_then(|id| {
                bags.iter().position(|other| {
                    other.certificate_der.is_some() && other.local_key_id().as_ref() == Some(&id)
                })
            });
            let leaf = leaf_index.and_then(|leaf| bags[leaf].certificate_der.as_deref());
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
            entries.push((
                KeystoreEntry {
                    alias,
                    certificate: leaf.and_then(certificate::summarize),
                    content: Content::Certificates {
                        kind: Kind::PrivateKey,
                        certificates,
                    },
                    chain_warning,
                },
                std::iter::once(index).chain(leaf_index).collect(),
            ));
        }
    }
    let mut unnamed_certificates = 0;
    for (index, bag) in bags.iter().enumerate() {
        match &bag.bag {
            Bag::Secret { .. } => {
                if let Some(alias) = bag.friendly_name() {
                    entries.push((
                        KeystoreEntry {
                            alias,
                            certificate: None,
                            content: Content::Certificates {
                                kind: Kind::SecretKey,
                                certificates: vec![],
                            },
                            chain_warning: None,
                        },
                        vec![index],
                    ));
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
                    if entries.iter().any(|(entry, _)| {
                        is_key(entry) && entry.certificates().iter().any(|stored| stored == der)
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
                    entries.push((
                        KeystoreEntry {
                            alias,
                            certificate: certificate::summarize(der),
                            content: Content::Certificates {
                                kind: Kind::Certificate,
                                certificates,
                            },
                            chain_warning,
                        },
                        vec![index],
                    ));
                    continue;
                }
                if let Some(alias) = bag.friendly_name() {
                    // An identical copy of a trusted certificate already
                    // listed under the same name adds nothing.
                    if let Some((_, sources)) = entries.iter_mut().find(|(entry, _)| {
                        entry.alias == alias
                            && matches!(
                                entry.content,
                                Content::Certificates {
                                    kind: Kind::TrustedCertificate,
                                    ..
                                }
                            )
                            && entry.certificates().first().map(Vec::as_slice) == Some(der)
                    }) {
                        sources.push(index);
                        continue;
                    }
                    let (certificates, chain_warning) = certificate::details::chain(der, &pool);
                    entries.push((
                        KeystoreEntry {
                            alias,
                            certificate: certificate::summarize(der),
                            content: Content::Certificates {
                                kind: Kind::TrustedCertificate,
                                certificates,
                            },
                            chain_warning,
                        },
                        vec![index],
                    ));
                } else {
                    incomplete = true;
                }
            }
            Bag::ShroudedKey(_) => {}
            _ => incomplete = true,
        }
    }
    entries.sort_by(|a, b| a.0.alias.cmp(&b.0.alias));
    (entries, incomplete)
}
