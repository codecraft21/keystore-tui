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
        self.open_with_budget(password, MAX_TOTAL_ITERATIONS)
    }

    pub(super) fn open_with_budget(
        &self,
        password: &str,
        mut remaining_iterations: u64,
    ) -> Result<(Verified, Option<Writable>), VerifyError> {
        let mut password_bytes = password.as_bytes();
        // PKCS12 stores can omit MacData even when their contents are encrypted.
        // When a MAC is present, it must still verify before reading any entries.
        if let Some(mac) = &self.0.mac {
            let cost = u64::from(mac.iterations);
            if cost > remaining_iterations {
                return Err(VerifyError::Invalid(
                    "PKCS12 MAC iteration count is unsupported",
                ));
            }
            remaining_iterations -= cost;
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

        let (contents, password_bytes) =
            match self.read_bags_with_budget(password_bytes, &mut remaining_iterations) {
                // Without a MAC, only decryption can tell whether an empty password
                // was stored in Java's NUL encoding.
                Err(VerifyError::Password) if password.is_empty() => (
                    self.read_bags_with_budget(b"\0", &mut remaining_iterations)?,
                    &b"\0"[..],
                ),
                result => (result?, password_bytes),
            };
        let (listed, unlisted) = list(&contents.bags);
        let incomplete = contents.incomplete || unlisted;
        let (entries, sources) = listed.into_iter().unzip();
        let mac_iterations = self
            .0
            .mac
            .as_ref()
            .map(|mac| mac.iterations.max(PBE_ITERATIONS));
        // Saving a store that was not read completely would lose the rest.
        let writable = (!incomplete).then(|| Writable {
            bags: contents.bags,
            safes: contents.safes,
            mac_iterations,
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
    #[cfg(test)]
    pub(super) fn read_bags(&self, password: &[u8]) -> Result<Contents, VerifyError> {
        let mut remaining_iterations = MAX_TOTAL_ITERATIONS.saturating_sub(
            self.0
                .mac
                .as_ref()
                .map_or(0, |mac| u64::from(mac.iterations)),
        );
        self.read_bags_with_budget(password, &mut remaining_iterations)
    }

    fn read_bags_with_budget(
        &self,
        password: &[u8],
        remaining_iterations: &mut u64,
    ) -> Result<Contents, VerifyError> {
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
            let (content, safe_iterations) = if info.content_type.matches(oid::OID_PKCS7_DATA) {
                (
                    Reader::new(&info.content)
                        .read_octet_string_owned()
                        .map(Zeroizing::new)
                        .ok(),
                    None,
                )
            } else if encrypted {
                // Without a MAC, only decryption shows whether the password
                // is right. Most wrong keys fail CBC padding, but about 1 in
                // 256 pass it and RC4 has no padding, so plaintext that is
                // not SafeContents also means a wrong password.
                match decrypt_safe(&info.content, password, remaining_iterations) {
                    Ok((content, iterations))
                        if self.0.mac.is_some() || is_safe_contents(&content) =>
                    {
                        (
                            Some(Zeroizing::new(content)),
                            Some(iterations.max(PBE_ITERATIONS)),
                        )
                    }
                    Ok(_) | Err(SafeError::Decryption) if self.0.mac.is_none() => {
                        return Err(VerifyError::Password);
                    }
                    _ => (None, Some(PBE_ITERATIONS)),
                }
            } else {
                (None, None)
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
            safes.push(safe_iterations);
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
    /// For each safe, in file order, `Some(iterations)` if encrypted, else `None`.
    pub(super) safes: Vec<Option<u32>>,
    /// Whether any part could not be read.
    incomplete: bool,
}

/// Lists the entries that `bags` hold, sorted by alias, each with the indices
/// of the bags it comes from, and whether any bag could not be listed.
pub(super) fn list(bags: &[MetadataBag]) -> (Vec<(KeystoreEntry, Vec<usize>)>, bool) {
    use std::collections::{HashMap, HashSet, VecDeque};

    struct BagMeta {
        is_trusted: bool,
        local_key_id: Option<Vec<u8>>,
        friendly_name: Option<String>,
    }

    fn pop_unclaimed(queue: &mut VecDeque<usize>, claimed: &mut [bool]) -> Option<usize> {
        while let Some(index) = queue.pop_front() {
            if !claimed[index] {
                claimed[index] = true;
                return Some(index);
            }
        }
        None
    }

    let pool: Vec<_> = bags
        .iter()
        .filter_map(|bag| bag.certificate_der.as_deref())
        .collect();
    let pool = certificate::details::ParsedPool::new(&pool);
    let meta: Vec<BagMeta> = bags
        .iter()
        .map(|bag| BagMeta {
            is_trusted: bag
                .attributes
                .iter()
                .any(|attr| attr.oid.matches(TRUSTED_KEY_USAGE)),
            local_key_id: bag.local_key_id(),
            friendly_name: bag.friendly_name(),
        })
        .collect();
    let mut incomplete = false;
    let mut key_entries: Vec<(KeystoreEntry, Vec<usize>)> = Vec::new();
    let mut unnamed_keys = 0;

    // Match each private key to at most one non-trusted certificate bag sharing
    // its localKeyId. Prefer a matching friendlyName first, then a non-conflicting
    // name, then any remaining unclaimed non-trusted bag with that localKeyId.
    let mut claimed_certs = vec![false; bags.len()];
    let mut certs_by_id: HashMap<&[u8], VecDeque<usize>> = HashMap::new();
    let mut unnamed_certs_by_id: HashMap<&[u8], VecDeque<usize>> = HashMap::new();
    let mut certs_by_id_and_name: HashMap<(&[u8], &str), VecDeque<usize>> = HashMap::new();
    let mut key_leaves: Vec<(usize, Option<usize>)> = Vec::new();
    for (index, (bag, info)) in bags.iter().zip(&meta).enumerate() {
        if matches!(bag.bag, Bag::ShroudedKey(_)) {
            key_leaves.push((index, None));
        } else if bag.certificate_der.is_some()
            && !info.is_trusted
            && let Some(id) = info.local_key_id.as_deref()
        {
            certs_by_id.entry(id).or_default().push_back(index);
            if let Some(name) = info.friendly_name.as_deref() {
                certs_by_id_and_name
                    .entry((id, name))
                    .or_default()
                    .push_back(index);
            } else {
                unnamed_certs_by_id.entry(id).or_default().push_back(index);
            }
        }
    }
    for (key_index, leaf_slot) in &mut key_leaves {
        let info = &meta[*key_index];
        let (Some(id), Some(name)) = (info.local_key_id.as_deref(), info.friendly_name.as_deref())
        else {
            continue;
        };
        if let Some(cert_index) = certs_by_id_and_name
            .get_mut(&(id, name))
            .and_then(|queue| pop_unclaimed(queue, &mut claimed_certs))
        {
            *leaf_slot = Some(cert_index);
        }
    }
    for (key_index, leaf_slot) in &mut key_leaves {
        if leaf_slot.is_some() {
            continue;
        }
        let info = &meta[*key_index];
        let Some(id) = info.local_key_id.as_deref() else {
            continue;
        };
        let found = if info.friendly_name.is_some() {
            unnamed_certs_by_id
                .get_mut(id)
                .and_then(|queue| pop_unclaimed(queue, &mut claimed_certs))
                .or_else(|| {
                    certs_by_id
                        .get_mut(id)
                        .and_then(|queue| pop_unclaimed(queue, &mut claimed_certs))
                })
        } else {
            certs_by_id
                .get_mut(id)
                .and_then(|queue| pop_unclaimed(queue, &mut claimed_certs))
        };
        if let Some(cert_index) = found {
            *leaf_slot = Some(cert_index);
        }
    }

    for (index, leaf_index) in key_leaves {
        let leaf = leaf_index.and_then(|leaf| bags[leaf].certificate_der.as_deref());
        // OpenSSL only stores a friendly name when given one.
        let alias = meta[index]
            .friendly_name
            .clone()
            .or_else(|| leaf.and_then(certificate_file::subject_name))
            .unwrap_or_else(|| {
                unnamed_keys += 1;
                format!("Private key {unnamed_keys}")
            });
        let (certificates, chain_warning) =
            leaf.map_or_else(|| (vec![], None), |leaf| pool.chain(leaf));
        key_entries.push((
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

    let key_chain_certs: HashSet<&[u8]> = key_entries
        .iter()
        .flat_map(|(entry, _)| entry.certificates().iter().map(Vec::as_slice))
        .collect();
    let mut other_entries: Vec<(KeystoreEntry, Vec<usize>)> = Vec::new();
    let mut trusted_entries: HashMap<(&str, &[u8]), usize> = HashMap::new();
    let mut unnamed_certificates = 0;
    for (index, (bag, info)) in bags.iter().zip(&meta).enumerate() {
        match &bag.bag {
            Bag::Secret { .. } => {
                if let Some(alias) = info.friendly_name.clone() {
                    other_entries.push((
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
                if claimed_certs[index] {
                    continue;
                }
                let der = bag.certificate_der.as_deref().unwrap();
                // Java identifies trusted entries with its trustedKeyUsage
                // attribute. Other tools store plain certificates: unnamed
                // chain certificates are hidden while part of a key's chain,
                // whereas standalone named certificates stay visible.
                if !info.is_trusted {
                    if info.friendly_name.is_none() && key_chain_certs.contains(der) {
                        continue;
                    }
                    let alias = info
                        .friendly_name
                        .clone()
                        .or_else(|| certificate_file::subject_name(der))
                        .unwrap_or_else(|| {
                            unnamed_certificates += 1;
                            format!("Certificate {unnamed_certificates}")
                        });
                    let (certificates, chain_warning) = pool.chain(der);
                    other_entries.push((
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
                if let Some(alias) = info.friendly_name.as_deref() {
                    // An identical copy of a trusted certificate already
                    // listed under the same name adds nothing.
                    if let Some(&entry_index) = trusted_entries.get(&(alias, der)) {
                        other_entries[entry_index].1.push(index);
                        continue;
                    }
                    let (certificates, chain_warning) = pool.chain(der);
                    trusted_entries.insert((alias, der), other_entries.len());
                    other_entries.push((
                        KeystoreEntry {
                            alias: alias.to_owned(),
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
    drop(key_chain_certs);
    key_entries.extend(other_entries);
    key_entries.sort_by(|a, b| a.0.alias.cmp(&b.0.alias));
    (key_entries, incomplete)
}
