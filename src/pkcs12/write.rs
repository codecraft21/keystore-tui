use super::*;

/// Why a PKCS12 keystore could not be changed or written.
pub type WriteError = &'static str;

pub(super) const PBE_ITERATIONS: u32 = 10_000;
pub(super) const SALT_SIZE: usize = 20;
pub(super) const ANY_EXTENDED_KEY_USAGE: &[u64] = &[2, 5, 29, 37, 0];

/// A verified store's bags, for writing it back. Each bag keeps its original
/// bytes, so encrypted keys are written exactly as they were read and are
/// never decrypted. Only bags whose alias changes are rebuilt.
#[derive(Clone)]
pub struct Writable {
    pub(super) bags: Vec<MetadataBag>,
    /// Whether each safe, by a bag's `safe` index, is written encrypted.
    pub(super) safes: Vec<bool>,
    /// Whether the store gets an integrity MAC.
    pub(super) mac: bool,
    /// The password as the store encodes it, which for an empty password
    /// may be a NUL character.
    pub(super) password: Zeroizing<Vec<u8>>,
    /// The bags each listed entry comes from, in listing order.
    pub(super) sources: Vec<Vec<usize>>,
}

impl Writable {
    /// A store without entries, protected by `password`.
    pub fn empty(password: &str) -> Self {
        Self {
            bags: Vec::new(),
            // Certificates are encrypted; keys carry their own encryption.
            safes: vec![true, false],
            mac: true,
            password: Zeroizing::new(password.as_bytes().to_vec()),
            sources: Vec::new(),
        }
    }

    /// The password to verify the written store with.
    pub fn password(&self) -> &str {
        std::str::from_utf8(&self.password).unwrap_or_default()
    }

    fn relist(&mut self) -> Vec<KeystoreEntry> {
        let (entries, sources) = list(&self.bags).0.into_iter().unzip();
        self.sources = sources;
        entries
    }

    /// Keeps the bags at these indices, in order.
    fn keep(&mut self, indices: &[usize]) {
        let mut bags: Vec<_> = std::mem::take(&mut self.bags)
            .into_iter()
            .map(Some)
            .collect();
        self.bags = indices
            .iter()
            .filter_map(|&index| bags[index].take())
            .collect();
    }

    /// Removes the entry listed at `index` and returns the new listing. A
    /// private key goes with its certificate, and with the chain
    /// certificates no other entry uses, which would otherwise turn into
    /// entries of their own.
    pub fn remove(&mut self, index: usize) -> Vec<KeystoreEntry> {
        let listed: Vec<usize> = self.sources.iter().flatten().copied().collect();
        let removed = &self.sources[index];
        let kept: Vec<usize> = (0..self.bags.len())
            .filter(|bag| !removed.contains(bag))
            .collect();
        self.keep(&kept);
        // A bag that was in no entry before and is in one now was only
        // there as part of the removed key's chain.
        let orphans: Vec<usize> = list(&self.bags)
            .0
            .into_iter()
            .filter(|(_, sources)| sources.iter().any(|&bag| !listed.contains(&kept[bag])))
            .flat_map(|(_, sources)| sources)
            .collect();
        let kept: Vec<usize> = (0..self.bags.len())
            .filter(|bag| !orphans.contains(bag))
            .collect();
        self.keep(&kept);
        self.relist()
    }

    /// Gives the entry listed at `index` the friendly name `alias`, on its
    /// key and certificate bags, and returns the new listing.
    pub fn rename(&mut self, index: usize, alias: &str) -> Result<Vec<KeystoreEntry>, WriteError> {
        let renamed = self.sources[index]
            .iter()
            .map(|&source| {
                let bag = &self.bags[source];
                let raw = with_friendly_name(&bag.raw, alias).ok()?;
                let mut renamed = parse_metadata_bag(&raw).ok()??;
                renamed.safe = bag.safe;
                Some((source, renamed))
            })
            .collect::<Option<Vec<_>>>()
            .ok_or("the entry could not be rebuilt")?;
        for (source, bag) in renamed {
            self.bags[source] = bag;
        }
        Ok(self.relist())
    }

    /// Adds a certificate bag that Java reads as a trusted certificate, and
    /// returns the new listing. It joins the encrypted certificates when the
    /// store has any, and is stored as openly as the others otherwise.
    pub fn insert_trusted_certificate(
        &mut self,
        alias: &str,
        certificate: &[u8],
    ) -> Result<Vec<KeystoreEntry>, WriteError> {
        let attributes = vec![
            friendly_name_attribute(alias),
            attribute(
                TRUSTED_KEY_USAGE,
                &der::oid(&object_id(ANY_EXTENDED_KEY_USAGE)),
            ),
        ];
        self.push_certificate(certificate, attributes)?;
        Ok(self.relist())
    }

    /// Adds a certificate bag with these attributes to the safe that
    /// certificates go in.
    fn push_certificate(
        &mut self,
        certificate: &[u8],
        attributes: Vec<Vec<u8>>,
    ) -> Result<(), WriteError> {
        let certificate_bag = der::sequence(
            &[
                der::oid(&object_id(oid::OID_X509_CERTIFICATE)),
                der::explicit(0, &der::octet_string(certificate)),
            ]
            .concat(),
        );
        let safe = match self.safes.iter().position(|&encrypted| encrypted) {
            Some(safe) => safe,
            None if !self.safes.is_empty() => 0,
            None => {
                self.safes.push(self.mac);
                0
            }
        };
        self.push_bag(oid::OID_PKCS12_CERT_BAG, &certificate_bag, attributes, safe)
    }

    /// Adds a bag of type `kind` with `value` and `attributes` to `safe`.
    fn push_bag(
        &mut self,
        kind: &[u64],
        value: &[u8],
        mut attributes: Vec<Vec<u8>>,
        safe: usize,
    ) -> Result<(), WriteError> {
        // DER orders the elements of a SET OF by their encoding.
        attributes.sort();
        let mut content = [der::oid(&object_id(kind)), der::explicit(0, value)].concat();
        if !attributes.is_empty() {
            content.extend(der::set(&attributes.concat()));
        }
        let mut bag = parse_metadata_bag(&der::sequence(&content))
            .ok()
            .flatten()
            .ok_or("the entry could not be stored")?;
        bag.safe = safe;
        self.bags.push(bag);
        Ok(())
    }

    /// Adds a private key, given as its PKCS #8 encoding, with its
    /// certificate chain, leaf first, and returns the new listing. The key is
    /// encrypted with the store's password, as Java expects, in a safe that
    /// is not encrypted again. The key and its certificate share a local key
    /// ID, and chain certificates the store already holds are not repeated.
    pub fn insert_private_key(
        &mut self,
        alias: &str,
        key: &[u8],
        chain: &[Vec<u8>],
        rng: &mut impl Rng,
    ) -> Result<Vec<KeystoreEntry>, WriteError> {
        let encrypted = encrypt_key(key, &self.password, rng)?;
        let mut attributes = vec![friendly_name_attribute(alias)];
        if let Some((leaf, issuers)) = chain.split_first() {
            let id: [u8; 20] = Sha1::digest(leaf).into();
            let key_id = attribute(oid::OID_PKCS9_LOCAL_KEY_ID, &der::octet_string(&id));
            attributes.push(key_id.clone());
            self.push_certificate(leaf, vec![friendly_name_attribute(alias), key_id])?;
            for issuer in issuers {
                let held = self.bags.iter().any(|bag| {
                    bag.certificate_der.as_deref() == Some(issuer) && bag.attributes.is_empty()
                });
                if !held {
                    self.push_certificate(issuer, vec![])?;
                }
            }
        }
        let safe = match self.safes.iter().position(|&encrypted| !encrypted) {
            Some(safe) => safe,
            None => {
                self.safes.push(false);
                self.safes.len() - 1
            }
        };
        self.push_bag(
            oid::OID_PKCS12_SHROUDED_KEY_BAG,
            &encrypted,
            attributes,
            safe,
        )?;
        Ok(self.relist())
    }

    /// Replaces the certificate chain, leaf first, of the private key
    /// listed at `index` under `alias`, and returns the new listing. The
    /// key stays encrypted as it is; it and its new certificate are named
    /// `alias` and share a new local key ID. The old chain's certificates
    /// that no other entry uses are dropped, as when a key is removed.
    pub fn set_chain(
        &mut self,
        index: usize,
        alias: &str,
        chain: &[Vec<u8>],
    ) -> Result<Vec<KeystoreEntry>, WriteError> {
        const NOT_REBUILT: WriteError = "the entry could not be rebuilt";
        let (leaf, issuers) = chain.split_first().ok_or("the chain is empty")?;
        let key = self.sources[index]
            .first()
            .map(|&bag| &self.bags[bag])
            .filter(|bag| matches!(bag.bag, Bag::ShroudedKey(_)))
            .ok_or("not a private key entry")?;
        let id: [u8; 20] = Sha1::digest(leaf).into();
        let key_id = attribute(oid::OID_PKCS9_LOCAL_KEY_ID, &der::octet_string(&id));
        let raw = with_friendly_name(&key.raw, alias)
            .and_then(|raw| with_attribute(&raw, oid::OID_PKCS9_LOCAL_KEY_ID, key_id.clone()))
            .map_err(|_| NOT_REBUILT)?;
        let mut rebuilt = parse_metadata_bag(&raw).ok().flatten().ok_or(NOT_REBUILT)?;
        rebuilt.safe = key.safe;
        self.remove(index);
        self.push_certificate(leaf, vec![friendly_name_attribute(alias), key_id])?;
        for issuer in issuers {
            let held = self.bags.iter().any(|bag| {
                bag.certificate_der.as_deref() == Some(issuer) && bag.attributes.is_empty()
            });
            if !held {
                self.push_certificate(issuer, vec![])?;
            }
        }
        self.bags.push(rebuilt);
        Ok(self.relist())
    }

    /// The PKCS #8 encoding of the private key listed at `index`, decrypted
    /// in memory with the store's password, or `None` if that fails.
    pub fn private_key(&self, index: usize) -> Option<Zeroizing<Vec<u8>>> {
        let bag = &self.bags[*self.sources[index].first()?];
        let Bag::ShroudedKey(info) = &bag.bag else {
            return None;
        };
        decrypt_info(info, &self.password)
    }

    /// The PKCS #8 structure around the secret key listed at `index`,
    /// decrypted in memory with the store's password, or `None` if that
    /// fails or the entry is not a secret key as Java stores one.
    pub fn secret_key(&self, index: usize) -> Option<Zeroizing<Vec<u8>>> {
        let bag = &self.bags[*self.sources[index].first()?];
        let Bag::Secret { oid: kind, value } = &bag.bag else {
            return None;
        };
        decrypt_info(&secret_info(kind, value)?, &self.password)
    }

    /// Adds a secret key, given in its PKCS #8 structure, and returns the
    /// new listing. The key is encrypted with the store's password, as Java
    /// expects, in a safe that is not encrypted again. Like Java, it gets a
    /// local key ID made of the time `created`, in milliseconds since the
    /// Unix epoch.
    pub fn insert_secret_key(
        &mut self,
        alias: &str,
        key: &[u8],
        created: u64,
        rng: &mut impl Rng,
    ) -> Result<Vec<KeystoreEntry>, WriteError> {
        let encrypted = encrypt_key(key, &self.password, rng)?;
        let id = format!("Time {created}");
        let attributes = vec![
            friendly_name_attribute(alias),
            attribute(
                oid::OID_PKCS9_LOCAL_KEY_ID,
                &der::octet_string(id.as_bytes()),
            ),
        ];
        let safe = match self.safes.iter().position(|&encrypted| !encrypted) {
            Some(safe) => safe,
            None => {
                self.safes.push(false);
                self.safes.len() - 1
            }
        };
        self.push_bag(
            oid::OID_PKCS12_SECRET_BAG,
            &secret_value(&encrypted),
            attributes,
            safe,
        )?;
        Ok(self.relist())
    }

    /// Protects the store with `password` from now on. Java expects keys to
    /// be encrypted with the store's password, so each key is decrypted in
    /// memory with the current password and encrypted again with the new
    /// one, with a fresh salt from `rng`. Nothing changes unless every key
    /// can be re-encrypted.
    pub fn set_password(&mut self, password: &str, rng: &mut impl Rng) -> Result<(), WriteError> {
        if password.is_empty() {
            return Err("A PKCS12 keystore needs a password that is not empty.");
        }
        let is_key =
            |bag: &MetadataBag| matches!(bag.bag, Bag::ShroudedKey(_) | Bag::Secret { .. });
        if !self.mac && !self.safes.contains(&true) && !self.bags.iter().any(is_key) {
            return Err("This PKCS12 keystore is not protected by a password.");
        }
        let mut rebuilt = Vec::new();
        for (index, bag) in self.bags.iter().enumerate() {
            if !is_key(bag) {
                continue;
            }
            let value = reencrypt_key(&bag.bag, &self.password, password.as_bytes(), rng)?;
            let rebuilt_bag = with_value(&bag.raw, &value)
                .ok()
                .and_then(|raw| parse_metadata_bag(&raw).ok().flatten())
                .ok_or(
                    "A key in this keystore could not be rebuilt; the password was not changed.",
                )?;
            rebuilt.push((index, bag.safe, rebuilt_bag));
        }
        for (index, safe, mut bag) in rebuilt {
            bag.safe = safe;
            self.bags[index] = bag;
        }
        self.password = Zeroizing::new(password.as_bytes().to_vec());
        Ok(())
    }

    /// The store file. Encrypted safes and the MAC get fresh salts from
    /// `rng` and use AES-256-CBC with PBKDF2 and HMAC-SHA256, whatever the
    /// store used before; safes that were not encrypted stay so.
    pub fn encode(&self, rng: &mut impl Rng) -> Result<Vec<u8>, WriteError> {
        let failed = |_| "the PKCS12 keystore could not be encrypted";
        let mut safes = Vec::new();
        for (safe, &encrypted) in self.safes.iter().enumerate() {
            let bags: Vec<u8> = self
                .bags
                .iter()
                .filter(|bag| bag.safe == safe)
                .flat_map(|bag| bag.raw.iter().copied())
                .collect();
            if bags.is_empty() {
                continue;
            }
            let contents = Zeroizing::new(der::sequence(&bags));
            let info = if encrypted {
                let mut salt = vec![0; SALT_SIZE];
                rng.fill_bytes(&mut salt);
                let mut iv = vec![0; 16];
                rng.fill_bytes(&mut iv);
                let pbe = Pbes2 {
                    salt,
                    iterations: PBE_ITERATIONS,
                    key_length: None,
                    prf: Hash::Sha256,
                    cipher: Pbes2Cipher::Aes256Cbc { iv },
                };
                let ciphertext = pbe.encrypt(&contents, &self.password).map_err(failed)?;
                let encrypted_content = der::sequence(
                    &[
                        der::oid(&object_id(oid::OID_PKCS7_DATA)),
                        pbe.to_algorithm().encode(),
                        der::implicit(0, false, &ciphertext),
                    ]
                    .concat(),
                );
                ContentInfo {
                    content_type: object_id(oid::OID_PKCS7_ENCRYPTED_DATA),
                    content: der::sequence(&[der::integer(&[0]), encrypted_content].concat()),
                }
            } else {
                ContentInfo::data(&contents)
            };
            safes.extend(info.encode());
        }
        let authenticated_safe = der::sequence(&safes);
        let mac = if self.mac {
            let mut salt = vec![0; SALT_SIZE];
            rng.fill_bytes(&mut salt);
            let key = pkcs12kdf::derive(
                Hash::Sha256.factory(),
                &pkcs12_password(&self.password),
                &salt,
                3,
                u64::from(PBE_ITERATIONS),
                32,
            )
            .map(Zeroizing::new)
            .map_err(failed)?;
            let mut hmac = EvpHash::new_sha256_hmac(&key).map_err(failed)?;
            hmac.write_all(&authenticated_safe).map_err(failed)?;
            Some(MacData {
                digest_algorithm: AlgorithmIdentifier::with_null(object_id(Hash::Sha256.oid())),
                digest: hmac.sum(),
                salt,
                iterations: PBE_ITERATIONS,
            })
        } else {
            None
        };
        Ok(Pfx {
            version: 3,
            auth_safe: ContentInfo::data(&authenticated_safe),
            mac,
        }
        .encode())
    }
}
