use crown::{
    asn1::{
        der::{self, Reader},
        oid::{self, ObjectIdentifier},
    },
    core::CoreWrite,
    envelope::EvpHash,
    error::CryptoError,
    kdf::pkcs12kdf,
    pkcs7::ContentInfo,
    pkcs12::{Bag, MacData, Pfx, SafeBag},
    rng::Rng,
    x509::{
        algorithm::{AlgorithmIdentifier, Hash},
        attribute::parse_attributes,
        keys::EncryptedPrivateKeyInfo,
        pbe::{LegacyPbe, LegacyPbeKind, Pbes2, Pbes2Cipher, encrypt_private_key, pkcs12_password},
    },
};
use sha1::{Digest, Sha1};
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
    fn read_bags(&self, password: &[u8]) -> Result<Contents, VerifyError> {
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
struct Contents {
    bags: Vec<MetadataBag>,
    /// Whether each safe, in file order, is encrypted.
    safes: Vec<bool>,
    /// Whether any part could not be read.
    incomplete: bool,
}

/// Lists the entries that `bags` hold, sorted by alias, each with the indices
/// of the bags it comes from, and whether any bag could not be listed.
fn list(bags: &[MetadataBag]) -> (Vec<(KeystoreEntry, Vec<usize>)>, bool) {
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

/// Why a PKCS12 keystore could not be changed or written.
pub type WriteError = &'static str;

const PBE_ITERATIONS: u32 = 10_000;
const SALT_SIZE: usize = 20;
const ANY_EXTENDED_KEY_USAGE: &[u64] = &[2, 5, 29, 37, 0];

/// A verified store's bags, for writing it back. Each bag keeps its original
/// bytes, so encrypted keys are written exactly as they were read and are
/// never decrypted. Only bags whose alias changes are rebuilt.
pub struct Writable {
    bags: Vec<MetadataBag>,
    /// Whether each safe, by a bag's `safe` index, is written encrypted.
    safes: Vec<bool>,
    /// Whether the store gets an integrity MAC.
    mac: bool,
    /// The password as the store encodes it, which for an empty password
    /// may be a NUL character.
    password: Zeroizing<Vec<u8>>,
    /// The bags each listed entry comes from, in listing order.
    sources: Vec<Vec<usize>>,
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
        let encrypted = encrypt_private_key(
            key,
            &self.password,
            Pbes2Cipher::Aes256Cbc { iv: Vec::new() },
            PBE_ITERATIONS,
            rng,
        )
        .map_err(|_| "the key could not be encrypted")?
        .encode();
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

    /// The PKCS #8 encoding of the private key listed at `index`, decrypted
    /// in memory with the store's password.
    pub fn private_key(&self, index: usize) -> Result<Zeroizing<Vec<u8>>, WriteError> {
        let bag = self.sources[index]
            .first()
            .map(|&source| &self.bags[source]);
        let Some(Bag::ShroudedKey(info)) = bag.map(|bag| &bag.bag) else {
            return Err("the entry holds no private key");
        };
        pbe_decrypt(&info.algorithm, &info.encrypted_data, &self.password)
            .ok()
            .map(Zeroizing::new)
            .filter(|key| is_private_key_info(key))
            .ok_or("the key could not be decrypted with the keystore's password")
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

fn object_id(arcs: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::new(arcs).expect("static oid")
}

/// An `Attribute` with a single value.
fn attribute(arcs: &[u64], value: &[u8]) -> Vec<u8> {
    der::sequence(&[der::oid(&object_id(arcs)), der::set(value)].concat())
}

/// The `friendlyName` attribute, a BMPString as PKCS #9 requires.
fn friendly_name_attribute(alias: &str) -> Vec<u8> {
    let name: Vec<u8> = alias.encode_utf16().flat_map(u16::to_be_bytes).collect();
    let mut value = vec![0x1e];
    der::write_length(&mut value, name.len());
    value.extend(name);
    attribute(oid::OID_PKCS9_FRIENDLY_NAME, &value)
}

/// The bag `raw` with `alias` as its only friendly name. The bag's value
/// and other attributes keep their bytes.
fn with_friendly_name(raw: &[u8], alias: &str) -> Result<Vec<u8>, CryptoError> {
    let mut reader = Reader::new(raw);
    let mut bag = reader.read_sequence()?;
    let id = bag.read_raw_tlv()?;
    let value = bag.read_raw_tlv()?;
    let mut attributes = vec![friendly_name_attribute(alias)];
    if !bag.is_empty() {
        let mut set = bag.read_set()?;
        while !set.is_empty() {
            let attribute = set.read_raw_tlv()?;
            let is_name = Reader::new(attribute)
                .read_sequence()?
                .read_oid()?
                .matches(oid::OID_PKCS9_FRIENDLY_NAME);
            if !is_name {
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

struct MetadataBag {
    metadata: SafeBag,
    certificate_der: Option<Vec<u8>>,
    /// The bag as stored.
    raw: Vec<u8>,
    /// The index of the safe the bag is stored in.
    safe: usize,
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
    pbe_decrypt(&algorithm, ciphertext, password)
}

/// Decrypts `ciphertext` as its password-based encryption `algorithm` says.
fn pbe_decrypt(
    algorithm: &AlgorithmIdentifier,
    ciphertext: &[u8],
    password: &[u8],
) -> Result<Vec<u8>, SafeError> {
    let unreadable = |_| SafeError::Unreadable;
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
        let pbe = Pbes2::parse(algorithm).map_err(unreadable)?;
        let block_size = match pbe.cipher {
            Pbes2Cipher::Aes128Cbc { .. }
            | Pbes2Cipher::Aes192Cbc { .. }
            | Pbes2Cipher::Aes256Cbc { .. } => 16,
            Pbes2Cipher::DesEde3Cbc { .. } => 8,
        };
        check(pbe.iterations, &pbe.salt, block_size)?;
        pbe.decrypt(ciphertext, password)
    } else {
        let mut pbe = LegacyPbe::parse(algorithm).map_err(unreadable)?;
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

const OTHER_KEY_PASSWORD: WriteError = "A key in this keystore is protected by another password, so the keystore password was not changed.";
const UNSUPPORTED_KEY: WriteError = "A key in this keystore uses encryption that is not supported, so the keystore password was not changed.";

/// The value of a key bag, as its `[0]` element, with the key decrypted
/// with `old` and encrypted again with `new`. The decrypted key exists only
/// in memory and is wiped. A secret key is handled as Java stores it: an
/// encrypted PKCS #8 structure inside the secret bag.
fn reencrypt_key(
    bag: &Bag,
    old: &[u8],
    new: &[u8],
    rng: &mut impl Rng,
) -> Result<Vec<u8>, WriteError> {
    let secret;
    let (info, is_secret) = match bag {
        Bag::ShroudedKey(info) => (info, false),
        Bag::Secret { oid: kind, value } if kind.matches(oid::OID_PKCS12_SHROUDED_KEY_BAG) => {
            secret = Reader::new(value)
                .read_explicit(0)
                .and_then(|mut value| value.read_octet_string_owned())
                .and_then(|der| EncryptedPrivateKeyInfo::parse(&der))
                .map_err(|_| UNSUPPORTED_KEY)?;
            (&secret, true)
        }
        _ => return Err(UNSUPPORTED_KEY),
    };
    let key = pbe_decrypt(&info.algorithm, &info.encrypted_data, old)
        .map(Zeroizing::new)
        .map_err(|error| match error {
            SafeError::Unreadable => UNSUPPORTED_KEY,
            SafeError::Decryption => OTHER_KEY_PASSWORD,
        })?;
    // About 1 wrong password in 256 leaves valid padding, and RC4 has none.
    if !is_private_key_info(&key) {
        return Err(OTHER_KEY_PASSWORD);
    }
    let encrypted = encrypt_private_key(
        &key,
        new,
        Pbes2Cipher::Aes256Cbc { iv: Vec::new() },
        PBE_ITERATIONS,
        rng,
    )
    .map_err(|_| UNSUPPORTED_KEY)?
    .encode();
    Ok(if is_secret {
        der::explicit(
            0,
            &der::sequence(
                &[
                    der::oid(&object_id(oid::OID_PKCS12_SHROUDED_KEY_BAG)),
                    der::explicit(0, &der::octet_string(&encrypted)),
                ]
                .concat(),
            ),
        )
    } else {
        der::explicit(0, &encrypted)
    })
}

/// Whether `content` has the shape of a PKCS #8 `PrivateKeyInfo`: a version,
/// an algorithm, and the key octets, with optional fields after them.
pub(crate) fn is_private_key_info(content: &[u8]) -> bool {
    let mut reader = Reader::new(content);
    let Ok(mut info) = reader.read_sequence() else {
        return false;
    };
    info.read_integer().is_ok()
        && info.read_sequence().is_ok()
        && info.read_octet_string().is_ok()
        && reader.expect_end().is_ok()
}

/// The bag `raw` with `value` as its `[0]` value element. The bag's type and
/// attributes keep their bytes.
fn with_value(raw: &[u8], value: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut reader = Reader::new(raw);
    let mut bag = reader.read_sequence()?;
    let id = bag.read_raw_tlv()?;
    bag.read_raw_tlv()?;
    let attributes = if bag.is_empty() {
        &[][..]
    } else {
        bag.read_raw_tlv()?
    };
    Ok(der::sequence(&[id, value, attributes].concat()))
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
    use crate::test_support::{TestRng, fixture_certificate_der, fixture_summary, synthetic_pkcs8};
    use crown::{
        asn1::{der, oid::ObjectIdentifier},
        pkcs12::{SafeBag, encode_safe_contents},
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
    fn trusted_certificates_with_colliding_aliases_remain_visible() {
        use crate::test_support::metadata_certificate;
        use crown::x509::attribute::Attribute;

        let first = metadata_certificate("first", "first", &[1], &[]);
        let second = metadata_certificate("second", "second", &[2], &[]);
        let trusted = |der: &[u8], alias| {
            raw_certificate(
                der,
                vec![
                    friendly_name(alias),
                    Attribute::new(
                        ObjectIdentifier::new(TRUSTED_KEY_USAGE).unwrap(),
                        vec![der::oid(
                            &ObjectIdentifier::new(&[2, 5, 29, 37, 0]).unwrap(),
                        )],
                    ),
                ],
            )
        };
        for alias in ["shared", "SHARED"] {
            let data = synthetic(vec![trusted(&first, "shared"), trusted(&second, alias)]);
            let verified = parse(&data).unwrap().verify("changeit").unwrap();
            assert!(!verified.incomplete);
            assert_eq!(verified.entries.len(), 2);
            let mut expected = vec![("shared", first.clone()), (alias, second.clone())];
            expected.sort_by(|a, b| a.0.cmp(b.0));
            for (entry, (alias, der)) in verified.entries.iter().zip(expected) {
                assert_eq!(entry.alias, alias);
                assert_eq!(entry.kind(), "Trusted certificate");
                assert_eq!(entry.certificates(), [der]);
            }

            // A name shared with a key must not hide a trusted certificate either.
            let key = SafeBag {
                bag: Bag::ShroudedKey(EncryptedPrivateKeyInfo {
                    algorithm: AlgorithmIdentifier::with_null(
                        ObjectIdentifier::new(oid::OID_PBES2).unwrap(),
                    ),
                    encrypted_data: vec![1, 2, 3],
                }),
                attributes: vec![friendly_name("shared")],
            };
            let mut secret = secret_bag();
            secret.attributes = vec![friendly_name("shared")];
            for other in [key, secret] {
                let kind = if matches!(other.bag, Bag::ShroudedKey(_)) {
                    "Private key"
                } else {
                    "Secret key"
                };
                let data = synthetic(vec![other, trusted(&second, alias)]);
                let verified = parse(&data).unwrap().verify("changeit").unwrap();
                assert!(!verified.incomplete);
                assert_eq!(verified.entries.len(), 2);
                assert!(verified.entries.iter().any(|entry| entry.kind() == kind));
                let certificate = verified
                    .entries
                    .iter()
                    .find(|entry| entry.kind() == "Trusted certificate")
                    .unwrap();
                assert_eq!(certificate.alias, alias);
                assert_eq!(certificate.certificates(), std::slice::from_ref(&second));
            }
        }
    }

    #[test]
    fn identical_trusted_certificates_are_listed_once() {
        use crate::test_support::metadata_certificate;
        use crown::x509::attribute::Attribute;

        let der = metadata_certificate("ca", "ca", &[1], &[]);
        let trusted = |alias| {
            raw_certificate(
                &der,
                vec![
                    friendly_name(alias),
                    Attribute::new(
                        ObjectIdentifier::new(TRUSTED_KEY_USAGE).unwrap(),
                        vec![der::oid(
                            &ObjectIdentifier::new(&[2, 5, 29, 37, 0]).unwrap(),
                        )],
                    ),
                ],
            )
        };
        let data = synthetic(vec![trusted("ca"), trusted("ca")]);
        let verified = parse(&data).unwrap().verify("changeit").unwrap();
        assert!(!verified.incomplete);
        assert_eq!(verified.entries.len(), 1);
        assert_eq!(verified.entries[0].alias, "ca");

        // The same certificate under names differing in case stays separate.
        let data = synthetic(vec![trusted("ca"), trusted("CA")]);
        let verified = parse(&data).unwrap().verify("changeit").unwrap();
        assert_eq!(verified.entries.len(), 2);
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

    fn open(data: &[u8], password: &str) -> (Vec<KeystoreEntry>, Writable) {
        let (verified, writable) = parse(data).unwrap().open(password).unwrap();
        (verified.entries, writable.unwrap())
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|window| window == needle)
    }

    fn shrouded_key(attributes: Vec<crown::x509::attribute::Attribute>) -> SafeBag {
        SafeBag {
            bag: Bag::ShroudedKey(EncryptedPrivateKeyInfo {
                algorithm: AlgorithmIdentifier::with_null(
                    ObjectIdentifier::new(oid::OID_PBES2).unwrap(),
                ),
                encrypted_data: b"synthetic, not a private key".to_vec(),
            }),
            attributes,
        }
    }

    #[test]
    fn written_stores_read_back_with_the_same_entries_and_protection() {
        let passwordless = include_bytes!("../tests/fixtures/passwordless.p12");
        for (name, data, password) in [
            ("modern", MODERN, "changeit"),
            ("legacy", LEGACY, "changeit"),
            ("unicode alias", UNICODE_ALIAS, "changeit"),
            ("openssl", OPENSSL, "changeit"),
            ("openssl legacy", OPENSSL_LEGACY, "changeit"),
            ("openssl no mac", OPENSSL_NO_MAC_AES, "changeit"),
            ("empty password", EMPTY_PASSWORD, ""),
            ("nul password", NUL_PASSWORD, ""),
            ("empty password no mac", EMPTY_PASSWORD_NO_MAC, ""),
            ("passwordless", &passwordless[..], ""),
        ] {
            let original = parse(data).unwrap();
            let (entries, writable) = open(data, password);
            let saved = writable.encode(&mut TestRng(0)).unwrap();
            let store = parse(&saved).unwrap();
            let verified = store.verify(password).unwrap();
            assert_eq!(verified.entries, entries, "{name}");
            assert!(!verified.incomplete, "{name}");
            // A store keeps its MAC, or its lack of one, and certificates
            // that were encrypted stay hidden.
            assert_eq!(store.0.mac.is_some(), original.0.mac.is_some(), "{name}");
            assert_eq!(
                contains(&saved, fixture_certificate_der()),
                contains(data, fixture_certificate_der()),
                "{name}"
            );
            if original.0.mac.is_some() || !contains(data, fixture_certificate_der()) {
                assert!(
                    matches!(store.verify("wrong"), Err(VerifyError::Password)),
                    "{name}"
                );
                // Fresh salts make every protected save differ.
                assert_ne!(saved, writable.encode(&mut TestRng(7)).unwrap(), "{name}");
            }
        }
    }

    #[test]
    fn stores_that_were_not_read_completely_are_not_writable() {
        let unknown = SafeBag {
            bag: Bag::Other {
                oid: ObjectIdentifier::new(&[1, 2, 3, 4]).unwrap(),
                value: der::null(),
            },
            attributes: vec![friendly_name("other")],
        };
        let data = synthetic(vec![shrouded_key(vec![friendly_name("key")]), unknown]);
        let (verified, writable) = parse(&data).unwrap().open("changeit").unwrap();
        assert!(verified.incomplete);
        assert!(writable.is_none());
    }

    #[test]
    fn removing_a_key_takes_its_certificate_and_unshared_chain() {
        use crate::test_support::metadata_certificate;
        let leaf = metadata_certificate("leaf", "intermediate", &[1], &[]);
        let other_leaf = metadata_certificate("other-leaf", "root", &[5], &[]);
        let intermediate = metadata_certificate("intermediate", "root", &[2], &[]);
        let root = metadata_certificate("root", "root", &[3], &[]);
        let loose = metadata_certificate("loose", "loose", &[4], &[]);
        let data = synthetic(vec![
            shrouded_key(vec![friendly_name("a-key"), local_key_id(&[1])]),
            shrouded_key(vec![friendly_name("b-key"), local_key_id(&[2])]),
            raw_certificate(&leaf, vec![local_key_id(&[1])]),
            raw_certificate(&other_leaf, vec![local_key_id(&[2])]),
            raw_certificate(&intermediate, vec![]),
            raw_certificate(&root, vec![]),
            raw_certificate(&loose, vec![friendly_name("loose")]),
        ]);
        let aliases = |entries: &[KeystoreEntry]| -> Vec<String> {
            entries.iter().map(|entry| entry.alias.clone()).collect()
        };
        let (entries, mut writable) = open(&data, "changeit");
        assert_eq!(aliases(&entries), ["a-key", "b-key", "loose"]);
        assert_eq!(entries[0].certificates().len(), 3);

        // The intermediate goes with its key; the root is still b-key's.
        let entries = writable.remove(0);
        assert_eq!(aliases(&entries), ["b-key", "loose"]);
        assert_eq!(entries[1].kind(), "Certificate");
        assert_eq!(
            entries[0].certificates(),
            [other_leaf.clone(), root.clone()]
        );
        let saved = writable.encode(&mut TestRng(0)).unwrap();
        assert_eq!(
            parse(&saved).unwrap().verify("changeit").unwrap().entries,
            entries
        );
        assert!(!contains(&saved, &leaf) && !contains(&saved, &intermediate));
        assert!(contains(&saved, &root) && contains(&saved, &loose));

        // Then a plain certificate, then the last key with its root.
        let entries = writable.remove(1);
        assert_eq!(aliases(&entries), ["b-key"]);
        assert!(writable.remove(0).is_empty());
        let saved = writable.encode(&mut TestRng(0)).unwrap();
        let verified = parse(&saved).unwrap().verify("changeit").unwrap();
        assert!(verified.entries.is_empty() && !verified.incomplete);
        assert!(!contains(&saved, &root));
    }

    #[test]
    fn renaming_names_the_key_and_its_certificate_and_keeps_the_rest() {
        use crate::test_support::metadata_certificate;
        let leaf = metadata_certificate("leaf", "leaf", &[1], &[]);
        let data = synthetic(vec![
            shrouded_key(vec![friendly_name("old"), local_key_id(&[7, 7])]),
            raw_certificate(&leaf, vec![friendly_name("old"), local_key_id(&[7, 7])]),
            shrouded_key(vec![local_key_id(&[9])]),
        ]);
        let (entries, mut writable) = open(&data, "changeit");
        assert_eq!(entries[0].alias, "Private key 1");
        assert_eq!(entries[1].alias, "old");

        let entries = writable.rename(1, "new-ü😀").unwrap();
        assert_eq!(entries[1].alias, "new-ü😀");
        assert_eq!(entries[1].certificates(), std::slice::from_ref(&leaf));
        // A key without a name gets one.
        let entries = writable.rename(0, "named").unwrap();
        assert_eq!(entries[0].alias, "named");
        assert_eq!(entries[0].kind(), "Private key");

        let saved = writable.encode(&mut TestRng(0)).unwrap();
        let store = parse(&saved).unwrap();
        assert_eq!(store.verify("changeit").unwrap().entries, entries);
        let bags = store.read_bags(b"changeit").unwrap().bags;
        // Both bags of the entry carry the name once, as a BMPString, and
        // still share their key ID; the key itself is untouched.
        for bag in &bags[..2] {
            assert_eq!(bag.friendly_name().as_deref(), Some("new-ü😀"));
            assert_eq!(bag.local_key_id(), Some(vec![7, 7]));
            assert_eq!(bag.attributes.len(), 2);
            assert!(contains(&bag.raw, &[0x1e, 14, 0, b'n', 0, b'e', 0, b'w']));
        }
        for bag in [&bags[0], &bags[2]] {
            let Bag::ShroudedKey(key) = &bag.bag else {
                panic!("a key bag");
            };
            assert_eq!(key.encrypted_data, b"synthetic, not a private key");
        }
    }

    #[test]
    fn inserted_certificates_are_trusted_entries_stored_like_the_others() {
        use crate::test_support::metadata_certificate;
        let added = metadata_certificate("added", "added", &[9], &[]);
        // Java's store encrypts certificates, so the new one is encrypted.
        let (_, mut writable) = open(MODERN, "changeit");
        let entries = writable
            .insert_trusted_certificate("added", &added)
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0],
            KeystoreEntry {
                alias: "added".into(),
                certificate: certificate::summarize(&added),
                content: Content::Certificates {
                    kind: Kind::TrustedCertificate,
                    certificates: vec![added.clone()],
                },
                chain_warning: None,
            }
        );
        let saved = writable.encode(&mut TestRng(0)).unwrap();
        assert!(!contains(&saved, &added));
        assert_eq!(
            parse(&saved).unwrap().verify("changeit").unwrap().entries,
            entries
        );

        // A passwordless truststore stays readable without a password.
        let passwordless = include_bytes!("../tests/fixtures/passwordless.p12");
        let (_, mut writable) = open(passwordless, "");
        let entries = writable
            .insert_trusted_certificate("added", &added)
            .unwrap();
        let saved = writable.encode(&mut TestRng(0)).unwrap();
        assert!(contains(&saved, &added));
        let store = parse(&saved).unwrap();
        assert!(store.0.mac.is_none());
        assert_eq!(store.verify("").unwrap().entries, entries);

        // A new store has a MAC and encrypts its certificates.
        let mut writable = Writable::empty("secret");
        let empty = writable.encode(&mut TestRng(0)).unwrap();
        let verified = parse(&empty).unwrap().verify("secret").unwrap();
        assert!(verified.entries.is_empty() && !verified.incomplete);
        assert!(matches!(
            parse(&empty).unwrap().verify("wrong"),
            Err(VerifyError::Password)
        ));
        let entries = writable
            .insert_trusted_certificate("added", &added)
            .unwrap();
        let saved = writable.encode(&mut TestRng(0)).unwrap();
        assert!(!contains(&saved, &added));
        assert_eq!(
            parse(&saved).unwrap().verify("secret").unwrap().entries,
            entries
        );
    }

    #[test]
    fn the_password_changes_only_where_nothing_else_depends_on_it() {
        let (entries, mut writable) = open(MODERN, "changeit");
        assert!(
            writable
                .set_password("", &mut TestRng(0))
                .unwrap_err()
                .contains("not empty")
        );
        writable.set_password("new-päss", &mut TestRng(0)).unwrap();
        let saved = writable.encode(&mut TestRng(0)).unwrap();
        let store = parse(&saved).unwrap();
        assert!(matches!(
            store.verify("changeit"),
            Err(VerifyError::Password)
        ));
        assert_eq!(store.verify("new-päss").unwrap().entries, entries);

        let passwordless = include_bytes!("../tests/fixtures/passwordless.p12");
        let (_, mut writable) = open(passwordless, "");
        let error = writable
            .set_password("secret", &mut TestRng(0))
            .unwrap_err();
        assert!(error.contains("not protected by a password"), "{error}");

        // A key that is not really encrypted cannot be re-encrypted.
        let data = synthetic(vec![shrouded_key(vec![friendly_name("key")])]);
        let (_, mut writable) = open(&data, "changeit");
        let error = writable
            .set_password("secret", &mut TestRng(0))
            .unwrap_err();
        assert!(error.contains("not supported"), "{error}");
        let saved = writable.encode(&mut TestRng(0)).unwrap();
        assert!(parse(&saved).unwrap().verify("changeit").is_ok());
    }

    fn encrypted_key(pkcs8: &[u8], password: &[u8], legacy: bool) -> EncryptedPrivateKeyInfo {
        if legacy {
            let pbe = LegacyPbe {
                salt: vec![7; 8],
                iterations: 50,
                kind: LegacyPbeKind::DesEde3,
            };
            EncryptedPrivateKeyInfo {
                algorithm: pbe.to_algorithm(),
                encrypted_data: pbe.encrypt(pkcs8, password).unwrap(),
            }
        } else {
            encrypt_private_key(
                pkcs8,
                password,
                Pbes2Cipher::Aes256Cbc { iv: Vec::new() },
                50,
                &mut TestRng(3),
            )
            .unwrap()
        }
    }

    /// The content of every key and secret bag that `password` decrypts,
    /// in bag order.
    fn decrypted_keys(data: &[u8], password: &str) -> Vec<Vec<u8>> {
        let bags = parse(data)
            .unwrap()
            .read_bags(password.as_bytes())
            .unwrap()
            .bags;
        bags.iter()
            .filter_map(|bag| match &bag.bag {
                Bag::ShroudedKey(info) => Some(info.clone()),
                Bag::Secret { value, .. } => {
                    let der = Reader::new(value)
                        .read_explicit(0)
                        .unwrap()
                        .read_octet_string_owned()
                        .unwrap();
                    Some(EncryptedPrivateKeyInfo::parse(&der).unwrap())
                }
                _ => None,
            })
            .filter_map(|info| {
                pbe_decrypt(&info.algorithm, &info.encrypted_data, password.as_bytes()).ok()
            })
            .collect()
    }

    #[test]
    fn changing_the_password_re_encrypts_keys_without_changing_them() {
        use crate::test_support::metadata_certificate;
        let leaf = metadata_certificate("leaf", "leaf", &[1], &[]);
        let modern = synthetic_pkcs8(b"first synthetic key");
        let legacy = synthetic_pkcs8(b"second synthetic key");
        let secret = synthetic_pkcs8(b"synthetic secret");
        let secret_bag = |password: &[u8]| SafeBag {
            bag: Bag::Secret {
                oid: ObjectIdentifier::new(oid::OID_PKCS12_SHROUDED_KEY_BAG).unwrap(),
                value: der::explicit(
                    0,
                    &der::octet_string(&encrypted_key(&secret, password, false).encode()),
                ),
            },
            attributes: vec![friendly_name("secret")],
        };
        let bags = |other_password: &[u8]| {
            vec![
                SafeBag {
                    bag: Bag::ShroudedKey(encrypted_key(&modern, b"changeit", false)),
                    attributes: vec![friendly_name("modern"), local_key_id(&[1])],
                },
                raw_certificate(&leaf, vec![local_key_id(&[1])]),
                SafeBag {
                    bag: Bag::ShroudedKey(encrypted_key(&legacy, b"changeit", true)),
                    attributes: vec![friendly_name("legacy")],
                },
                secret_bag(other_password),
            ]
        };
        let data = synthetic(bags(b"changeit"));
        let (entries, mut writable) = open(&data, "changeit");
        assert_eq!(entries.len(), 3);
        writable.set_password("new-päss", &mut TestRng(0)).unwrap();
        let saved = writable.encode(&mut TestRng(0)).unwrap();
        let store = parse(&saved).unwrap();
        assert!(matches!(
            store.verify("changeit"),
            Err(VerifyError::Password)
        ));
        // The listing, names, and key IDs are as before.
        assert_eq!(store.verify("new-päss").unwrap().entries, entries);
        // Each key decrypts with the new password to the same bytes, and
        // is now encrypted with PBES2.
        assert_eq!(
            decrypted_keys(&saved, "new-päss"),
            [modern.clone(), legacy.clone(), secret.clone()]
        );
        for bag in store.read_bags("new-päss".as_bytes()).unwrap().bags {
            if let Bag::ShroudedKey(info) = &bag.bag {
                assert!(info.algorithm.oid.matches(oid::OID_PBES2));
                assert!(
                    pbe_decrypt(&info.algorithm, &info.encrypted_data, b"changeit")
                        .ok()
                        .is_none_or(|key| !is_private_key_info(&key))
                );
            }
        }
        // The keys are not left in the file unencrypted.
        for key in [&modern, &legacy, &secret] {
            assert!(!contains(&saved, key));
        }

        // One key under another password stops the change, and nothing moves.
        let data = synthetic(bags(b"other"));
        let (_, mut writable) = open(&data, "changeit");
        let error = writable
            .set_password("new-päss", &mut TestRng(0))
            .unwrap_err();
        assert!(error.contains("another password"), "{error}");
        let saved = writable.encode(&mut TestRng(0)).unwrap();
        assert_eq!(decrypted_keys(&saved, "changeit"), [modern, legacy]);
    }

    #[test]
    fn keys_that_cannot_be_re_encrypted_stop_the_password_change() {
        let secret = |kind: &[u64], value: Vec<u8>| SafeBag {
            bag: Bag::Secret {
                oid: ObjectIdentifier::new(kind).unwrap(),
                value,
            },
            attributes: vec![friendly_name("secret")],
        };
        let not_a_key = encrypted_key(b"decrypts, but is not a key", b"changeit", false);
        for (bag, reason) in [
            // A secret that is not an encrypted PKCS #8 structure.
            (
                secret(&[1, 2, 3, 4], der::explicit(0, &der::octet_string(b"raw"))),
                "not supported",
            ),
            (
                secret(
                    oid::OID_PKCS12_SHROUDED_KEY_BAG,
                    der::explicit(0, &der::octet_string(b"not encrypted key info")),
                ),
                "not supported",
            ),
            // Content that decrypts with valid padding but is not a key
            // means the password was wrong.
            (
                SafeBag {
                    bag: Bag::ShroudedKey(not_a_key),
                    attributes: vec![friendly_name("key")],
                },
                "another password",
            ),
        ] {
            let data = synthetic(vec![bag]);
            let (entries, mut writable) = open(&data, "changeit");
            let error = writable
                .set_password("secret", &mut TestRng(0))
                .unwrap_err();
            assert!(error.contains(reason), "{error}");
            let saved = writable.encode(&mut TestRng(0)).unwrap();
            assert_eq!(
                parse(&saved).unwrap().verify("changeit").unwrap().entries,
                entries
            );
        }
    }

    #[test]
    fn recognizes_the_shape_of_a_private_key() {
        assert!(is_private_key_info(&synthetic_pkcs8(b"key")));
        for content in [
            &b""[..],
            b"not DER",
            &der::sequence(&der::integer(&[0])),
            &der::octet_string(b"key"),
            &[synthetic_pkcs8(b"key"), vec![0]].concat(),
        ] {
            assert!(!is_private_key_info(content));
        }
    }
}
