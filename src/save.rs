//! Writing an edited keystore: the open keystore's writable form and
//! password, the "save as" name prompt, and replacing a file atomically.
use crate::path_input::PathInput;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crown::rng::Rng;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use zeroize::Zeroizing;

use crate::{
    certificate,
    key_protection::{self, Error as KeyError},
    keystore::{self, Content, KeystoreEntry, Kind},
    pkcs12,
    secret_key::{self, SecretKey},
};

/// An open keystore that can be edited and saved. Its password is kept, to
/// protect the saved file with, until the keystore is closed; dropping the
/// document wipes it.
///
/// Every edit takes the entry list as shown and leaves it matching what
/// would be saved, in alias order.
pub enum Document {
    Jks {
        writable: keystore::Writable,
        password: Zeroizing<String>,
    },
    Pkcs12(pkcs12::Writable),
}

const NO_RANDOMNESS: &str = "The system provided no random numbers; nothing was changed.";

/// The operating system's random numbers, for PKCS12 salts.
#[derive(Default)]
pub(crate) struct OsRng {
    failed: bool,
}

impl OsRng {
    /// Fills `out` with random bytes from the operating system, recording any
    /// failure so a later [`check`](Self::check) also reports it.
    pub(crate) fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), String> {
        if self.failed || getrandom::fill(out).is_err() {
            self.failed = true;
            return Err(NO_RANDOMNESS.into());
        }
        Ok(())
    }

    /// Fails if any request for random numbers was not met.
    pub(crate) fn check(mut self) -> Result<(), String> {
        // Also catches a source that fails before it is first used.
        self.try_fill_bytes(&mut [0])
    }
}

impl Rng for OsRng {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        let _ = self.try_fill_bytes(out);
    }
}

impl Document {
    pub fn jks(writable: keystore::Writable, password: &str) -> Self {
        Self::Jks {
            writable,
            password: Zeroizing::new(password.to_owned()),
        }
    }

    /// Saves under `password` from now on; the old one is wiped.
    pub fn set_password(&mut self, new: &str) -> Result<(), String> {
        if matches!(self, Self::Pkcs12(_)) {
            // Re-encrypting keys needs salts; check for them first, so
            // that a failure leaves the keystore as it was.
            OsRng::default().check()?;
        }
        self.set_password_with_rng(new, OsRng::default())
    }

    fn set_password_with_rng(&mut self, new: &str, mut rng: OsRng) -> Result<(), String> {
        match self {
            Self::Jks { password, .. } => *password = Zeroizing::new(new.to_owned()),
            Self::Pkcs12(writable) => {
                let mut changed = writable.clone();
                changed.set_password(new, &mut rng)?;
                rng.check()?;
                *writable = changed;
            }
        }
        Ok(())
    }

    /// Whether keys have passwords of their own, as in JKS and JCEKS. In
    /// PKCS12 they share the keystore's.
    pub fn has_key_passwords(&self) -> bool {
        matches!(self, Self::Jks { .. })
    }

    /// Recovers the private key of the entry listed at `index` with
    /// `password`, or with the keystore's password when there is none.
    fn recover_key(
        &self,
        index: usize,
        password: Option<&str>,
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        let Self::Jks {
            writable,
            password: store_password,
        } = self
        else {
            return Err(KeyError::Unsupported);
        };
        let protected = writable.protected_key(index).ok_or(KeyError::Unsupported)?;
        key_protection::recover(protected, password.unwrap_or(store_password))
    }

    /// Recovers the JCEKS secret key listed at `index` with `password`, or
    /// with the keystore's password when there is none. `None` for any
    /// other entry.
    fn sealed_key(
        &self,
        index: usize,
        password: Option<&str>,
    ) -> Option<Result<SecretKey, KeyError>> {
        let Self::Jks {
            writable,
            password: store_password,
        } = self
        else {
            return None;
        };
        let sealed = writable.sealed_key(index)?;
        Some(secret_key::unseal(
            sealed,
            password.unwrap_or(store_password),
        ))
    }

    /// Whether `password`, or the keystore's password when there is none,
    /// is the one protecting the private or secret key listed at `index`.
    pub fn unlocks_key(&self, index: usize, password: Option<&str>) -> Result<bool, String> {
        let recovered = match self.sealed_key(index, password) {
            Some(secret) => secret.map(drop),
            None => self.recover_key(index, password).map(drop),
        };
        match recovered {
            Ok(()) => Ok(true),
            Err(KeyError::Password) => Ok(false),
            Err(error) => Err(key_error(error)),
        }
    }

    /// Protects the private or secret key listed at `index` with the
    /// password `new`.
    /// The key is recovered in memory with `current`, or with the keystore's
    /// password when there is none, and wiped once protected again.
    pub fn set_key_password(
        &mut self,
        index: usize,
        current: Option<&str>,
        new: &str,
    ) -> Result<(), String> {
        let failed = |error| format!("The key password was not changed: {error}.");
        if let Some(secret) = self.sealed_key(index, current) {
            let secret = secret.map_err(key_error)?;
            if let Self::Jks { writable, .. } = self {
                OsRng::default().check()?;
                let mut rng = OsRng::default();
                let sealed = secret_key::seal(&secret, new, &mut rng).map_err(key_error)?;
                rng.check()?;
                writable.set_sealed_key(index, &sealed).map_err(failed)?;
            }
            return Ok(());
        }
        // Only a JKS or JCEKS document recovers a key.
        let key = self.recover_key(index, current).map_err(key_error)?;
        if let Self::Jks { writable, .. } = self {
            OsRng::default().check()?;
            let mut rng = OsRng::default();
            let protected = key_protection::protect(&key, new, writable.is_jceks(), &mut rng)
                .map_err(key_error)?;
            rng.check()?;
            writable
                .set_protected_key(index, &protected)
                .map_err(failed)?;
        }
        Ok(())
    }

    /// Removes the entry listed at `index`.
    pub fn remove(&mut self, entries: &mut Vec<KeystoreEntry>, index: usize) {
        match self {
            Self::Jks { writable, .. } => {
                writable.remove(index);
                entries.remove(index);
            }
            Self::Pkcs12(writable) => *entries = writable.remove(index),
        }
    }

    /// Gives the entry listed at `index` the alias `alias`, and returns
    /// where it is listed now.
    pub fn rename(
        &mut self,
        entries: &mut Vec<KeystoreEntry>,
        index: usize,
        alias: String,
    ) -> Result<usize, String> {
        let failed = |error: String| format!("Not renamed: {error}.");
        match self {
            Self::Jks { writable, .. } => {
                let mut entry = entries.remove(index);
                let to = entries.partition_point(|other| other.alias < alias);
                let result = writable.rename(index, &alias, to);
                // On failure the entry returns to where it was.
                let at = if result.is_ok() { to } else { index };
                if result.is_ok() {
                    entry.alias = alias;
                }
                entries.insert(at, entry);
                result
                    .map(|()| to)
                    .map_err(|error| failed(error.to_string()))
            }
            Self::Pkcs12(writable) => {
                *entries = writable
                    .rename(index, &alias)
                    .map_err(|error| failed(error.to_owned()))?;
                Ok(listed_at(entries, &alias))
            }
        }
    }

    /// Adds `certificate` as a trusted certificate named `alias`, and
    /// returns where it is listed.
    pub fn import_certificate(
        &mut self,
        entries: &mut Vec<KeystoreEntry>,
        alias: String,
        certificate: &[u8],
    ) -> Result<usize, String> {
        let failed = |error: String| format!("Not imported: {error}.");
        match self {
            Self::Jks { writable, .. } => {
                let to = entries.partition_point(|other| other.alias < alias);
                let created = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.as_millis() as u64);
                writable
                    .insert_trusted_certificate(to, &alias, certificate, created)
                    .map_err(|error| failed(error.to_string()))?;
                entries.insert(
                    to,
                    KeystoreEntry {
                        alias,
                        certificate: certificate::summarize(certificate),
                        content: Content::Certificates {
                            kind: Kind::TrustedCertificate,
                            certificates: vec![certificate.to_vec()],
                        },
                        chain_warning: None,
                    },
                );
                Ok(to)
            }
            Self::Pkcs12(writable) => {
                *entries = writable
                    .insert_trusted_certificate(&alias, certificate)
                    .map_err(|error| failed(error.to_owned()))?;
                Ok(listed_at(entries, &alias))
            }
        }
    }

    /// Adds the PKCS #8 private key `key` with its certificate `chain` as a
    /// key pair named `alias`, protected with the keystore's password, and
    /// returns where it is listed.
    pub fn import_key_pair(
        &mut self,
        entries: &mut Vec<KeystoreEntry>,
        alias: String,
        key: &[u8],
        chain: &[Vec<u8>],
    ) -> Result<usize, String> {
        OsRng::default().check()?;
        self.import_key_pair_with_rng(entries, alias, key, chain, OsRng::default())
    }

    fn import_key_pair_with_rng(
        &mut self,
        entries: &mut Vec<KeystoreEntry>,
        alias: String,
        key: &[u8],
        chain: &[Vec<u8>],
        mut rng: OsRng,
    ) -> Result<usize, String> {
        let failed = |error: String| format!("Not imported: {error}.");
        match self {
            Self::Jks { writable, password } => {
                let protected =
                    key_protection::protect(key, password, writable.is_jceks(), &mut rng)
                        .map_err(key_error)?;
                rng.check()?;
                let to = entries.partition_point(|other| other.alias < alias);
                let created = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.as_millis() as u64);
                writable
                    .insert_private_key(to, &alias, &protected, chain, created)
                    .map_err(|error| failed(error.to_string()))?;
                entries.insert(
                    to,
                    KeystoreEntry {
                        alias,
                        // Like Java, a key may be stored without a chain.
                        certificate: chain.first().and_then(|leaf| certificate::summarize(leaf)),
                        content: Content::Certificates {
                            kind: Kind::PrivateKey,
                            certificates: chain.to_vec(),
                        },
                        chain_warning: None,
                    },
                );
                Ok(to)
            }
            Self::Pkcs12(writable) => {
                // The key and its certificate are paired by the
                // certificate's digest, which must not pair two keys. A key
                // without a certificate is paired with none.
                if let Some(held) = chain.first().and_then(|leaf| {
                    entries.iter().find(|entry| {
                        entry.kind() == Kind::PrivateKey.label()
                            && entry.certificates().first() == Some(leaf)
                    })
                }) {
                    return Err(failed(format!(
                        "the keystore already holds this key pair as '{}'",
                        held.alias
                    )));
                }
                let mut changed = writable.clone();
                let listed = changed
                    .insert_private_key(&alias, key, chain, &mut rng)
                    .map_err(|error| failed(error.to_owned()))?;
                rng.check()?;
                *writable = changed;
                *entries = listed;
                Ok(listed_at(entries, &alias))
            }
        }
    }

    /// Adds the secret key `key` under `alias`, protected with the
    /// keystore's password, and returns where it is listed.
    pub fn import_secret_key(
        &mut self,
        entries: &mut Vec<KeystoreEntry>,
        alias: String,
        key: &SecretKey,
    ) -> Result<usize, String> {
        OsRng::default().check()?;
        self.import_secret_key_with_rng(entries, alias, key, OsRng::default())
    }

    fn import_secret_key_with_rng(
        &mut self,
        entries: &mut Vec<KeystoreEntry>,
        alias: String,
        key: &SecretKey,
        mut rng: OsRng,
    ) -> Result<usize, String> {
        let failed = |error: String| format!("Not added: {error}.");
        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis() as u64);
        match self {
            Self::Jks { writable, password } => {
                if !writable.is_jceks() {
                    return Err(failed(JKS_HOLDS_NO_SECRET_KEYS.into()));
                }
                let sealed = secret_key::seal(key, password, &mut rng).map_err(key_error)?;
                rng.check()?;
                let to = entries.partition_point(|other| other.alias < alias);
                writable
                    .insert_secret_key(to, &alias, &sealed, created)
                    .map_err(|error| failed(error.to_string()))?;
                entries.insert(
                    to,
                    KeystoreEntry {
                        alias,
                        certificate: None,
                        content: Content::Certificates {
                            kind: Kind::SecretKey,
                            certificates: vec![],
                        },
                        chain_warning: None,
                    },
                );
                Ok(to)
            }
            Self::Pkcs12(writable) => {
                let wrapped = secret_key::to_pkcs8(key).ok_or_else(|| {
                    failed(format!(
                        "PKCS12 has no name for the algorithm '{}'",
                        key.algorithm
                    ))
                })?;
                let mut changed = writable.clone();
                let listed = changed
                    .insert_secret_key(&alias, &wrapped, created, &mut rng)
                    .map_err(|error| failed(error.to_owned()))?;
                rng.check()?;
                *writable = changed;
                *entries = listed;
                Ok(listed_at(entries, &alias))
            }
        }
    }

    /// Replaces the certificate chain of the private key listed at `index`
    /// with `chain`, leaf first, and returns where the entry is listed. The
    /// key itself is not touched.
    pub fn replace_chain(
        &mut self,
        entries: &mut Vec<KeystoreEntry>,
        index: usize,
        chain: &[Vec<u8>],
    ) -> Result<usize, String> {
        let failed = |error: String| format!("Not replaced: {error}.");
        let leaf = chain
            .first()
            .ok_or_else(|| failed("the chain is empty".into()))?;
        match self {
            Self::Jks { writable, .. } => {
                writable
                    .set_chain(index, chain)
                    .map_err(|error| failed(error.to_string()))?;
                let entry = &mut entries[index];
                entry.certificate = certificate::summarize(leaf);
                entry.content = Content::Certificates {
                    kind: Kind::PrivateKey,
                    certificates: chain.to_vec(),
                };
                entry.chain_warning = None;
                Ok(index)
            }
            Self::Pkcs12(writable) => {
                // As for an imported key pair, a certificate pairs with
                // one key only.
                if let Some(held) = entries.iter().enumerate().find(|(other, entry)| {
                    *other != index
                        && entry.kind() == Kind::PrivateKey.label()
                        && entry.certificates().first() == Some(leaf)
                }) {
                    return Err(failed(format!(
                        "the certificate already belongs to the key '{}'",
                        held.1.alias
                    )));
                }
                let alias = entries[index].alias.clone();
                // Changed on a copy, which is kept only if it lists the
                // chain as it was given.
                let mut changed = writable.clone();
                let listed = changed
                    .set_chain(index, &alias, chain)
                    .map_err(|error| failed(error.to_owned()))?;
                let to = listed_at(&listed, &alias);
                if listed.get(to).map(KeystoreEntry::certificates) != Some(chain) {
                    return Err(failed(
                        "the keystore would not list this chain again, for example because it holds another certificate with an issuer's name".into(),
                    ));
                }
                *writable = changed;
                *entries = listed;
                Ok(to)
            }
        }
    }

    /// The keystore file, after checking that it reads back as `entries`.
    fn encode(&self, entries: &[KeystoreEntry]) -> Result<Vec<u8>, String> {
        let (data, read_back) = match self {
            Self::Jks { writable, password } => {
                let data = writable.encode(password);
                let read_back = keystore::parse(data.clone())
                    .ok()
                    .and_then(|keystore| keystore.open(password).ok())
                    .map(|(read, _)| read);
                (data, read_back)
            }
            Self::Pkcs12(writable) => {
                let mut rng = OsRng::default();
                let data = writable
                    .encode(&mut rng)
                    .map_err(|error| format!("Cannot save: {error}."))?;
                rng.check()?;
                let read_back = pkcs12::parse(&data)
                    .ok()
                    .and_then(|store| store.verify(writable.password()).ok())
                    .filter(|verified| !verified.incomplete)
                    .map(|verified| verified.entries);
                (data, read_back)
            }
        };
        match read_back {
            Some(read) if read == entries => Ok(data),
            _ => Err(
                "The keystore to save does not read back as listed; nothing was written.".into(),
            ),
        }
    }

    /// Replaces the file at `path`, which keeps its old content if anything
    /// fails.
    pub fn save(&self, path: &Path, entries: &[KeystoreEntry]) -> Result<(), String> {
        let data = self.encode(entries)?;
        replace(path, &data).map_err(|error| format!("Cannot save '{}': {error}", path.display()))
    }

    /// Writes a new file, failing if `path` already exists.
    pub fn save_new(&self, path: &Path, entries: &[KeystoreEntry]) -> Result<(), String> {
        create(path, &self.encode(entries)?)
    }

    pub fn format(&self) -> Format {
        match self {
            Self::Jks { writable, .. } if writable.is_jceks() => Format::Jceks,
            Self::Jks { .. } => Format::Jks,
            Self::Pkcs12(_) => Format::Pkcs12,
        }
    }

    /// The keystore's password, as typed.
    pub fn password(&self) -> &str {
        match self {
            Self::Jks { password, .. } => password,
            // An empty PKCS12 password may be stored as a NUL character.
            Self::Pkcs12(writable) => writable.password().trim_end_matches('\0'),
        }
    }

    /// The keystore as a file of another format, with the same password.
    /// Private keys are recovered in memory with the keystore's password,
    /// protected again as the other format does, and wiped. The result is
    /// read back and compared with `entries` before it is returned.
    pub fn convert(&self, entries: &[KeystoreEntry], target: Format) -> Result<Vec<u8>, String> {
        let password = self.password();
        let to_java = target != Format::Pkcs12;
        let mut expected: Vec<Converted> = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            let key = match &entry.content {
                Content::Certificates {
                    kind: Kind::PrivateKey,
                    ..
                } => Some(self.private_key(index).map_err(|error| {
                    format!("Not converted: the key '{}' {error}.", entry.alias)
                })?),
                Content::Certificates {
                    kind: Kind::TrustedCertificate | Kind::Certificate,
                    ..
                } => None,
                _ => None,
            };
            let secret = match entry.kind() == Kind::SecretKey.label() {
                true if target == Format::Jks => {
                    return Err(format!(
                        "Not converted: the secret key '{}' stops it, because {JKS_HOLDS_NO_SECRET_KEYS}.",
                        entry.alias
                    ));
                }
                true => Some(self.secret_key(index).map_err(|error| {
                    format!("Not converted: the secret key '{}' {error}.", entry.alias)
                })?),
                false => None,
            };
            // JKS and JCEKS look aliases up in lower case.
            let alias = if to_java {
                entry.alias.to_lowercase()
            } else {
                entry.alias.clone()
            };
            if to_java && expected.iter().any(|other| other.alias == alias) {
                return Err(format!(
                    "Not converted: two entries would share the alias '{alias}'."
                ));
            }
            // Certificate-only entries store a single certificate; PKCS12
            // attaches any issuer found in the store when listing, whereas
            // JKS and JCEKS do not.
            let certificates = if key.is_none() && secret.is_none() {
                entry.certificates().first().cloned().into_iter().collect()
            } else {
                entry.certificates().to_vec()
            };
            expected.push(Converted {
                alias,
                key,
                secret,
                certificates,
            });
        }
        let created = |index: usize| match self {
            Self::Jks { writable, .. } => writable.created(index),
            Self::Pkcs12(_) => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_millis() as u64),
        };
        let failed = |error: String| format!("Not converted: {error}.");
        OsRng::default().check()?;
        let mut rng = OsRng::default();
        let data = if to_java {
            let jceks = target == Format::Jceks;
            let mut writable = keystore::Writable::empty(jceks);
            for (index, entry) in expected.iter().enumerate() {
                if let Some(secret) = &entry.secret {
                    let sealed = secret_key::seal(secret, password, &mut rng).map_err(key_error)?;
                    writable
                        .insert_secret_key(index, &entry.alias, &sealed, created(index))
                        .map_err(|error| failed(error.to_string()))?;
                    continue;
                }
                match &entry.key {
                    Some(key) => {
                        let protected = key_protection::protect(key, password, jceks, &mut rng)
                            .map_err(key_error)?;
                        writable.insert_private_key(
                            index,
                            &entry.alias,
                            &protected,
                            &entry.certificates,
                            created(index),
                        )
                    }
                    None => writable.insert_trusted_certificate(
                        index,
                        &entry.alias,
                        &entry.certificates[0],
                        created(index),
                    ),
                }
                .map_err(|error| failed(error.to_string()))?;
            }
            writable.encode(password)
        } else {
            if password.is_empty() {
                return Err(failed(
                    "a PKCS12 keystore needs a password that is not empty; change the password first (p)"
                        .into(),
                ));
            }
            let mut writable = pkcs12::Writable::empty(password);
            for (index, entry) in expected.iter().enumerate() {
                if let Some(secret) = &entry.secret {
                    let wrapped = secret_key::to_pkcs8(secret).ok_or_else(|| {
                        failed(format!(
                            "PKCS12 has no name for the algorithm '{}' of the secret key '{}'",
                            secret.algorithm, entry.alias
                        ))
                    })?;
                    writable
                        .insert_secret_key(&entry.alias, &wrapped, created(index), &mut rng)
                        .map_err(|error| failed(error.to_owned()))?;
                    continue;
                }
                match &entry.key {
                    Some(key) => writable.insert_private_key(
                        &entry.alias,
                        key,
                        &entry.certificates,
                        &mut rng,
                    ),
                    None => {
                        writable.insert_trusted_certificate(&entry.alias, &entry.certificates[0])
                    }
                }
                .map_err(|error| failed(error.to_owned()))?;
            }
            writable
                .encode(&mut rng)
                .map_err(|error| failed(error.to_owned()))?
        };
        rng.check()?;
        // Open the result as a file would be opened, and recover its keys.
        let mut read = Self::open(&data, password).and_then(|(read, document)| {
            read.iter()
                .enumerate()
                .map(|(index, entry)| {
                    let is_key = entry.kind() == Kind::PrivateKey.label();
                    let is_secret = entry.kind() == Kind::SecretKey.label();
                    let certificates = if !is_key && !is_secret {
                        entry.certificates().first().cloned().into_iter().collect()
                    } else {
                        entry.certificates().to_vec()
                    };
                    Some(Converted {
                        alias: entry.alias.clone(),
                        key: match is_key {
                            true => Some(document.private_key(index).ok()?),
                            false => None,
                        },
                        secret: match is_secret {
                            true => Some(document.secret_key(index).ok()?),
                            false => None,
                        },
                        certificates,
                    })
                })
                .collect::<Option<Vec<_>>>()
        });
        let order = |a: &Converted, b: &Converted| {
            (&a.alias, &a.certificates, a.key.is_some()).cmp(&(
                &b.alias,
                &b.certificates,
                b.key.is_some(),
            ))
        };
        expected.sort_by(order);
        if let Some(read) = &mut read {
            read.sort_by(order);
        }
        if read.as_ref() == Some(&expected) {
            Ok(data)
        } else {
            Err("Not converted: the keystore would not read back with the same entries and keys, for example because a certificate chain is not linked by issuer names. Nothing was written.".into())
        }
    }

    /// Opens keystore `data` with its password, as a file is opened.
    fn open(data: &[u8], password: &str) -> Option<(Vec<KeystoreEntry>, Self)> {
        if keystore::has_magic(data) {
            let (entries, writable) = keystore::parse(data.to_vec()).ok()?.open(password).ok()?;
            Some((entries, Self::jks(writable, password)))
        } else {
            let (verified, writable) = pkcs12::parse(data).ok()?.open(password).ok()?;
            Some((verified.entries, Self::Pkcs12(writable?)))
        }
    }

    /// The secret key listed at `index`, recovered in memory with the
    /// keystore's password.
    pub(crate) fn secret_key(&self, index: usize) -> Result<SecretKey, String> {
        match self {
            Self::Jks { .. } => match self.sealed_key(index, None) {
                Some(Ok(key)) => Ok(key),
                Some(Err(KeyError::Password)) => Err(
                    "has a password of its own; give it the keystore's password first (P)".into(),
                ),
                Some(Err(_)) => Err("is sealed in a way that is not supported".into()),
                None => Err("is not a secret key".into()),
            },
            Self::Pkcs12(writable) => writable
                .secret_key(index)
                .and_then(|wrapped| secret_key::from_pkcs8(&wrapped))
                .ok_or_else(|| "could not be decrypted with the keystore's password".into()),
        }
    }

    /// The PKCS #8 encoding of the private key listed at `index`, recovered
    /// in memory with the keystore's password.
    pub(crate) fn private_key(&self, index: usize) -> Result<Zeroizing<Vec<u8>>, String> {
        match self {
            Self::Jks { .. } => match self.recover_key(index, None) {
                // The other formats only hold PKCS #8 keys.
                Ok(key) if pkcs12::is_private_key_info(&key) => Ok(key),
                Ok(_) => Err("is not a PKCS #8 key".into()),
                Err(KeyError::Password) => Err(
                    "has a password of its own; give it the keystore's password first (P)".into(),
                ),
                Err(_) => Err("uses protection that is not supported".into()),
            },
            Self::Pkcs12(writable) => writable
                .private_key(index)
                .ok_or_else(|| "could not be decrypted with the keystore's password".into()),
        }
    }
}

const JKS_HOLDS_NO_SECRET_KEYS: &str =
    "a JKS keystore cannot hold secret keys; save it as JCEKS or PKCS12 first (W)";

/// What an entry is in a converted keystore: its alias, its private key if
/// it has one, as PKCS #8, its secret key if it is one, and its
/// certificates.
#[derive(PartialEq)]
struct Converted {
    alias: String,
    key: Option<Zeroizing<Vec<u8>>>,
    secret: Option<SecretKey>,
    certificates: Vec<Vec<u8>>,
}

/// A keystore file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Jks,
    Jceks,
    Pkcs12,
}

impl Format {
    pub fn label(self) -> &'static str {
        match self {
            Self::Jks => "JKS",
            Self::Jceks => "JCEKS",
            Self::Pkcs12 => "PKCS12",
        }
    }

    /// The format a file name asks for: `.jks`, `.jceks`, and `.p12` or
    /// `.pfx`, ignoring case. Other names ask for none.
    pub fn from_name(path: &Path) -> Option<Self> {
        let extension = path.extension()?.to_str()?.to_ascii_lowercase();
        match extension.as_str() {
            "jks" => Some(Self::Jks),
            "jceks" => Some(Self::Jceks),
            "p12" | "pfx" => Some(Self::Pkcs12),
            _ => None,
        }
    }
}

/// Writes a new file, failing if `path` already exists. On Unix only the
/// owner can read or write it.
pub fn create(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).map_err(|error| match error.kind() {
        io::ErrorKind::AlreadyExists => {
            format!("'{}' already exists; choose another name.", path.display())
        }
        _ => format!("Cannot create '{}': {error}", path.display()),
    })?;
    let result = file.write_all(data).and_then(|()| file.sync_all());
    drop(file);
    result.map_err(|error| {
        let _ = fs::remove_file(path);
        format!("Cannot write '{}': {error}", path.display())
    })
}

/// Like `create`, for a file holding a private or secret key.
pub fn create_private(path: &Path, data: &[u8]) -> Result<(), String> {
    create(path, data)
}

fn key_error(error: KeyError) -> String {
    match error {
        KeyError::Password => "Incorrect key password.",
        KeyError::Unsupported => "This key's protection is not supported.",
        KeyError::PasswordNotAscii => {
            "A JCEKS key password can only use printable ASCII characters."
        }
    }
    .into()
}

/// Where the entry named `alias` is listed.
fn listed_at(entries: &[KeystoreEntry], alias: &str) -> usize {
    entries
        .iter()
        .position(|entry| entry.alias == alias)
        .unwrap_or(0)
}

/// Replaces `path` with `data` in one step: the data is written to a
/// temporary file in the same directory, which is then renamed over `path`.
/// A symbolic link is followed, and the file keeps its permissions.
fn replace(path: &Path, data: &[u8]) -> io::Result<()> {
    replace_with(path, data, random_u64)
}

fn random_u64() -> io::Result<u64> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| io::Error::other(NO_RANDOMNESS))?;
    Ok(u64::from_ne_bytes(bytes))
}

fn create_temp_file(
    directory: &Path,
    file_name: &std::ffi::OsStr,
    mut next_suffix: impl FnMut() -> io::Result<u64>,
) -> io::Result<(PathBuf, File)> {
    const MAX_ATTEMPTS: usize = 64;
    let mut last_error = None;
    for _ in 0..MAX_ATTEMPTS {
        let suffix = next_suffix()?;
        let mut name = file_name.to_os_string();
        name.push(format!(".{}.{suffix:016x}.tmp", std::process::id()));
        let temporary = directory.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        match options.open(&temporary) {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::AlreadyExists, "temporary file exists")))
}

fn replace_with(
    path: &Path,
    data: &[u8],
    next_suffix: impl FnMut() -> io::Result<u64>,
) -> io::Result<()> {
    let target = fs::canonicalize(path)?;
    let invalid = || io::Error::other("not a file path");
    let directory = target.parent().ok_or_else(invalid)?;
    let file_name = target.file_name().ok_or_else(invalid)?;
    let (temporary, mut file) = create_temp_file(directory, file_name, next_suffix)?;
    let result = (|| {
        file.write_all(data)?;
        let permissions = fs::metadata(&target)?.permissions();
        #[cfg(unix)]
        file.set_permissions(permissions)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &target)?;
        #[cfg(not(unix))]
        if permissions.readonly() {
            let _ = fs::set_permissions(&target, permissions);
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            // Make the rename durable where a directory can be synced.
            if cfg!(unix)
                && let Ok(directory) = File::open(directory)
            {
                let _ = directory.sync_all();
            }
            Ok(())
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(error)
        }
    }
}

pub enum Outcome {
    Editing,
    Cancelled,
    Save(PathBuf),
}

/// The file name being typed for "save as".
pub struct SaveAsPrompt {
    pub path: PathInput,
    directory: PathBuf,
    /// Whether the name is for a new, empty keystore rather than a copy.
    pub creating: bool,
}

impl SaveAsPrompt {
    /// Suggests `<name>-copy.<extension>` next to `current`, numbered to
    /// avoid names that already exist.
    pub fn new(current: &Path) -> Self {
        let directory = crate::path_bar::directory(current);
        let stem = current
            .file_stem()
            .map_or("keystore".into(), |stem| stem.to_string_lossy());
        let extension = current
            .extension()
            .map(|extension| format!(".{}", extension.to_string_lossy()))
            .unwrap_or_default();
        Self::suggesting(directory, &format!("{stem}-copy"), &extension, false)
    }

    /// Suggests `keystore.jks` in `directory` for a new keystore, numbered
    /// to avoid names that already exist.
    pub fn for_new(directory: PathBuf) -> Self {
        Self::suggesting(directory, "keystore", ".jks", true)
    }

    fn suggesting(directory: PathBuf, stem: &str, extension: &str, creating: bool) -> Self {
        let name = (1..100)
            .map(|n| match n {
                1 => format!("{stem}{extension}"),
                n => format!("{stem}-{n}{extension}"),
            })
            .find(|name| !directory.join(name).exists())
            .unwrap_or_else(|| format!("{stem}{extension}"));
        let path = if directory.is_absolute() {
            directory.join(name)
        } else {
            PathBuf::from(name)
        };
        Self {
            path: PathInput::new(path.to_string_lossy().into_owned()),
            directory,
            creating,
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Esc => return Outcome::Cancelled,
            KeyCode::Enter if !self.path.is_empty() => {
                // Relative names are saved next to the opened file.
                return Outcome::Save(self.directory.join(&self.path));
            }
            _ => {
                self.path.handle_key(key);
            }
        }
        Outcome::Editing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{KEYTOOL_JKS, TestDirectory, mixed_keystore};
    use ratatui::crossterm::event::KeyModifiers;

    fn open(data: &[u8], password: &str) -> (Vec<KeystoreEntry>, Document) {
        let (entries, writable) = keystore::parse(data.to_vec())
            .unwrap()
            .open(password)
            .ok()
            .unwrap();
        (entries, Document::jks(writable, password))
    }

    #[test]
    fn saving_replaces_the_file_and_leaves_no_temporary_file() {
        let directory = TestDirectory::new();
        let path = directory.path().join("store.jks");
        fs::write(&path, mixed_keystore()).unwrap();
        let (mut entries, mut document) = open(&mixed_keystore(), "changeit");
        document.remove(&mut entries, 0);
        document.save(&path, &entries).unwrap();
        let saved = fs::read(&path).unwrap();
        assert_eq!(keystore::load_entries(&saved, "changeit").unwrap(), entries);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn saving_keeps_permissions_and_follows_symbolic_links() {
        use std::os::unix::fs::PermissionsExt;
        let directory = TestDirectory::new();
        let path = directory.path().join("store.jks");
        let link = directory.path().join("link.jks");
        fs::write(&path, KEYTOOL_JKS).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&path, &link).unwrap();
        let (mut entries, mut document) = open(KEYTOOL_JKS, "changeit");
        document.remove(&mut entries, 0);
        document.save(&link, &entries).unwrap();
        assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            keystore::load_entries(&fs::read(&path).unwrap(), "changeit")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn only_jks_and_jceks_keys_have_passwords_of_their_own() {
        let (_, mut jks) = open(&mixed_keystore(), "changeit");
        assert!(jks.has_key_passwords());
        // The trusted certificate, listed first, has no key.
        assert!(jks.unlocks_key(0, None).is_err());
        assert!(jks.set_key_password(0, None, "new").is_err());

        let mut pkcs12 = Document::Pkcs12(pkcs12::Writable::empty("changeit"));
        assert!(!pkcs12.has_key_passwords());
        let error = pkcs12.unlocks_key(0, None).unwrap_err();
        assert!(error.contains("not supported"), "{error}");
        assert!(pkcs12.set_key_password(0, None, "new").is_err());
    }

    #[test]
    fn conversion_refuses_what_the_other_format_cannot_hold() {
        use crate::keystore::{PRIVATE_KEY_TAG, VERSION_02};
        use crate::test_support::{Builder, TestRng, metadata_certificate};
        // PKCS12 aliases that differ only in case would collide in JKS.
        let mut writable = pkcs12::Writable::empty("changeit");
        let mut entries = Vec::new();
        for (alias, serial) in [("Dup", 1), ("dup", 2), ("other", 3)] {
            let certificate = metadata_certificate(alias, alias, &[serial], &[]);
            entries = writable
                .insert_trusted_certificate(alias, &certificate)
                .unwrap();
        }
        let document = Document::Pkcs12(writable);
        assert_eq!(document.format(), Format::Pkcs12);
        for target in [Format::Jks, Format::Jceks] {
            let error = document.convert(&entries, target).unwrap_err();
            assert!(error.contains("share the alias 'dup'"), "{error}");
        }
        // Without the clash, mixed case becomes lower case.
        let Document::Pkcs12(mut writable) = document else {
            panic!()
        };
        writable.remove(0);
        entries = writable.rename(0, "Mixed").unwrap();
        assert_eq!(entries[0].alias, "Mixed");
        let mut writable = pkcs12::Writable::empty("changeit");
        for entry in &entries {
            writable
                .insert_trusted_certificate(&entry.alias, &entry.certificates()[0])
                .unwrap();
        }
        let data = Document::Pkcs12(writable)
            .convert(&entries, Format::Jks)
            .unwrap();
        let converted = keystore::load_entries(&data, "changeit").unwrap();
        assert_eq!(converted[0].alias, "mixed");
        assert_eq!(converted[0].kind(), "Trusted certificate");

        // A JKS key that is not PKCS #8 has no place in the other formats,
        // and JCEKS cannot protect keys with a password that is not ASCII.
        for (key, password, target, reason) in [
            (
                &b"not PKCS #8"[..],
                "changeit",
                Format::Pkcs12,
                "is not a PKCS #8 key",
            ),
            (
                &crate::test_support::synthetic_pkcs8(b"synthetic")[..],
                "pässword",
                Format::Jceks,
                "printable ASCII",
            ),
        ] {
            let protected = key_protection::protect(key, password, false, &mut TestRng(0)).unwrap();
            let mut builder = Builder::new(VERSION_02, 1);
            builder.entry_header(PRIVATE_KEY_TAG, b"key");
            builder.payload(&protected);
            builder.u32_field(0);
            let (entries, document) = open(&builder.finish(password), password);
            assert_eq!(document.format(), Format::Jks);
            let error = document.convert(&entries, target).unwrap_err();
            assert!(error.contains(reason), "{error}");
        }
        assert_eq!(Format::from_name(Path::new("a.PFX")), Some(Format::Pkcs12));
        assert_eq!(Format::from_name(Path::new("cacerts")), None);
        assert_eq!(Format::from_name(Path::new("a.pem")), None);
    }

    #[test]
    fn a_failed_save_writes_nothing() {
        let directory = TestDirectory::new();
        let path = directory.path().join("store.jks");
        fs::write(&path, KEYTOOL_JKS).unwrap();
        let (entries, document) = open(KEYTOOL_JKS, "changeit");
        // The listing no longer matches what would be written.
        let error = document.save(&path, &[]).unwrap_err();
        assert!(error.contains("nothing was written"), "{error}");
        let error = document
            .save(&directory.path().join("missing.jks"), &entries)
            .unwrap_err();
        assert!(error.contains("Cannot save"), "{error}");
        let error = document.save_new(&path, &entries).unwrap_err();
        assert!(error.contains("already exists"), "{error}");
        assert_eq!(fs::read(&path).unwrap(), KEYTOOL_JKS);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn save_as_suggests_an_unused_copy_name_next_to_the_file() {
        let directory = TestDirectory::new();
        let path = directory.path().join("store.jks");
        let prompt = SaveAsPrompt::new(&path);
        assert_eq!(
            Path::new(&prompt.path),
            directory.path().join("store-copy.jks")
        );
        fs::write(directory.path().join("store-copy.jks"), b"existing").unwrap();
        let mut prompt = SaveAsPrompt::new(&path);
        assert_eq!(
            Path::new(&prompt.path),
            directory.path().join("store-copy-2.jks")
        );
        prompt.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        prompt.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
        let Outcome::Save(saved) =
            prompt.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        else {
            panic!("Enter saves");
        };
        assert_eq!(saved, directory.path().join("a"));
    }

    /// A JKS keystore holding one private key, `key`, protected with
    /// `key_password`, under the keystore password "changeit".
    fn private_key_keystore(key: &[u8], key_password: &str) -> (Vec<KeystoreEntry>, Document) {
        use crate::keystore::{PRIVATE_KEY_TAG, VERSION_02};
        use crate::test_support::{Builder, TestRng};
        let protected = key_protection::protect(key, key_password, false, &mut TestRng(0)).unwrap();
        let mut builder = Builder::new(VERSION_02, 1);
        builder.entry_header(PRIVATE_KEY_TAG, b"key");
        builder.payload(&protected);
        builder.u32_field(0);
        open(&builder.finish("changeit"), "changeit")
    }

    #[test]
    fn a_key_password_of_its_own_is_checked_and_can_be_changed() {
        let key = crate::test_support::synthetic_pkcs8(b"synthetic");
        let (_, mut document) = private_key_keystore(&key, "own");
        assert_eq!(document.unlocks_key(0, None), Ok(false));
        assert_eq!(document.unlocks_key(0, Some("own")), Ok(true));
        let error = document.private_key(0).unwrap_err();
        assert!(error.contains("password of its own"), "{error}");
        let error = document.secret_key(0).err().unwrap();
        assert!(error.contains("not a secret key"), "{error}");
        let error = document
            .set_key_password(0, Some("wrong"), "new")
            .unwrap_err();
        assert!(error.contains("Incorrect key password"), "{error}");

        // Giving it the keystore's password makes it usable.
        document
            .set_key_password(0, Some("own"), "changeit")
            .unwrap();
        assert_eq!(document.unlocks_key(0, None), Ok(true));
        assert_eq!(*document.private_key(0).unwrap(), key);
    }

    #[test]
    fn a_jks_key_that_is_not_pkcs8_cannot_be_exported() {
        let (_, document) = private_key_keystore(b"not PKCS #8", "changeit");
        let error = document.private_key(0).unwrap_err();
        assert!(error.contains("not a PKCS #8 key"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn create_and_save_new_use_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let directory = TestDirectory::new();
        let created = directory.path().join("converted.p12");
        create(&created, b"keystore").unwrap();
        assert_eq!(
            fs::metadata(&created).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let (entries, document) = open(KEYTOOL_JKS, "changeit");
        let saved_as = directory.path().join("copy.jks");
        document.save_new(&saved_as, &entries).unwrap();
        assert_eq!(
            fs::metadata(&saved_as).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn temporary_filename_uses_random_suffix_and_retries_on_collision() {
        let directory = TestDirectory::new();
        let name = std::ffi::OsStr::new("store.jks");
        let (first, first_file) = create_temp_file(directory.path(), name, random_u64).unwrap();
        let (second, second_file) = create_temp_file(directory.path(), name, random_u64).unwrap();
        drop(first_file);
        drop(second_file);
        assert_ne!(first, second);
        let prefix = format!("store.jks.{}.", std::process::id());
        for temp in [&first, &second] {
            let file_name = temp.file_name().unwrap().to_str().unwrap();
            let rest = file_name
                .strip_prefix(&prefix)
                .and_then(|s| s.strip_suffix(".tmp"))
                .unwrap();
            assert_eq!(rest.len(), 16, "{file_name}");
            assert!(rest.chars().all(|c| c.is_ascii_hexdigit()), "{file_name}");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(temp).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            fs::remove_file(temp).unwrap();
        }

        // Colliding first suffix is skipped without touching the existing file.
        let path = directory.path().join("store.jks");
        fs::write(&path, b"original").unwrap();
        let colliding = directory.path().join(format!(
            "store.jks.{}.0000000000000001.tmp",
            std::process::id()
        ));
        fs::write(&colliding, b"other").unwrap();
        let mut suffixes = [1u64, 2u64].into_iter();
        replace_with(&path, b"updated", || Ok(suffixes.next().unwrap())).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"updated");
        assert_eq!(fs::read(&colliding).unwrap(), b"other");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);

        // Exhausting retries fails with AlreadyExists and leaves both files intact.
        let error = replace_with(&path, b"never", || Ok(1)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&colliding).unwrap(), b"other");
        assert_eq!(fs::read(&path).unwrap(), b"updated");
    }

    #[test]
    fn a_failed_replacement_removes_its_temporary_file() {
        let directory = TestDirectory::new();
        // Renaming a file over a directory fails (empty or non-empty), and the
        // temporary file written for it is removed.
        let target = directory.path().join("folder");
        fs::create_dir(&target).unwrap();
        assert!(replace(&target, b"data").is_err());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);

        fs::write(target.join("inside"), b"x").unwrap();
        assert!(replace(&target, b"data").is_err());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn creating_a_file_in_a_missing_directory_fails() {
        let directory = TestDirectory::new();
        let path = directory.path().join("missing").join("out.pem");
        let error = create_private(&path, b"data").unwrap_err();
        assert!(error.contains("Cannot create"), "{error}");
    }

    #[test]
    fn conversion_with_issuer_and_issued_certificates_succeeds_in_both_directions() {
        use crate::test_support::metadata_certificate;
        let root = metadata_certificate("Root CA", "Root CA", &[1], &[]);
        let leaf = metadata_certificate("Leaf", "Root CA", &[2], &[]);

        // PKCS12 -> JKS and PKCS12 -> JCEKS
        let mut p12 = pkcs12::Writable::empty("changeit");
        p12.insert_trusted_certificate("root", &root).unwrap();
        let p12_entries = p12.insert_trusted_certificate("leaf", &leaf).unwrap();
        let leaf_entry = p12_entries.iter().find(|e| e.alias == "leaf").unwrap();
        assert_eq!(leaf_entry.certificates(), &[leaf.clone(), root.clone()]);
        let p12_doc = Document::Pkcs12(p12);

        for target in [Format::Jks, Format::Jceks] {
            let data = p12_doc.convert(&p12_entries, target).unwrap();
            let (entries, doc) = open(&data, "changeit");
            assert_eq!(doc.format(), target);
            assert_eq!(entries.len(), 2);
            let leaf_entry = entries.iter().find(|e| e.alias == "leaf").unwrap();
            let root_entry = entries.iter().find(|e| e.alias == "root").unwrap();
            assert_eq!(leaf_entry.certificates(), std::slice::from_ref(&leaf));
            assert_eq!(root_entry.certificates(), std::slice::from_ref(&root));

            // Round-trip back: JKS -> PKCS12 and JCEKS -> PKCS12
            let back = doc.convert(&entries, Format::Pkcs12).unwrap();
            let (verified, _) = pkcs12::parse(&back).unwrap().open("changeit").unwrap();
            assert_eq!(verified.entries.len(), 2);
            let leaf_back = verified.entries.iter().find(|e| e.alias == "leaf").unwrap();
            let root_back = verified.entries.iter().find(|e| e.alias == "root").unwrap();
            assert_eq!(leaf_back.certificates(), &[leaf.clone(), root.clone()]);
            assert_eq!(root_back.certificates(), std::slice::from_ref(&root));
        }
    }

    #[test]
    fn conversion_still_checks_full_certificate_chain_for_private_keys() {
        use crate::test_support::{TestRng, metadata_certificate, synthetic_pkcs8};
        let key = synthetic_pkcs8(b"synthetic");
        let root = metadata_certificate("Root CA", "Root CA", &[1], &[]);
        let leaf = metadata_certificate("Leaf", "Root CA", &[2], &[]);
        let unrelated = metadata_certificate("Other CA", "Other CA", &[3], &[]);

        // An unlinked private-key chain must still fail JKS -> PKCS12 conversion.
        let mut writable = keystore::Writable::empty(false);
        let protected = key_protection::protect(&key, "changeit", false, &mut TestRng(0)).unwrap();
        writable
            .insert_private_key(0, "key", &protected, &[leaf.clone(), unrelated], 1)
            .unwrap();
        let jks_bytes = writable.encode("changeit");
        let (entries, document) = open(&jks_bytes, "changeit");
        let error = document.convert(&entries, Format::Pkcs12).unwrap_err();
        assert!(
            error.contains("would not read back with the same entries and keys"),
            "{error}"
        );

        // A properly linked private-key chain succeeds in both directions and
        // preserves the full chain.
        let mut writable = keystore::Writable::empty(false);
        writable
            .insert_private_key(0, "key", &protected, &[leaf.clone(), root.clone()], 1)
            .unwrap();
        let jks_bytes = writable.encode("changeit");
        let (entries, document) = open(&jks_bytes, "changeit");
        let p12_bytes = document.convert(&entries, Format::Pkcs12).unwrap();
        let (verified, p12_writable) = pkcs12::parse(&p12_bytes).unwrap().open("changeit").unwrap();
        assert_eq!(
            verified.entries[0].certificates(),
            &[leaf.clone(), root.clone()]
        );
        let p12_doc = Document::Pkcs12(p12_writable.unwrap());
        let jks_back = p12_doc.convert(&verified.entries, Format::Jks).unwrap();
        let (back_entries, _) = open(&jks_back, "changeit");
        assert_eq!(back_entries[0].certificates(), &[leaf, root]);
    }

    #[test]
    fn os_rng_short_circuits_after_failure() {
        let mut rng = OsRng { failed: true };
        let mut buf = [0xaa; 8];
        assert_eq!(rng.try_fill_bytes(&mut buf), Err(NO_RANDOMNESS.into()));
        assert_eq!(buf, [0xaa; 8]);
        assert_eq!(rng.check(), Err(NO_RANDOMNESS.into()));
    }

    #[test]
    fn pkcs12_mutations_leave_document_unchanged_on_rng_failure() {
        use crate::test_support::{metadata_certificate, synthetic_pkcs8};

        let cert = metadata_certificate("leaf", "leaf", &[1], &[]);
        let key = synthetic_pkcs8(b"synthetic key");
        let secret = SecretKey {
            algorithm: "AES".into(),
            key: Zeroizing::new(vec![0x42; 16]),
        };

        let mut writable = pkcs12::Writable::empty("changeit");
        let mut entries = writable
            .insert_private_key(
                "existing",
                &key,
                std::slice::from_ref(&cert),
                &mut crate::test_support::TestRng(0),
            )
            .unwrap();
        let mut doc = Document::Pkcs12(writable);
        let original_aliases: Vec<String> = entries.iter().map(|e| e.alias.clone()).collect();

        // Failing RNG on set_password must not change the stored password or keys.
        let error = doc
            .set_password_with_rng("newpass", OsRng { failed: true })
            .unwrap_err();
        assert_eq!(error, NO_RANDOMNESS);
        assert_eq!(doc.password(), "changeit");
        assert_eq!(*doc.private_key(0).unwrap(), key);

        // Failing RNG on import_key_pair must not mutate writable or entries.
        let other_cert = metadata_certificate("other", "other", &[2], &[]);
        let error = doc
            .import_key_pair_with_rng(
                &mut entries,
                "other".into(),
                &key,
                std::slice::from_ref(&other_cert),
                OsRng { failed: true },
            )
            .unwrap_err();
        assert_eq!(error, NO_RANDOMNESS);
        assert_eq!(
            entries.iter().map(|e| e.alias.as_str()).collect::<Vec<_>>(),
            original_aliases
        );
        assert!(doc.encode(&entries).is_ok());

        // Failing RNG on import_secret_key must not mutate writable or entries.
        let error = doc
            .import_secret_key_with_rng(
                &mut entries,
                "secret".into(),
                &secret,
                OsRng { failed: true },
            )
            .unwrap_err();
        assert_eq!(error, NO_RANDOMNESS);
        assert_eq!(
            entries.iter().map(|e| e.alias.as_str()).collect::<Vec<_>>(),
            original_aliases
        );
        assert!(doc.encode(&entries).is_ok());
    }

    #[test]
    fn save_as_prompt_joins_a_relative_directory_once() {
        let directory = TestDirectory::in_working_directory();
        let relative = crate::test_support::relative_to_working_directory(directory.path());
        assert!(relative.is_relative());
        fs::write(relative.join("keystore.jks"), b"existing").unwrap();
        let mut prompt = SaveAsPrompt::for_new(relative.clone());
        assert_eq!(&*prompt.path, "keystore-2.jks");
        let Outcome::Save(path) =
            prompt.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        else {
            panic!("expected a save");
        };
        assert_eq!(path, relative.join("keystore-2.jks"));
    }

    #[cfg(unix)]
    #[test]
    fn replace_uses_owner_only_temp_file_and_preserves_target_mode() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        let path = directory.path().join("store.jks");
        fs::write(&path, b"original").unwrap();

        let (temp, file) = create_temp_file(
            directory.path(),
            std::ffi::OsStr::new("store.jks"),
            random_u64,
        )
        .unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        drop(file);
        fs::remove_file(&temp).unwrap();

        for mode in [0o600, 0o640] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            replace(&path, b"updated").unwrap();
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                mode,
                "mode {mode:#o}"
            );
            assert_eq!(fs::read(&path).unwrap(), b"updated");
            assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        }
    }
}
