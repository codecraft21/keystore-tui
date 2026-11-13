//! Importing a key pair: finding the private key in a PEM or PKCS #8 file,
//! or a keystore to copy entries from, matching a key to its certificate,
//! and the prompts in between.
use std::path::Path;

use crown::{
    asn1::{Reader, der, oid, oid::ObjectIdentifier, pem},
    x509::{
        cert::Certificate,
        keys::{EncryptedPrivateKeyInfo, PrivateKeyInfo, SubjectPublicKeyInfo},
    },
};
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use zeroize::Zeroizing;

use crate::{
    App, MAX_KEYSTORE_SIZE, Password, certificate_file,
    editing::{Action, AliasPrompt},
    keystore::{self, Content},
    pkcs12, read_limited, save,
};

/// A private key as PKCS #8, wiped when dropped.
pub type Key = Zeroizing<Vec<u8>>;
/// Certificate chains, each starting with its own certificate.
type Chains = Vec<Vec<Vec<u8>>>;

/// What an import file holds besides certificates.
pub enum Found {
    Key(Key),
    Locked(Locked),
}

/// A key or a keystore that needs its file's password.
pub enum Locked {
    /// An `EncryptedPrivateKeyInfo`.
    Encrypted(Vec<u8>),
    /// A PKCS12 keystore.
    Pkcs12(pkcs12::Store),
    /// A JKS or JCEKS keystore.
    Jks(keystore::Keystore),
}

/// A key pair import that is waiting for the user.
pub struct KeyImport {
    /// The file the key comes from, as shown in messages.
    file: String,
    stage: Stage,
}

enum Stage {
    /// The password of the key's file is being typed.
    Locked {
        source: Locked,
        chains: Chains,
        password: Password,
    },
    /// The file browser is choosing the file with the key's certificates.
    Certificates(Key),
}

impl KeyImport {
    /// The file whose password is being typed and the password so far.
    pub fn password(&self) -> Option<(&str, &str)> {
        match &self.stage {
            Stage::Locked { password, .. } => Some((&self.file, &password.0)),
            Stage::Certificates(_) => None,
        }
    }
}

/// Looks for a private key in the file content `data`. `None` means the
/// file holds none and may be a certificate file.
pub fn find(data: &[u8]) -> Result<Option<Found>, String> {
    if certificate_file::is_pem(data) {
        let Some(text) = std::str::from_utf8(data).ok() else {
            return Ok(None);
        };
        let mut keys: Vec<_> = pem::parse(text)
            .unwrap_or_default()
            .into_iter()
            .filter(|block| block.label.ends_with("PRIVATE KEY"))
            .map(|block| (block.label, Zeroizing::new(block.data)))
            .collect();
        let Some((label, key)) = keys.pop() else {
            return Ok(None);
        };
        if !keys.is_empty() {
            return Err("holds several private keys; import a file with a single one".into());
        }
        if text.contains("Proc-Type: 4,ENCRYPTED") {
            return Err(
                "is encrypted in OpenSSL's old format; convert the key to PKCS #8 first".into(),
            );
        }
        let malformed = || "holds a malformed private key".to_owned();
        match label.as_str() {
            "PRIVATE KEY" if pkcs12::is_private_key_info(&key) => Ok(Some(Found::Key(key))),
            "ENCRYPTED PRIVATE KEY" if EncryptedPrivateKeyInfo::parse(&key).is_ok() => {
                Ok(Some(Found::Locked(Locked::Encrypted(key.to_vec()))))
            }
            "RSA PRIVATE KEY" => Ok(Some(Found::Key(pkcs8(
                oid::OID_RSA_ENCRYPTION,
                &der::null(),
                &key,
            )))),
            "EC PRIVATE KEY" => {
                let curve = ec_curve(&key).ok_or_else(malformed)?;
                Ok(Some(Found::Key(pkcs8(oid::OID_EC_PUBLIC_KEY, curve, &key))))
            }
            "PRIVATE KEY" | "ENCRYPTED PRIVATE KEY" => Err(malformed()),
            _ => Err(format!(
                "holds a '{label}' block, which is not supported; convert the key to PKCS #8 first"
            )),
        }
    } else if pkcs12::is_private_key_info(data) {
        Ok(Some(Found::Key(Zeroizing::new(data.to_vec()))))
    } else if EncryptedPrivateKeyInfo::parse(data).is_ok() {
        Ok(Some(Found::Locked(Locked::Encrypted(data.to_vec()))))
    } else if keystore::has_magic(data) {
        Ok(keystore::parse(data.to_vec())
            .ok()
            .map(|store| Found::Locked(Locked::Jks(store))))
    } else if certificate_file::parse(data).is_err() {
        Ok(pkcs12::parse(data)
            .ok()
            .map(|store| Found::Locked(Locked::Pkcs12(store))))
    } else {
        Ok(None)
    }
}

/// The curve named inside an `ECPrivateKey`, as an encoded object identifier.
fn ec_curve(key: &[u8]) -> Option<&[u8]> {
    let mut key = Reader::new(key).read_sequence().ok()?;
    key.read_integer().ok()?;
    key.read_octet_string().ok()?;
    key.read_explicit(0).ok()?.read_raw_tlv().ok()
}

/// A PKCS #8 `PrivateKeyInfo` around `key`, a key in its algorithm's own
/// encoding.
fn pkcs8(algorithm: &[u64], parameters: &[u8], key: &[u8]) -> Key {
    let algorithm = ObjectIdentifier::new(algorithm).expect("static oid");
    let octets = Zeroizing::new(der::octet_string(key));
    let mut content = Zeroizing::new(Vec::with_capacity(octets.len() + 64));
    content.extend(der::integer(&[0]));
    content.extend(der::sequence(
        &[der::oid(&algorithm), parameters.to_vec()].concat(),
    ));
    content.extend_from_slice(&octets);
    Zeroizing::new(der::sequence(&content))
}

/// The certificate chains in the certificate file content `data`.
pub(crate) fn chains(data: &[u8]) -> Chains {
    certificate_file::parse(data)
        .map(|file| file.entries)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| match entry.content {
            Content::Certificates { certificates, .. } => Some(certificates),
            Content::Request(_) => None,
        })
        .collect()
}

/// The chain whose first certificate holds the public key of `key`, if any.
/// Fails for a type of key whose public key cannot be worked out.
pub fn matching_chain(
    key: &[u8],
    chains: &[Vec<Vec<u8>>],
) -> Result<Option<Vec<Vec<u8>>>, &'static str> {
    let public = PrivateKeyInfo::parse(key)
        .and_then(|info| info.decode())
        .and_then(|key| key.public_key())
        .and_then(|public| SubjectPublicKeyInfo::from_public_key(&public))
        .map_err(|_| "this type of private key is not supported")?
        .encode();
    let holds_key = |certificate: &[u8]| {
        Certificate::parse(certificate)
            .and_then(|parsed| SubjectPublicKeyInfo::from_public_key(parsed.public_key()))
            .is_ok_and(|info| info.encode() == public)
    };
    Ok(chains
        .iter()
        .find(|chain| chain.first().is_some_and(|leaf| holds_key(leaf)))
        .cloned())
}

/// The file's name, as shown in messages.
pub(crate) fn name(path: &Path) -> String {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}

impl App {
    /// Imports from the file chosen in the file browser: a key pair if the
    /// file holds a private key, a trusted certificate otherwise.
    pub(crate) fn import_file(&mut self, path: &Path) {
        let read = read_limited(path, MAX_KEYSTORE_SIZE)
            .map(Zeroizing::new)
            .map_err(|error| format!("Cannot read {}: {error}", path.display()));
        let file = name(path);
        let result = read.and_then(|data| match self.key_import.take() {
            Some(KeyImport {
                stage: Stage::Certificates(key),
                ..
            }) => self.ask_key_alias(&file, key, &chains(&data)),
            _ => match find(&data).map_err(|error| format!("'{file}' {error}."))? {
                Some(Found::Key(key)) => self.import_key(file, key, chains(&data)),
                Some(Found::Locked(source)) => {
                    self.key_import = Some(KeyImport {
                        file,
                        stage: Stage::Locked {
                            source,
                            chains: chains(&data),
                            password: Password::default(),
                        },
                    });
                    Ok(())
                }
                None => self.import_certificate(path, &data),
            },
        });
        if let Err(error) = result {
            self.message = Some((error, true));
        }
    }

    /// Continues with a readable key: asks for its certificate file when
    /// its own file has no certificates, and for the alias otherwise.
    fn import_key(&mut self, file: String, key: Key, chains: Chains) -> Result<(), String> {
        if !chains.is_empty() {
            return self.ask_key_alias(&file, key, &chains);
        }
        self.open_picker();
        if self.file_picker.is_some() {
            self.importing = true;
            self.key_import = Some(KeyImport {
                file,
                stage: Stage::Certificates(key),
            });
        }
        Ok(())
    }

    /// Asks for the alias of the key pair made of `key` and its chain among
    /// the `chains` read from `file`, suggesting the certificate's
    /// subject name.
    fn ask_key_alias(
        &mut self,
        file: &str,
        key: Key,
        chains: &[Vec<Vec<u8>>],
    ) -> Result<(), String> {
        let chain = matching_chain(&key, chains)
            .map_err(|error| format!("Not imported: {error}."))?
            .ok_or_else(|| {
                format!("Not imported: no certificate in '{file}' matches the private key.")
            })?;
        let alias = certificate_file::subject_name(&chain[0])
            .unwrap_or_default()
            .to_lowercase();
        self.alias_prompt = Some(AliasPrompt {
            action: Action::ImportKey(key, chain),
            alias,
        });
        Ok(())
    }

    /// Whether the password of a key's file is being typed.
    pub(crate) fn unlocking_import(&self) -> bool {
        self.key_import
            .as_ref()
            .is_some_and(|import| import.password().is_some())
    }

    /// Stops choosing the certificate file of a key, wiping the key.
    pub(crate) fn cancel_key_import(&mut self) {
        self.key_import = None;
    }

    pub(crate) fn handle_import_password(&mut self, key: KeyEvent) {
        let Some(KeyImport {
            stage: Stage::Locked { password, .. },
            ..
        }) = &mut self.key_import
        else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.key_import = None,
            KeyCode::Char(ch) if crate::is_text_input(key.modifiers) => password.push(ch),
            KeyCode::Backspace => password.pop(),
            KeyCode::Enter => {
                if let Err(error) = self.unlock_import() {
                    self.message = Some((error, true));
                }
            }
            _ => {}
        }
    }

    /// Reads the key with the typed password. A wrong password leaves the
    /// prompt open for another attempt.
    fn unlock_import(&mut self) -> Result<(), String> {
        let Some(KeyImport {
            file,
            stage:
                Stage::Locked {
                    source,
                    chains,
                    password,
                },
        }) = self.key_import.take()
        else {
            return Ok(());
        };
        let failed = |error: &str| format!("Not imported from '{file}': {error}.");
        // A keystore's entries are chosen from a list; a key continues alone.
        let (source, unlocked) = match source {
            Locked::Pkcs12(store) => match store.open(&password.0) {
                Ok((verified, writable)) => {
                    let writable = writable.ok_or_else(|| failed("it was not read completely"))?;
                    let source = save::Document::Pkcs12(writable);
                    return self.choose_entries(file, source, verified.entries);
                }
                Err(pkcs12::VerifyError::Password) => (Locked::Pkcs12(store), None),
                Err(pkcs12::VerifyError::Invalid(error)) => return Err(failed(error)),
            },
            Locked::Jks(store) => match store.open(&password.0) {
                Ok((entries, writable)) => {
                    let source = save::Document::jks(writable, &password.0);
                    return self.choose_entries(file, source, entries);
                }
                Err(store) => (Locked::Jks(store), None),
            },
            Locked::Encrypted(encrypted) => {
                let key = pkcs12::decrypt_key(&encrypted, password.0.as_bytes());
                (Locked::Encrypted(encrypted), key)
            }
        };
        match unlocked {
            Some(key) => self.import_key(file, key, chains),
            None => {
                self.key_import = Some(KeyImport {
                    file,
                    stage: Stage::Locked {
                        source,
                        chains,
                        password: Password::default(),
                    },
                });
                Err("Incorrect password.".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestRng, ed25519_certificate, ed25519_pkcs8};
    use crown::{
        asn1::Asn1Time,
        x509::{
            algorithm::{Hash, SignatureAlgorithm},
            name::Name,
        },
    };

    fn found_key(data: &[u8]) -> Key {
        match find(data) {
            Ok(Some(Found::Key(key))) => key,
            _ => panic!("a readable key"),
        }
    }

    fn error(data: &[u8]) -> String {
        find(data).err().unwrap()
    }

    #[test]
    fn finds_pkcs8_keys_in_pem_and_der() {
        let key = ed25519_pkcs8(7);
        assert_eq!(*found_key(&key), key);
        let text = pem::encode("PRIVATE KEY", &key);
        assert_eq!(*found_key(text.as_bytes()), key);
        // Certificates, keystores, and other data hold no key.
        let certificate = ed25519_certificate("leaf", "leaf", 7, 7);
        for data in [
            &certificate[..],
            pem::encode("CERTIFICATE", &certificate).as_bytes(),
            b"\xfe\xed\xfe\xed",
            b"-----BEGIN \xff",
            b"neither",
        ] {
            assert!(matches!(find(data), Ok(None)));
        }
    }

    #[test]
    fn refuses_keys_it_cannot_read() {
        let key = pem::encode("PRIVATE KEY", &ed25519_pkcs8(7));
        assert!(error(format!("{key}{key}").as_bytes()).contains("several private keys"));
        let legacy = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\
            DEK-Info: AES-256-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        assert!(error(legacy.as_bytes()).contains("OpenSSL's old format"));
        for label in ["PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "EC PRIVATE KEY"] {
            let text = pem::encode(label, b"\x30\x00");
            assert!(error(text.as_bytes()).contains("malformed"), "{label}");
        }
        let text = pem::encode("DSA PRIVATE KEY", b"\x30\x00");
        assert!(error(text.as_bytes()).contains("'DSA PRIVATE KEY' block"));
    }

    #[test]
    fn wraps_openssl_keys_as_pkcs8() {
        // An `ECPrivateKey` on P-256 with a synthetic scalar.
        let curve = der::oid(&ObjectIdentifier::new(&[1, 2, 840, 10045, 3, 1, 7]).unwrap());
        let sec1 = der::sequence(
            &[
                der::integer(&[1]),
                der::octet_string(&[5; 32]),
                der::explicit(0, &curve),
            ]
            .concat(),
        );
        let key = found_key(pem::encode("EC PRIVATE KEY", &sec1).as_bytes());
        let info = PrivateKeyInfo::parse(&key).unwrap();
        assert!(info.algorithm.oid.matches(oid::OID_EC_PUBLIC_KEY));
        assert_eq!(info.private_key, sec1);
        // The wrapped key matches a certificate made with it.
        let time = |seconds| Asn1Time::from_unix(seconds, true);
        let certificate = Certificate::self_signed(
            Name::from_common_name("ec"),
            SignatureAlgorithm::Ecdsa(Hash::Sha256),
            &info.decode().unwrap(),
            time(0),
            time(1_000_000_000),
            vec![],
            &mut TestRng(1),
        )
        .unwrap()
        .encode();
        let other = ed25519_certificate("other", "other", 7, 7);
        let chains = [vec![other.clone()], vec![certificate.clone(), other]];
        assert_eq!(matching_chain(&key, &chains), Ok(Some(chains[1].clone())));
        assert_eq!(matching_chain(&key, &chains[..1]), Ok(None));

        // An `RSAPrivateKey` is wrapped whole; this one is not a real key.
        let key = found_key(pem::encode("RSA PRIVATE KEY", b"synthetic").as_bytes());
        let info = PrivateKeyInfo::parse(&key).unwrap();
        assert!(info.algorithm.oid.matches(oid::OID_RSA_ENCRYPTION));
        assert_eq!(info.algorithm.parameters.as_deref(), Some(&der::null()[..]));
        assert_eq!(info.private_key, b"synthetic");
        assert_eq!(
            matching_chain(&key, &chains),
            Err("this type of private key is not supported")
        );
    }
}
