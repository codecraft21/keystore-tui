//! Exporting a private key, alone or with its certificates, to a new
//! PKCS12, PEM, or DER file.
use std::path::{Path, PathBuf};

use crown::{asn1::pem, rng::Rng};
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use zeroize::Zeroizing;

use crate::{
    App, Confirm, Password,
    export::{ExportPrompt, Outcome, Scope},
    keystore::Kind,
    legacy_pem,
    new_password::{NewPasswordPrompt, Purpose},
    path_bar, pkcs12, save,
};

/// What an exported file holds, chosen by its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// A PKCS12 keystore with the key and its certificates.
    Pkcs12,
    /// PEM blocks: the key (PKCS #8 or legacy OpenSSL), then its certificates.
    PemPair,
    /// The key alone, as a PEM block (PKCS #8 or legacy OpenSSL).
    PemKey,
    /// The key alone, as PKCS #8 DER.
    DerKey,
}

impl Format {
    /// `.p12` and `.pfx` name a PKCS12 keystore, `.key` the key in PEM,
    /// `.p8` and `.der` the key in DER, and any other name PEM with the
    /// certificates. Case is ignored.
    pub fn from_name(path: &Path) -> Self {
        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        match extension.as_str() {
            "p12" | "pfx" => Self::Pkcs12,
            "key" => Self::PemKey,
            "p8" | "der" => Self::DerKey,
            _ => Self::PemPair,
        }
    }

    pub fn is_pem(self) -> bool {
        matches!(self, Self::PemPair | Self::PemKey)
    }
}

/// The file content for `format`: the PKCS #8 private key `key`, encrypted
/// with `password` unless it is empty, and its certificate `chain`. When
/// `legacy` is true and `format` is PEM, writes OpenSSL's legacy
/// `RSA PRIVATE KEY` or `EC PRIVATE KEY` format instead of PKCS #8. The
/// encrypted key is decrypted again as a check before it is returned.
pub fn encode(
    format: Format,
    legacy: bool,
    alias: &str,
    key: &[u8],
    chain: &[Vec<u8>],
    password: &str,
    rng: &mut impl Rng,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let failed = |error: &str| format!("Not exported: {error}.");
    if format == Format::Pkcs12 {
        if password.is_empty() {
            return Err(failed("a PKCS12 file needs a password that is not empty"));
        }
        let mut writable = pkcs12::Writable::empty(password);
        let entries = writable
            .insert_private_key(alias, key, chain, rng)
            .map_err(failed)?;
        // PKCS12 rebuilds the chain from issuer names when it is read.
        let same = matches!(&entries[..], [entry] if entry.certificates() == chain)
            && writable.private_key(0).as_deref().map(Vec::as_slice) == Some(key);
        if !same {
            return Err(failed(
                "the key pair would not read back the same, for example because its certificate chain is not linked by issuer names",
            ));
        }
        return writable.encode(rng).map(Zeroizing::new).map_err(failed);
    }
    if legacy && format.is_pem() {
        let (label, raw) = legacy_pem::from_pkcs8(key).map_err(failed)?;
        let certificates: String = if format == Format::PemPair {
            chain
                .iter()
                .map(|certificate| pem::encode("CERTIFICATE", certificate))
                .collect()
        } else {
            String::new()
        };
        return if password.is_empty() {
            Ok(legacy_pem::pem_block(
                label,
                "",
                &raw,
                certificates.as_bytes(),
            ))
        } else {
            legacy_pem::encrypt_pem_block(
                label,
                &raw,
                password.as_bytes(),
                rng,
                certificates.as_bytes(),
            )
            .map_err(failed)
        };
    }
    let (label, key) = if password.is_empty() {
        ("PRIVATE KEY", Zeroizing::new(key.to_vec()))
    } else {
        let encrypted = pkcs12::encrypt_key(key, password.as_bytes(), rng).map_err(failed)?;
        if pkcs12::decrypt_key(&encrypted, password.as_bytes())
            .as_deref()
            .map(Vec::as_slice)
            != Some(key)
        {
            return Err(failed("the encrypted key would not decrypt again"));
        }
        ("ENCRYPTED PRIVATE KEY", Zeroizing::new(encrypted))
    };
    Ok(match format {
        Format::DerKey => key,
        Format::PemKey => legacy_pem::pem_block(label, "", &key, &[]),
        Format::PemPair | Format::Pkcs12 => {
            let certificates: String = chain
                .iter()
                .map(|certificate| pem::encode("CERTIFICATE", certificate))
                .collect();
            legacy_pem::pem_block(label, "", &key, certificates.as_bytes())
        }
    })
}

/// The file name being typed for the export of the private key at `index`
/// of the app's entries.
pub struct KeyExport {
    index: usize,
    pub prompt: ExportPrompt,
    legacy_label: Option<&'static str>,
    legacy: bool,
}

impl KeyExport {
    /// Whether `Tab` can toggle between PKCS #8 and legacy OpenSSL PEM for
    /// the current key and typed file name.
    pub fn can_toggle_legacy(&self) -> bool {
        self.legacy_label.is_some() && Format::from_name(Path::new(&self.prompt.path)).is_pem()
    }

    /// Whether the export will write legacy OpenSSL PEM.
    pub fn use_legacy(&self) -> bool {
        self.legacy && self.can_toggle_legacy()
    }
}

impl App {
    /// Asks for the file to export the selected private key to.
    pub(crate) fn ask_key_export(&mut self) {
        if !self.editable() {
            return;
        }
        let (Some(index), Some(document), Some(path)) =
            (self.selected_entry(), &self.document, &self.keystore_path)
        else {
            return;
        };
        if self.is_secret_key(index) {
            return self.ask_secret_export(index);
        }
        let entry = &self.entries[index];
        let readable = if entry.kind() == Kind::PrivateKey.label() {
            document
                .private_key(index)
                .map(|key| legacy_pem::legacy_label(&key))
                .map_err(|error| format!("Not exported: the key '{}' {error}.", entry.alias))
        } else {
            Err(
                "Only private and secret keys are exported with e; export certificates from the details (Enter, then x)."
                    .into(),
            )
        };
        match readable {
            Ok(legacy_label) => {
                let directory = path_bar::directory(path);
                self.key_export = Some(KeyExport {
                    index,
                    prompt: ExportPrompt::new(Scope::KeyPair, &directory, &entry.alias),
                    legacy_label,
                    legacy: false,
                });
            }
            Err(error) => self.message = Some((error, true)),
        }
    }

    /// Types the export's file name, then asks for the file's password.
    pub(crate) fn handle_key_export(&mut self, key: KeyEvent) {
        let Some(export) = &mut self.key_export else {
            return;
        };
        if key.code == KeyCode::Tab && export.can_toggle_legacy() {
            export.legacy = !export.legacy;
            return;
        }
        match export.prompt.handle_key(key) {
            Outcome::Editing => {}
            Outcome::Cancelled => self.key_export = None,
            Outcome::Save(path) if save::path_exists(&path) => {
                self.message = Some((
                    format!("'{}' already exists; choose another name.", path.display()),
                    true,
                ));
            }
            Outcome::Save(path) => {
                let index = export.index;
                let legacy = export.use_legacy();
                self.key_export = None;
                self.new_password =
                    Some(NewPasswordPrompt::new(Purpose::Export(path, index, legacy)));
            }
        }
    }

    /// Exports with the typed password. An empty one asks first, because
    /// the key is then written unencrypted; an encrypted legacy OpenSSL PEM
    /// asks first because it uses weaker MD5 key derivation.
    pub(crate) fn export_key_with(
        &mut self,
        path: PathBuf,
        index: usize,
        password: Password,
        legacy: bool,
    ) {
        if password.0.is_empty() && Format::from_name(&path) != Format::Pkcs12 {
            self.confirm = Some(Confirm::ExportPlain(path, index, legacy));
        } else if legacy && Format::from_name(&path).is_pem() {
            self.confirm = Some(Confirm::ExportLegacyEncrypted(path, index, password));
        } else {
            self.export_key(&path, index, &password.0, legacy);
        }
    }

    /// Writes the private key at `index`, with its certificates if the
    /// name asks for them, to the new file `path`.
    pub(crate) fn export_key(&mut self, path: &Path, index: usize, password: &str, legacy: bool) {
        let Some(document) = &self.document else {
            return;
        };
        let entry = &self.entries[index];
        let result = document
            .private_key(index)
            .map_err(|error| format!("Not exported: the key '{}' {error}.", entry.alias))
            .and_then(|key| {
                save::OsRng::default().check()?;
                let mut rng = save::OsRng::default();
                let data = encode(
                    Format::from_name(path),
                    legacy,
                    &entry.alias,
                    &key,
                    entry.certificates(),
                    password,
                    &mut rng,
                )?;
                rng.check()?;
                save::create_private(path, &data)
            });
        self.message = Some(match result {
            Ok(()) => (
                format!("Exported key '{}' to '{}'.", entry.alias, path.display()),
                false,
            ),
            Err(error) => (error, true),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestRng, metadata_certificate, synthetic_pkcs8};

    #[test]
    fn the_file_name_chooses_what_is_exported() {
        for (name, format) in [
            ("a.p12", Format::Pkcs12),
            ("a.PFX", Format::Pkcs12),
            ("a.key", Format::PemKey),
            ("a.p8", Format::DerKey),
            ("a.DER", Format::DerKey),
            ("a.pem", Format::PemPair),
            ("a", Format::PemPair),
        ] {
            assert_eq!(Format::from_name(Path::new(name)), format, "{name}");
        }
    }

    #[test]
    fn a_chain_pkcs12_cannot_rebuild_is_not_exported() {
        let key = synthetic_pkcs8(b"synthetic, not a private key");
        let leaf = metadata_certificate("leaf", "ca", &[1], &[]);
        let unrelated = metadata_certificate("other", "other", &[2], &[]);
        let export = |format, chain: &[Vec<u8>]| {
            encode(
                format,
                false,
                "alias",
                &key,
                chain,
                "password",
                &mut TestRng(1),
            )
        };
        let chain = [leaf, unrelated];
        let error = export(Format::Pkcs12, &chain).unwrap_err();
        assert!(error.contains("would not read back the same"), "{error}");
        // PEM keeps the certificates as they are stored.
        let text = String::from_utf8(export(Format::PemPair, &chain).unwrap().to_vec()).unwrap();
        let blocks = pem::parse(&text).unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[2].data, chain[1]);
        assert!(export(Format::Pkcs12, &chain[..1]).is_ok());
    }

    #[test]
    fn key_blocks_match_the_usual_pem_and_fill_their_buffer_exactly() {
        let certificates = pem::encode("CERTIFICATE", b"certificate");
        for length in 0..200 {
            let data: Vec<u8> = (0..length).map(|byte| byte as u8).collect();
            let block = legacy_pem::pem_block("PRIVATE KEY", "", &data, certificates.as_bytes());
            let expected = pem::encode("PRIVATE KEY", &data) + &certificates;
            assert_eq!(block.as_slice(), expected.as_bytes(), "{length}");
            assert_eq!(block.len(), block.capacity(), "{length}");
        }
    }

    #[test]
    fn plain_and_encrypted_keys_export_to_pem_and_der() {
        let key = synthetic_pkcs8(b"synthetic, not a private key");
        let chain = [metadata_certificate("leaf", "leaf", &[1], &[])];
        for password in ["", "password"] {
            let export = |format| {
                encode(
                    format,
                    false,
                    "alias",
                    &key,
                    &chain,
                    password,
                    &mut TestRng(1),
                )
                .unwrap()
            };
            let der = export(Format::DerKey);
            let decrypted = if password.is_empty() {
                der.to_vec()
            } else {
                pkcs12::decrypt_key(&der, password.as_bytes())
                    .unwrap()
                    .to_vec()
            };
            assert_eq!(decrypted, key);
            let label = if password.is_empty() {
                "PRIVATE KEY"
            } else {
                "ENCRYPTED PRIVATE KEY"
            };
            let text = String::from_utf8(export(Format::PemKey).to_vec()).unwrap();
            let blocks = pem::parse(&text).unwrap();
            assert_eq!((blocks.len(), blocks[0].label.as_str()), (1, label));
            let text = String::from_utf8(export(Format::PemPair).to_vec()).unwrap();
            let blocks = pem::parse(&text).unwrap();
            assert_eq!(blocks.len(), 2);
            assert_eq!(blocks[1].data, chain[0]);
        }
    }
}
