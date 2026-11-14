//! Exporting a private key, alone or with its certificates, to a new
//! PKCS12, PEM, or DER file.
use std::path::{Path, PathBuf};

use crown::{asn1::pem, rng::Rng};

use crate::{
    App, Confirm,
    export::{ExportPrompt, Outcome, Scope},
    keystore::Kind,
    new_password::{NewPasswordPrompt, Purpose},
    path_bar, pkcs12, save,
};

/// What an exported file holds, chosen by its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// A PKCS12 keystore with the key and its certificates.
    Pkcs12,
    /// PEM blocks: the key as PKCS #8, then its certificates.
    PemPair,
    /// The key alone, as a PKCS #8 PEM block.
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
}

/// The file content for `format`: the PKCS #8 private key `key`, encrypted
/// with `password` unless it is empty, and its certificate `chain`. The
/// encrypted key is decrypted again as a check before it is returned.
pub fn encode(
    format: Format,
    alias: &str,
    key: &[u8],
    chain: &[Vec<u8>],
    password: &str,
    rng: &mut impl Rng,
) -> Result<Vec<u8>, String> {
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
        return writable.encode(rng).map_err(failed);
    }
    let (label, key) = if password.is_empty() {
        ("PRIVATE KEY", zeroize::Zeroizing::new(key.to_vec()))
    } else {
        let encrypted = pkcs12::encrypt_key(key, password.as_bytes(), rng).map_err(failed)?;
        if pkcs12::decrypt_key(&encrypted, password.as_bytes())
            .as_deref()
            .map(Vec::as_slice)
            != Some(key)
        {
            return Err(failed("the encrypted key would not decrypt again"));
        }
        ("ENCRYPTED PRIVATE KEY", zeroize::Zeroizing::new(encrypted))
    };
    Ok(match format {
        Format::DerKey => key.to_vec(),
        Format::PemKey => pem::encode(label, &key).into_bytes(),
        Format::PemPair | Format::Pkcs12 => {
            let mut text = pem::encode(label, &key);
            for certificate in chain {
                text.push_str(&pem::encode("CERTIFICATE", certificate));
            }
            text.into_bytes()
        }
    })
}

/// The file name being typed for the export of the private key at `index`
/// of the app's entries.
pub struct KeyExport {
    index: usize,
    pub prompt: ExportPrompt,
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
                .map(drop)
                .map_err(|error| format!("Not exported: the key '{}' {error}.", entry.alias))
        } else {
            Err(
                "Only private and secret keys are exported with e; export certificates from the details (Enter, then x)."
                    .into(),
            )
        };
        match readable {
            Ok(()) => {
                let directory = path_bar::directory(path);
                self.key_export = Some(KeyExport {
                    index,
                    prompt: ExportPrompt::new(Scope::KeyPair, &directory, &entry.alias),
                });
            }
            Err(error) => self.message = Some((error, true)),
        }
    }

    /// Types the export's file name, then asks for the file's password.
    pub(crate) fn handle_key_export(&mut self, key: ratatui::crossterm::event::KeyEvent) {
        let Some(export) = &mut self.key_export else {
            return;
        };
        match export.prompt.handle_key(key) {
            Outcome::Editing => {}
            Outcome::Cancelled => self.key_export = None,
            Outcome::Save(path) if path.exists() => {
                self.message = Some((
                    format!("'{}' already exists; choose another name.", path.display()),
                    true,
                ));
            }
            Outcome::Save(path) => {
                let index = export.index;
                self.key_export = None;
                self.new_password = Some(NewPasswordPrompt::new(Purpose::Export(path, index)));
            }
        }
    }

    /// Exports with the typed password. An empty one asks first, because
    /// the key is then written unencrypted.
    pub(crate) fn export_key_with(&mut self, path: PathBuf, index: usize, password: &str) {
        if password.is_empty() && Format::from_name(&path) != Format::Pkcs12 {
            self.confirm = Some(Confirm::ExportPlain(path, index));
        } else {
            self.export_key(&path, index, password);
        }
    }

    /// Writes the private key at `index`, with its certificates if the
    /// name asks for them, to the new file `path`.
    pub(crate) fn export_key(&mut self, path: &Path, index: usize, password: &str) {
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
            encode(format, "alias", &key, chain, "password", &mut TestRng(1))
        };
        let chain = [leaf, unrelated];
        let error = export(Format::Pkcs12, &chain).unwrap_err();
        assert!(error.contains("would not read back the same"), "{error}");
        // PEM keeps the certificates as they are stored.
        let text = String::from_utf8(export(Format::PemPair, &chain).unwrap()).unwrap();
        let blocks = pem::parse(&text).unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[2].data, chain[1]);
        assert!(export(Format::Pkcs12, &chain[..1]).is_ok());
    }
}
