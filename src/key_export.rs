//! Exporting a private key, alone or with its certificates, to a new
//! PKCS12, PEM, or DER file.
use std::path::{Path, PathBuf};

use crown::{asn1::pem, rng::Rng};
use zeroize::Zeroizing;

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
        Format::PemKey => pem_block(label, &key, &[]),
        Format::PemPair | Format::Pkcs12 => {
            let certificates: String = chain
                .iter()
                .map(|certificate| pem::encode("CERTIFICATE", certificate))
                .collect();
            pem_block(label, &key, certificates.as_bytes())
        }
    })
}

/// `data` as a PEM block labelled `label`, followed by `rest`, written
/// into one buffer sized up front so no unwiped copy of `data` is left
/// behind by growing it.
fn pem_block(label: &str, data: &[u8], rest: &[u8]) -> Zeroizing<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let encoded = data.len().div_ceil(3) * 4;
    let lines = encoded.div_ceil(64);
    let armour = "-----BEGIN -----\n".len() + "-----END -----\n".len() + 2 * label.len();
    let mut out = Zeroizing::new(Vec::with_capacity(armour + encoded + lines + rest.len()));
    out.extend_from_slice(b"-----BEGIN ");
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(b"-----\n");
    for (index, group) in data.chunks(3).enumerate() {
        let bytes = [
            group[0],
            *group.get(1).unwrap_or(&0),
            *group.get(2).unwrap_or(&0),
        ];
        let bits = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);
        for position in 0..4 {
            out.push(if position <= group.len() {
                ALPHABET[(bits >> (18 - 6 * position) & 63) as usize]
            } else {
                b'='
            });
        }
        if index % 16 == 15 {
            out.push(b'\n');
        }
    }
    if !encoded.is_multiple_of(64) {
        out.push(b'\n');
    }
    out.extend_from_slice(b"-----END ");
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(b"-----\n");
    out.extend_from_slice(rest);
    debug_assert_eq!(out.len(), out.capacity());
    out
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
            let block = pem_block("PRIVATE KEY", &data, certificates.as_bytes());
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
            let export =
                |format| encode(format, "alias", &key, &chain, password, &mut TestRng(1)).unwrap();
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
