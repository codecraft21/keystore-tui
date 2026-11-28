//! Saving certificates, public keys, and certificate requests to new PEM,
//! DER, or PKCS#7 files.
//! Existing files are never replaced.
use crate::{certificate_file, path_input::PathInput};
use std::{
    borrow::Cow,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use crown::asn1::pem;
use ratatui::crossterm::event::{KeyCode, KeyEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The certificate selected in the hierarchy.
    Certificate,
    /// Every stored certificate of the entry, leaf first.
    Chain,
    /// A certificate request entry's request.
    Request,
    /// A private key, with its certificates when the file name asks for them.
    KeyPair,
    /// The public key (SubjectPublicKeyInfo) of the selected certificate.
    PublicKey,
    /// A certificate revocation list.
    Crl,
    /// A secret key, as its bytes or as hex digits.
    SecretKey,
}

impl Scope {
    pub fn label(self) -> &'static str {
        match self {
            Self::Certificate => "certificate",
            Self::Chain => "chain",
            Self::Request => "certificate request",
            Self::KeyPair => "key pair",
            Self::PublicKey => "public key",
            Self::Crl => "revocation list",
            Self::SecretKey => "secret key",
        }
    }

    /// The suggested file name extension.
    fn extension(self) -> &'static str {
        match self {
            Self::Certificate | Self::Chain | Self::PublicKey => "pem",
            Self::Request => "csr",
            Self::KeyPair => "p12",
            Self::Crl => "crl",
            Self::SecretKey => "bin",
        }
    }

    /// The suggested name when the alias gives none.
    fn default_stem(self) -> &'static str {
        match self {
            Self::Certificate | Self::Chain | Self::PublicKey => "certificate",
            Self::Request => "request",
            Self::KeyPair => "key",
            Self::Crl => "revocation-list",
            Self::SecretKey => "secret-key",
        }
    }

    /// The PEM block label for what this scope saves.
    pub fn pem_label(self) -> &'static str {
        match self {
            Self::Certificate | Self::Chain => "CERTIFICATE",
            Self::Request => "CERTIFICATE REQUEST",
            // A secret key has no PEM form; its file holds no label.
            Self::KeyPair | Self::SecretKey => "PRIVATE KEY",
            Self::PublicKey => "PUBLIC KEY",
            Self::Crl => crate::revocation_list::PEM_LABEL,
        }
    }

    /// Whether `.p7b` and `.p7c` file names write a PKCS#7 certificate bundle.
    pub fn supports_pkcs7(self) -> bool {
        matches!(self, Self::Certificate | Self::Chain)
    }
}

pub enum Outcome {
    Editing,
    Cancelled,
    Save(PathBuf),
}

/// The file name being typed for an export.
pub struct ExportPrompt {
    pub scope: Scope,
    pub path: PathInput,
    directory: PathBuf,
}

impl ExportPrompt {
    /// Suggests `<alias>.pem`, `<alias>-chain.pem`, `<alias>-public-key.pem`,
    /// or `<alias>.csr` in `directory`, numbered to avoid names that already exist. Enter resolves
    /// the name against `directory` once, so the suggestion includes the
    /// directory only when it is absolute.
    pub fn new(scope: Scope, directory: &Path, alias: &str) -> Self {
        let mut stem: String = alias
            .chars()
            .map(|ch| {
                if ch.is_alphanumeric() || "-_.".contains(ch) {
                    ch
                } else {
                    '_'
                }
            })
            .collect();
        if stem.trim_matches('.').is_empty() {
            stem = scope.default_stem().into();
        }
        match scope {
            Scope::Chain => stem.push_str("-chain"),
            Scope::PublicKey => stem.push_str("-public-key"),
            _ => {}
        }
        let extension = scope.extension();
        let name = (1..100)
            .map(|n| match n {
                1 => PathBuf::from(format!("{stem}.{extension}")),
                n => PathBuf::from(format!("{stem}-{n}.{extension}")),
            })
            .find(|name| !crate::save::path_exists(&directory.join(name)))
            .unwrap_or_else(|| PathBuf::from(format!("{stem}.{extension}")));
        let path = if directory.is_absolute() {
            directory.join(name)
        } else {
            name
        };
        Self {
            scope,
            path: PathInput::new(path.to_string_lossy().into_owned()),
            directory: directory.to_path_buf(),
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

/// Whether `path` names a DER file.
pub fn is_der(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("der"))
}

/// Whether `path` names a PKCS#7 certificate bundle (`.p7b` or `.p7c`).
pub fn is_pkcs7(path: &Path) -> bool {
    path.extension().is_some_and(|extension| {
        extension.eq_ignore_ascii_case("p7b") || extension.eq_ignore_ascii_case("p7c")
    })
}

/// Encodes `items` for `path` and `scope`: DER PKCS#7 `SignedData` for `.p7b`
/// or `.p7c` when `scope` holds certificates (refused for any other scope),
/// raw DER for a single item under `.der`, and concatenated PEM blocks
/// labelled `scope.pem_label()` otherwise.
pub fn encode<'a, T: AsRef<[u8]>>(
    items: &'a [T],
    path: &Path,
    scope: Scope,
) -> Result<Cow<'a, [u8]>, &'static str> {
    if items.is_empty() {
        return Err("There is nothing to save.");
    }
    if is_pkcs7(path) {
        if scope.supports_pkcs7() {
            Ok(Cow::Owned(certificate_file::encode_pkcs7(items)))
        } else {
            Err("A PKCS#7 file holds certificates; use a .pem or .der name.")
        }
    } else if is_der(path) {
        match items {
            [item] => Ok(Cow::Borrowed(item.as_ref())),
            _ => Err("A DER file holds one certificate; use a .pem or .p7b name for the chain."),
        }
    } else {
        Ok(Cow::Owned(
            items
                .iter()
                .map(|item| pem::encode(scope.pem_label(), item.as_ref()))
                .collect::<String>()
                .into_bytes(),
        ))
    }
}

/// Writes a new file, failing if `path` already exists.
pub fn save<T: AsRef<[u8]>>(path: &Path, items: &[T], scope: Scope) -> Result<(), String> {
    let data = encode(items, path, scope)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| match error.kind() {
            io::ErrorKind::AlreadyExists => {
                format!("'{}' already exists; choose another name.", path.display())
            }
            _ => format!("Cannot create '{}': {error}", path.display()),
        })?;
    let result = file.write_all(&data).and_then(|()| file.sync_all());
    drop(file);
    result.map_err(|error| {
        let _ = fs::remove_file(path);
        format!("Cannot write '{}': {error}", path.display())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestDirectory, metadata_certificate, relative_to_working_directory};
    use ratatui::crossterm::event::KeyModifiers;

    fn type_text(prompt: &mut ExportPrompt, text: &str) {
        for ch in text.chars() {
            prompt.handle_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
        }
    }

    #[test]
    fn suggests_a_safe_unused_name_next_to_the_opened_file() {
        let directory = TestDirectory::new();
        let prompt = ExportPrompt::new(Scope::Certificate, directory.path(), "my/key: 1");
        assert_eq!(
            Path::new(&prompt.path),
            directory.path().join("my_key__1.pem")
        );
        fs::write(directory.path().join("server-chain.pem"), b"existing").unwrap();
        let prompt = ExportPrompt::new(Scope::Chain, directory.path(), "server");
        assert_eq!(
            Path::new(&prompt.path),
            directory.path().join("server-chain-2.pem")
        );
        let prompt = ExportPrompt::new(Scope::KeyPair, directory.path(), "..");
        assert_eq!(Path::new(&prompt.path), directory.path().join("key.p12"));
        assert_eq!(
            (Scope::KeyPair.label(), Scope::KeyPair.pem_label()),
            ("key pair", "PRIVATE KEY")
        );
        let prompt = ExportPrompt::new(Scope::Certificate, directory.path(), "..");
        assert_eq!(
            Path::new(&prompt.path),
            directory.path().join("certificate.pem")
        );
        let prompt = ExportPrompt::new(Scope::Request, directory.path(), "server");
        assert_eq!(Path::new(&prompt.path), directory.path().join("server.csr"));
        let prompt = ExportPrompt::new(Scope::SecretKey, directory.path(), "..");
        assert_eq!(
            Path::new(&prompt.path),
            directory.path().join("secret-key.bin")
        );
        assert_eq!(Scope::SecretKey.label(), "secret key");
        let prompt = ExportPrompt::new(Scope::Crl, directory.path(), "..");
        assert_eq!(
            Path::new(&prompt.path),
            directory.path().join("revocation-list.crl")
        );
        assert_eq!(
            (Scope::Crl.label(), Scope::Crl.pem_label()),
            ("revocation list", "X509 CRL")
        );
        let prompt = ExportPrompt::new(Scope::PublicKey, directory.path(), "..");
        assert_eq!(
            Path::new(&prompt.path),
            directory.path().join("certificate-public-key.pem")
        );
        assert_eq!(
            (Scope::PublicKey.label(), Scope::PublicKey.pem_label()),
            ("public key", "PUBLIC KEY")
        );
    }

    #[test]
    fn editing_resolves_relative_names_and_quit_letters_are_text() {
        let directory = TestDirectory::new();
        let mut prompt = ExportPrompt::new(Scope::Certificate, directory.path(), "a");
        prompt.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert!(matches!(
            prompt.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            Outcome::Editing
        ));
        type_text(&mut prompt, "q.derx");
        prompt.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert_eq!(&*prompt.path, "q.der");
        let Outcome::Save(path) =
            prompt.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        else {
            panic!("expected a save");
        };
        assert_eq!(path, directory.path().join("q.der"));
        assert!(matches!(
            prompt.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            Outcome::Cancelled
        ));
    }

    #[test]
    fn a_relative_directory_is_joined_once() {
        let directory = TestDirectory::in_working_directory();
        let relative = relative_to_working_directory(directory.path());
        assert!(relative.is_relative());
        fs::write(relative.join("server.pem"), b"existing").unwrap();
        let mut prompt = ExportPrompt::new(Scope::Certificate, &relative, "server");
        assert_eq!(&*prompt.path, "server-2.pem");
        let Outcome::Save(path) =
            prompt.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        else {
            panic!("expected a save");
        };
        assert_eq!(path, relative.join("server-2.pem"));
    }

    #[test]
    fn saves_pem_pkcs7_and_single_der_without_overwriting() {
        let directory = TestDirectory::new();
        let leaf = metadata_certificate("leaf", "root", &[1], &[]);
        let root = metadata_certificate("root", "root", &[2], &[]);
        let chain = [leaf.clone(), root.clone()];

        let pem_path = directory.path().join("chain.PEM");
        save(&pem_path, &chain, Scope::Chain).unwrap();
        let blocks = pem::parse(&fs::read_to_string(&pem_path).unwrap()).unwrap();
        assert_eq!(blocks.len(), 2);
        assert!(blocks.iter().all(|block| block.label == "CERTIFICATE"));
        assert_eq!([blocks[0].data.clone(), blocks[1].data.clone()], chain);

        let der_path = directory.path().join("leaf.DER");
        save(&der_path, &chain[..1], Scope::Certificate).unwrap();
        assert_eq!(fs::read(&der_path).unwrap(), leaf);
        assert!(
            save(&der_path, &chain[1..], Scope::Certificate)
                .unwrap_err()
                .contains("already exists")
        );
        assert_eq!(fs::read(&der_path).unwrap(), leaf);

        // .p7b and .p7c (case-insensitive) write DER PKCS#7 SignedData for
        // single certificates and chains.
        for (name, scope, items) in [
            ("chain.p7b", Scope::Chain, &chain[..]),
            ("chain.P7C", Scope::Certificate, &chain[..]),
            ("leaf.P7B", Scope::Certificate, &chain[..1]),
        ] {
            let path = directory.path().join(name);
            save(&path, items, scope).unwrap();
            let bytes = fs::read(&path).unwrap();
            assert!(!certificate_file::is_pem(&bytes));
            let parsed = certificate_file::parse(&bytes).unwrap();
            assert_eq!(parsed.entries.len(), items.len());
            let leaf_entry = parsed.entries.iter().find(|e| e.alias == "leaf").unwrap();
            assert_eq!(leaf_entry.certificates(), items);
        }
        for name in ["empty.p7b", "empty.der", "empty.pem"] {
            let path = directory.path().join(name);
            assert!(
                save(&path, &[] as &[&[u8]], Scope::Certificate)
                    .unwrap_err()
                    .contains("nothing to save")
            );
            assert!(!path.exists());
        }

        let request = directory.path().join("request.csr");
        save(&request, &chain[..1], Scope::Request).unwrap();
        let blocks = pem::parse(&fs::read_to_string(&request).unwrap()).unwrap();
        assert_eq!(blocks[0].label, "CERTIFICATE REQUEST");

        // Only certificates can be saved under a .p7b or .p7c name.
        for (name, scope) in [
            ("request.p7b", Scope::Request),
            ("key.P7B", Scope::PublicKey),
            ("list.p7c", Scope::Crl),
        ] {
            let path = directory.path().join(name);
            assert!(
                save(&path, &chain[..1], scope)
                    .unwrap_err()
                    .contains("PKCS#7 file holds certificates")
            );
            assert!(!path.exists());
        }

        let rejected = directory.path().join("chain.der");
        assert!(
            save(&rejected, &chain, Scope::Certificate)
                .unwrap_err()
                .contains(".pem or .p7b")
        );
        assert!(!rejected.exists());
        assert!(
            save(
                &directory.path().join("missing/leaf.pem"),
                &chain,
                Scope::Certificate
            )
            .is_err()
        );
    }
}
