//! Writing an edited keystore: the open keystore's writable form and
//! password, the "save as" name prompt, and replacing a file atomically.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crown::rng::Rng;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zeroize::Zeroizing;

use crate::{
    certificate,
    key_protection::{self, Error as KeyError},
    keystore::{self, Content, KeystoreEntry, Kind},
    pkcs12,
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
struct OsRng {
    failed: bool,
}

impl OsRng {
    /// Fails if any request for random numbers was not met.
    fn check(mut self) -> Result<(), String> {
        // Also catches a source that fails before it is first used.
        self.fill_bytes(&mut [0]);
        (!self.failed)
            .then_some(())
            .ok_or_else(|| NO_RANDOMNESS.into())
    }
}

impl Rng for OsRng {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        self.failed |= getrandom::fill(out).is_err();
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
        match self {
            Self::Jks { password, .. } => *password = Zeroizing::new(new.to_owned()),
            Self::Pkcs12(writable) => {
                // Re-encrypting keys needs salts; check for them first, so
                // that a failure leaves the keystore as it was.
                OsRng::default().check()?;
                let mut rng = OsRng::default();
                writable.set_password(new, &mut rng)?;
                rng.check()?;
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

    /// Whether `password`, or the keystore's password when there is none,
    /// is the one protecting the private key listed at `index`.
    pub fn unlocks_key(&self, index: usize, password: Option<&str>) -> Result<bool, String> {
        match self.recover_key(index, password) {
            Ok(_) => Ok(true),
            Err(KeyError::Password) => Ok(false),
            Err(error) => Err(key_error(error)),
        }
    }

    /// Protects the private key listed at `index` with the password `new`.
    /// The key is recovered in memory with `current`, or with the keystore's
    /// password when there is none, and wiped once protected again.
    pub fn set_key_password(
        &mut self,
        index: usize,
        current: Option<&str>,
        new: &str,
    ) -> Result<(), String> {
        let key = self.recover_key(index, current).map_err(key_error)?;
        let Self::Jks { writable, .. } = self else {
            return Err(key_error(KeyError::Unsupported));
        };
        OsRng::default().check()?;
        let mut rng = OsRng::default();
        let protected =
            key_protection::protect(&key, new, writable.is_jceks(), &mut rng).map_err(key_error)?;
        rng.check()?;
        writable
            .set_protected_key(index, &protected)
            .map_err(|error| format!("The key password was not changed: {error}."))
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
        let data = self.encode(entries)?;
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
        file.write_all(&data)
            .and_then(|()| file.sync_all())
            .map_err(|error| {
                drop(fs::remove_file(path));
                format!("Cannot write '{}': {error}", path.display())
            })
    }
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
    let target = fs::canonicalize(path)?;
    let invalid = || io::Error::other("not a file path");
    let directory = target.parent().ok_or_else(invalid)?;
    let mut name = target.file_name().ok_or_else(invalid)?.to_os_string();
    name.push(format!(".{}.tmp", std::process::id()));
    let temporary = directory.join(name);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(data)?;
        file.set_permissions(fs::metadata(&target)?.permissions())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &target)
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
            // Never remove another process's file that had the same name.
            if error.kind() != io::ErrorKind::AlreadyExists {
                let _ = fs::remove_file(&temporary);
            }
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
    pub path: String,
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
        Self {
            path: directory.join(name).to_string_lossy().into_owned(),
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
            KeyCode::Backspace => {
                self.path.pop();
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.path.clear()
            }
            KeyCode::Char(ch) if crate::is_text_input(key.modifiers) => self.path.push(ch),
            _ => {}
        }
        Outcome::Editing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{KEYTOOL_JKS, TestDirectory, mixed_keystore};

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
}
