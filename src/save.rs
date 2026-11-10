//! Writing an edited keystore: the open keystore's writable form and
//! password, the "save as" name prompt, and replacing a file atomically.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zeroize::Zeroizing;

use crate::keystore::{self, KeystoreEntry};

/// An open JKS or JCEKS keystore that can be edited and saved. The password
/// is kept, to compute the integrity digest on saving, until the keystore is
/// closed; dropping the document wipes it.
pub struct Document {
    writable: keystore::Writable,
    password: Zeroizing<String>,
}

impl Document {
    pub fn new(writable: keystore::Writable, password: &str) -> Self {
        Self {
            writable,
            password: Zeroizing::new(password.to_owned()),
        }
    }

    /// Removes the entry listed at `index`.
    pub fn remove(&mut self, index: usize) {
        self.writable.remove(index);
    }

    /// Gives the entry listed at `index` the alias `alias`, listed at `to`.
    pub fn rename(&mut self, index: usize, alias: &str, to: usize) -> Result<(), String> {
        self.writable
            .rename(index, alias, to)
            .map_err(|error| format!("Not renamed: {error}."))
    }

    /// Adds a trusted certificate, listed at `to`; see
    /// `keystore::Writable::insert_trusted_certificate`.
    pub fn insert_trusted_certificate(
        &mut self,
        to: usize,
        alias: &str,
        certificate: &[u8],
        created: u64,
    ) -> Result<(), String> {
        self.writable
            .insert_trusted_certificate(to, alias, certificate, created)
            .map_err(|error| format!("Not imported: {error}."))
    }

    /// The keystore file, after checking that it reads back as `entries`.
    fn encode(&self, entries: &[KeystoreEntry]) -> Result<Vec<u8>, String> {
        let data = self.writable.encode(&self.password);
        let read_back = keystore::parse(data.clone())
            .ok()
            .and_then(|keystore| keystore.open(&self.password).ok());
        match read_back {
            Some((read, _)) if read == entries => Ok(data),
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
        let name = (1..100)
            .map(|n| match n {
                1 => format!("{stem}-copy{extension}"),
                n => format!("{stem}-copy-{n}{extension}"),
            })
            .find(|name| !directory.join(name).exists())
            .unwrap_or_else(|| format!("{stem}-copy{extension}"));
        Self {
            path: directory.join(name).to_string_lossy().into_owned(),
            directory,
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
        (entries, Document::new(writable, password))
    }

    #[test]
    fn saving_replaces_the_file_and_leaves_no_temporary_file() {
        let directory = TestDirectory::new();
        let path = directory.path().join("store.jks");
        fs::write(&path, mixed_keystore()).unwrap();
        let (mut entries, mut document) = open(&mixed_keystore(), "changeit");
        document.remove(0);
        entries.remove(0);
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
        document.remove(0);
        entries.remove(0);
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
